// Package netcheck verifies, once a tunnel is up, the two things a WireGuard
// handshake does not prove.
//
// A handshake is 148 bytes. It fits through almost any path, including paths
// that cannot carry a full-size packet — so a tunnel whose MTU is too high
// for the network it is on completes the handshake, reports itself connected,
// and then silently drops every large packet. That reaches the customer as
// "some sites load and some hang forever", which is unattributable: nothing
// logs it, no health check sees it, and the obvious suspects (DNS, the exit
// node, the site itself) are all innocent.
//
// wg.go's own comment already names this exact failure. The control plane
// already publishes the right MTU per transport. Nothing verified it, which
// is the same shape as the installer printing "The VPN works" without
// looking (bug class #16) and as wg-quick's exit code meaning nothing.
//
// The probe uses the in-tunnel resolver, because every client is handed
// DNS = the mesh gateway and something has to answer there anyway:
//
//  1. a SMALL query. If this fails the resolver is the problem, not the MTU,
//     and saying "MTU" would send the operator down the wrong path. It is
//     the positive control — without it a large-query failure proves
//     nothing, the same reason the relay allowlist test checks the allowed
//     leg before the denied one.
//  2. a LARGE query, padded so the packet WireGuard puts on the wire is as
//     big as the tunnel will ever send. Inside the tunnel this is an
//     ordinary datagram; outside it is MTU + 60 bytes, and a path that
//     cannot carry that drops it. WireGuard sets DF, so there is no
//     fragmentation to rescue it.
//
// Pure stdlib, no raw sockets, no privileges beyond what connect already has.
package netcheck

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// Overheads between an inner datagram and the packet on the wire:
// outer IPv4 (20) + outer UDP (8) + WireGuard data header (16) + Poly1305
// tag (16). Conservative — a v6 outer header is larger, which only makes the
// probe stricter.
const wireOverhead = 60

// Verdict is what the probe established.
type Verdict int

const (
	// OK: the resolver answered both a small and a full-size query.
	OK Verdict = iota
	// NoResolver: nothing answered even a small query. The tunnel may be
	// carrying traffic; the resolver it points at is not responding.
	NoResolver
	// MTUTooHigh: small queries answer, full-size ones do not. The tunnel
	// works for small packets and silently drops large ones.
	MTUTooHigh
	// Unknown: the probe itself could not run.
	Unknown
)

// Result carries the verdict and the numbers behind it.
type Result struct {
	Verdict  Verdict
	MTU      int    // the MTU that was tested
	WireSize int    // the on-the-wire size that large query produced
	Err      error  // why the probe could not run, when Verdict is Unknown
	Detail   string // one line naming what was and was not established
}

// dnsQuery builds an A query for name with an EDNS0 OPT record padded so the
// whole message is exactly size bytes. Hand-rolled because the DNS message
// builder lives in golang.org/x/net, and this package takes no dependency the
// rest of the client does not already have.
func dnsQuery(name string, size int) ([]byte, uint16) {
	id := uint16(rand.Intn(65535) + 1)
	var b []byte
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:], id)
	binary.BigEndian.PutUint16(hdr[2:], 0x0100) // standard query, recursion desired
	binary.BigEndian.PutUint16(hdr[4:], 1)      // one question
	binary.BigEndian.PutUint16(hdr[10:], 1)     // one additional (the OPT)
	b = append(b, hdr...)

	for _, label := range splitName(name) {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)                      // root
	b = append(b, 0x00, 0x01, 0x00, 0x01) // QTYPE A, QCLASS IN

	// EDNS0 OPT pseudo-record. Its RDATA holds one PADDING option (code 12),
	// which exists for exactly this: making a DNS message a chosen size.
	opt := []byte{
		0,          // root name
		0x00, 0x29, // TYPE OPT
		0x10, 0x00, // UDP payload size 4096
		0x00, 0x00, 0x00, 0x00, // extended RCODE, version, flags
		0x00, 0x00, // RDLENGTH, filled below
	}
	// 4 bytes of option header (code + length) sit inside RDATA.
	pad := size - len(b) - len(opt) - 4
	if pad < 0 {
		pad = 0
	}
	binary.BigEndian.PutUint16(opt[9:], uint16(4+pad))
	b = append(b, opt...)
	b = append(b, 0x00, 0x0c) // OPTION-CODE 12 (Padding)
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(pad))
	b = append(b, lenBytes...)
	b = append(b, make([]byte, pad)...)
	return b, id
}

func splitName(name string) []string {
	var out []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if i > start {
				out = append(out, name[start:i])
			}
			start = i + 1
		}
	}
	if start < len(name) {
		out = append(out, name[start:])
	}
	return out
}

// ask sends one query to addr ("host:port") and waits for a reply carrying
// the same transaction id. Any reply counts, including an error reply: the
// point is that a packet of this size made the round trip, not that the name
// resolved.
//
// It takes a full address rather than a host so a test can point it at a
// responder on an arbitrary port. It used to join port 53 itself, which made
// the transaction-id check untestable: the one test for it passed because
// the probe dialed :53, found nothing, and timed out — the right answer for
// the wrong reason, and the check could be deleted without the test noticing.
func ask(addr string, q []byte, id uint16, timeout time.Duration) (bool, error) {
	c, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false, err
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false, err
	}
	if _, err := c.Write(q); err != nil {
		return false, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return false, nil // timed out: no reply of this size came back
		}
		if n >= 2 && binary.BigEndian.Uint16(buf[0:]) == id {
			return true, nil
		}
		// A stray datagram from something else; keep waiting until the
		// deadline rather than treating it as our answer.
	}
}

// Probe runs the control query and then the full-size one.
//
// name is resolved through the tunnel's own resolver; it only has to be a
// name the resolver will answer SOMETHING about, so a reply of any kind
// proves the packet arrived.
func Probe(gateway string, mtu int, timeout time.Duration) Result {
	res := Result{MTU: mtu}
	if gateway == "" || mtu <= 0 {
		res.Verdict, res.Detail = Unknown, "no gateway or MTU to test"
		return res
	}

	small, sid := dnsQuery("a.root-servers.net", 0)
	dst := net.JoinHostPort(gateway, "53")
	okSmall, err := ask(dst, small, sid, timeout)
	if err != nil {
		res.Verdict, res.Err = Unknown, err
		res.Detail = "could not reach the resolver socket at all"
		return res
	}
	if !okSmall {
		res.Verdict = NoResolver
		res.Detail = fmt.Sprintf("no answer from %s:53 to a small query — the "+
			"resolver is not responding, so this says nothing about the MTU", gateway)
		return res
	}

	// An inner datagram of exactly MTU bytes: IP (20) + UDP (8) + payload.
	payload := mtu - 28
	if payload < 64 {
		res.Verdict, res.Detail = Unknown, "MTU too small to build a probe"
		return res
	}
	large, lid := dnsQuery("a.root-servers.net", payload)
	res.WireSize = mtu + wireOverhead
	okLarge, err := ask(dst, large, lid, timeout)
	if err != nil {
		res.Verdict, res.Err = Unknown, err
		return res
	}
	if !okLarge {
		res.Verdict = MTUTooHigh
		res.Detail = fmt.Sprintf("small queries answer but a full-size one does "+
			"not: a %d-byte packet (%d on the wire) is being dropped by this "+
			"network", mtu, res.WireSize)
		return res
	}
	res.Verdict = OK
	res.Detail = fmt.Sprintf("resolver answers, and a full-size %d-byte packet "+
		"(%d on the wire) makes the round trip", mtu, res.WireSize)
	return res
}
