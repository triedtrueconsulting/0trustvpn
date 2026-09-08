// Package obfs implements the obfuscated transport 0trust offers as an
// opt-in alternative to speaking WireGuard directly to a node.
//
// # What this is for
//
// WireGuard's handshake has a fixed, published structure: a first message of
// exactly 148 bytes whose first four bytes are 0x01 0x00 0x00 0x00, followed
// by a 92-byte response. Any deep packet inspection box worth the name
// identifies it on the first packet of a connection, on any port. Moving the
// listener to udp/443 changes what a NETFLOW record looks like and nothing
// about what a DPI box sees, so it is camouflage against one observer and
// transparent to the other.
//
// This package removes that fingerprint. Each WireGuard datagram is sealed
// inside a Shadowsocks AEAD packet, which on the wire is a random 32-byte
// salt followed by ciphertext and a tag — no fixed bytes anywhere, no
// handshake structure, nothing to write a signature against.
//
// # What it is NOT
//
//   - It is not authentication. The pre-shared key is the same for every
//     customer on a node, so it is not a secret from a censor willing to buy
//     an account. WireGuard remains the only thing standing between a
//     customer and everyone else, exactly as when this layer is off.
//   - It is not protection against traffic analysis. Packet sizes, timing and
//     volume are unchanged, and a flow to a VPN provider's node still looks
//     like a flow to that node.
//   - It does not survive a block on UDP itself. This is UDP in, UDP out; a
//     network that drops all outbound UDP drops this too. Carrying the same
//     frames over TCP is a separate mode and is not implemented — see
//     docs/DEPLOY.md rather than assuming it is here.
//
// # Wire format
//
// The Shadowsocks AEAD UDP packet, aes-256-gcm:
//
//	[32-byte random salt][AEAD_Seal(subkey, zero nonce, payload)]
//	payload = [ATYP][DST.ADDR][DST.PORT][data]
//
// with subkey = HKDF-SHA1(psk, salt, "ss-subkey"). The format is the
// published one because a widely deployed shape is a better place to hide
// than a bespoke one, and because it has been looked at by people who are
// not us.
//
// One deliberate divergence: the pre-shared key is used as the master key
// directly, 32 raw bytes carried as base64, rather than being stretched from
// a passphrase by Shadowsocks' EVP_BytesToKey. That construction is an
// unsalted MD5 chain, and there is no reason to inherit it when both ends of
// this transport are ours and the key is machine-generated. It changes
// nothing a DPI box can see. It does mean we do not claim interoperability
// with a stock shadowsocks-libev server, and nothing here should.
package obfs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

const (
	// KeyLen is the aes-256-gcm master key size, and therefore the size of a
	// 0trust obfuscation pre-shared key.
	KeyLen = 32
	// SaltLen is the per-packet salt. Equal to the key size, per the spec.
	SaltLen = 32
	// tagLen is the AES-GCM authentication tag.
	tagLen = 16
	// addrLenV4 is ATYP + 4 address bytes + 2 port bytes.
	addrLenV4 = 7
	// addrLenV6 is ATYP + 16 address bytes + 2 port bytes.
	addrLenV6 = 19

	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
)

// Overhead is how many bytes this transport adds to every datagram: the
// salt, the destination address header and the AEAD tag.
//
// It exists as a named constant because the number has to reach the MTU the
// client puts on its WireGuard interface. Get it wrong and the failure is
// the nastiest kind: the handshake is small enough to fit and succeeds, so
// the tunnel comes up and reports healthy, and then full-size packets are
// silently dropped — which the user experiences as "the VPN connects but
// some websites hang", not as an error anyone can act on.
const Overhead = SaltLen + addrLenV4 + tagLen // 55 for an IPv4 destination

// ErrShortPacket is returned for a datagram too small to be one of ours. It
// is expected traffic on a public UDP port, not an incident: anything that
// scans the internet will send some.
var ErrShortPacket = errors.New("obfs: packet too short")

// ParseKey decodes a base64 pre-shared key and checks it is the right size.
func ParseKey(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("obfs: key is not base64: %w", err)
	}
	if len(raw) != KeyLen {
		return nil, fmt.Errorf("obfs: key is %d bytes, want %d", len(raw), KeyLen)
	}
	return raw, nil
}

// NewKey mints a fresh pre-shared key, base64-encoded.
func NewKey() (string, error) {
	raw := make([]byte, KeyLen)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("obfs: keygen: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// hkdfSHA1 is RFC 5869 extract-and-expand over SHA-1, which is what the
// Shadowsocks AEAD spec calls for. Hand-rolled against the RFC rather than
// pulled from x/crypto for the same reason meshd's SOCKS5 client is: a
// dependency added here is a dependency on every node we run and every
// customer machine the client is installed on, and this is thirteen lines of
// a fully specified construction.
//
// SHA-1's collision weakness does not reach HMAC-SHA1 used as a KDF, and the
// choice is not ours in any case — it is the packet format.
func hkdfSHA1(secret, salt, info []byte, n int) []byte {
	ext := hmac.New(sha1.New, salt)
	ext.Write(secret)
	prk := ext.Sum(nil)

	var out, prev []byte
	for i := byte(1); len(out) < n; i++ {
		h := hmac.New(sha1.New, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{i})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

// sessionAEAD derives the per-packet subkey and returns the cipher for it.
func sessionAEAD(psk, salt []byte) (cipher.AEAD, error) {
	sub := hkdfSHA1(psk, salt, []byte("ss-subkey"), KeyLen)
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// appendAddr writes a SOCKS5-style address header.
func appendAddr(b []byte, ap netip.AddrPort) []byte {
	addr := ap.Addr()
	if addr.Is4() || addr.Is4In6() {
		v4 := addr.As4()
		b = append(b, atypIPv4)
		b = append(b, v4[:]...)
	} else {
		v6 := addr.As16()
		b = append(b, atypIPv6)
		b = append(b, v6[:]...)
	}
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

// parseAddr reads a SOCKS5-style address header, returning it and the rest.
//
// DOMAINNAME is refused outright. The only destination this transport ever
// carries is a node's own loopback WireGuard port, so a hostname has no
// legitimate use here — and accepting one would turn the relay into
// something that performs lookups on behalf of whoever sends it a packet.
func parseAddr(b []byte) (netip.AddrPort, []byte, error) {
	if len(b) < 1 {
		return netip.AddrPort{}, nil, ErrShortPacket
	}
	switch b[0] {
	case atypIPv4:
		if len(b) < addrLenV4 {
			return netip.AddrPort{}, nil, ErrShortPacket
		}
		ip := netip.AddrFrom4([4]byte(b[1:5]))
		port := binary.BigEndian.Uint16(b[5:7])
		return netip.AddrPortFrom(ip, port), b[addrLenV4:], nil
	case atypIPv6:
		if len(b) < addrLenV6 {
			return netip.AddrPort{}, nil, ErrShortPacket
		}
		ip := netip.AddrFrom16([16]byte(b[1:17]))
		port := binary.BigEndian.Uint16(b[17:19])
		return netip.AddrPortFrom(ip, port), b[addrLenV6:], nil
	case atypDomain:
		return netip.AddrPort{}, nil, errors.New("obfs: hostname destinations are not carried")
	}
	return netip.AddrPort{}, nil, fmt.Errorf("obfs: unknown address type %d", b[0])
}

// Pack seals one datagram addressed to dst.
//
// The nonce is twelve zero bytes, which is correct here and would be a
// catastrophe anywhere else: the subkey is derived from a fresh random salt
// on every single packet, so no (key, nonce) pair is ever reused. This is
// the spec's design and the reason the salt is not optional.
func Pack(psk []byte, dst netip.AddrPort, data []byte) ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("obfs: salt: %w", err)
	}
	aead, err := sessionAEAD(psk, salt)
	if err != nil {
		return nil, err
	}
	plain := appendAddr(make([]byte, 0, addrLenV6+len(data)), dst)
	plain = append(plain, data...)

	out := make([]byte, 0, SaltLen+len(plain)+tagLen)
	out = append(out, salt...)
	return aead.Seal(out, make([]byte, aead.NonceSize()), plain, nil), nil
}

// Unpack opens one datagram, returning the destination it names and the
// payload. A packet that fails to authenticate is an error and nothing more:
// callers must drop it without replying, so that an unauthenticated prober
// learns nothing from the difference between a wrong key and a closed port.
func Unpack(psk, pkt []byte) (netip.AddrPort, []byte, error) {
	if len(pkt) < SaltLen+tagLen {
		return netip.AddrPort{}, nil, ErrShortPacket
	}
	salt, body := pkt[:SaltLen], pkt[SaltLen:]
	aead, err := sessionAEAD(psk, salt)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	plain, err := aead.Open(body[:0], make([]byte, aead.NonceSize()), body, nil)
	if err != nil {
		return netip.AddrPort{}, nil, errors.New("obfs: packet did not authenticate")
	}
	return parseAddr(plain)
}
