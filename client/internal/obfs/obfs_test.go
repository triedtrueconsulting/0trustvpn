package obfs

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"testing"
	"time"
)

// wgStub stands in for the node's WireGuard listener: it echoes every
// datagram back with a marker, from the loopback port the relay is allowed
// to reach.
func wgStub(t *testing.T) (netip.AddrPort, func()) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("wg stub: %v", err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			c.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return c.LocalAddr().(*net.UDPAddr).AddrPort(), func() { c.Close() }
}

func testKey(t *testing.T) string {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return k
}

// TestPackUnpackRoundTrip is the crypto layer on its own.
func TestPackUnpackRoundTrip(t *testing.T) {
	k := testKey(t)
	psk, _ := ParseKey(k)
	dst := netip.MustParseAddrPort("127.0.0.1:51820")

	for _, size := range []int{0, 1, 148, 1420, 9000} {
		payload := make([]byte, size)
		rand.Read(payload)
		pkt, err := Pack(psk, dst, payload)
		if err != nil {
			t.Fatalf("pack %d: %v", size, err)
		}
		if got := len(pkt) - len(payload); got != Overhead {
			t.Fatalf("size %d: overhead is %d, Overhead says %d", size, got, Overhead)
		}
		gotDst, gotPayload, err := Unpack(psk, pkt)
		if err != nil {
			t.Fatalf("unpack %d: %v", size, err)
		}
		if gotDst != dst {
			t.Fatalf("size %d: dst %v, want %v", size, gotDst, dst)
		}
		if !bytes.Equal(gotPayload, payload) {
			t.Fatalf("size %d: payload did not survive", size)
		}
	}
}

// TestNoFixedBytesOnTheWire is the whole point of the package: two seals of
// the SAME plaintext under the SAME key must share no structure, or a DPI
// box has something to match on.
func TestNoFixedBytesOnTheWire(t *testing.T) {
	psk, _ := ParseKey(testKey(t))
	dst := netip.MustParseAddrPort("127.0.0.1:51820")

	// A real WireGuard handshake initiation: type 1, three reserved zero
	// bytes, then 144 bytes of key material. Those first four bytes are what
	// a signature matches, so they are the ones that must not survive.
	wgInit := make([]byte, 148)
	wgInit[0] = 0x01
	rand.Read(wgInit[4:])

	a, err := Pack(psk, dst, wgInit)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Pack(psk, dst, wgInit)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatalf("same input sealed to different lengths")
	}
	for i := range a {
		if a[i] == b[i] {
			// One byte in 256 collides by chance; a RUN of them is
			// structure. Check no four consecutive bytes agree.
			if i >= 3 && a[i-1] == b[i-1] && a[i-2] == b[i-2] && a[i-3] == b[i-3] {
				t.Fatalf("four identical bytes at offset %d across two seals "+
					"of the same plaintext — that is a signature", i-3)
			}
		}
	}
	if bytes.Contains(a, wgInit[:16]) {
		t.Fatalf("the WireGuard handshake prefix appears verbatim in the sealed packet")
	}
}

// TestWrongKeyIsRejected — a packet must not open under a different key.
func TestWrongKeyIsRejected(t *testing.T) {
	good, _ := ParseKey(testKey(t))
	bad, _ := ParseKey(testKey(t))
	pkt, err := Pack(good, netip.MustParseAddrPort("127.0.0.1:51820"), []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Unpack(bad, pkt); err == nil {
		t.Fatal("a packet opened under the wrong key")
	}
	// And a flipped bit in the ciphertext must not open under the right one.
	pkt[len(pkt)-20] ^= 0x01
	if _, _, err := Unpack(good, pkt); err == nil {
		t.Fatal("a tampered packet authenticated")
	}
}

// TestShortPacketsDoNotPanic — a public UDP port receives scanner noise.
func TestShortPacketsDoNotPanic(t *testing.T) {
	psk, _ := ParseKey(testKey(t))
	for n := 0; n < SaltLen+tagLen+4; n++ {
		junk := make([]byte, n)
		rand.Read(junk)
		if _, _, err := Unpack(psk, junk); err == nil {
			t.Fatalf("%d bytes of junk was accepted", n)
		}
	}
}

// TestHostnameDestinationsRefused — the relay must never resolve for anyone.
func TestHostnameDestinationsRefused(t *testing.T) {
	psk, _ := ParseKey(testKey(t))
	salt := make([]byte, SaltLen)
	rand.Read(salt)
	aead, err := sessionAEAD(psk, salt)
	if err != nil {
		t.Fatal(err)
	}
	// ATYP=3, one-byte length, "x", port.
	plain := []byte{atypDomain, 1, 'x', 0x01, 0xbb}
	pkt := aead.Seal(append([]byte{}, salt...), make([]byte, aead.NonceSize()), plain, nil)
	if _, _, err := Unpack(psk, pkt); err == nil {
		t.Fatal("a hostname destination was accepted")
	}
}

// TestEndToEnd runs the real thing: client relay -> server -> WireGuard stub
// and back, over actual sockets.
func TestEndToEnd(t *testing.T) {
	wgAddr, stop := wgStub(t)
	defer stop()

	key := testKey(t)
	srv, err := NewServer(key, []netip.AddrPort{wgAddr}, time.Minute)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	defer srv.Close()
	// Bind the server on an ephemeral port and learn which one.
	sc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	srvAddr := sc.LocalAddr().String()
	sc.Close()
	go srv.ListenAndServe(srvAddr)
	time.Sleep(100 * time.Millisecond)

	rl, err := NewRelay(srvAddr, key, wgAddr)
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	if err := rl.Start(); err != nil {
		t.Fatalf("relay start: %v", err)
	}
	defer rl.Close()

	// Talk to the relay exactly as WireGuard would.
	client, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(rl.Local))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	msg := []byte("wireguard-datagram")
	if _, err := client.Write(msg); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65535)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("no reply came back through the relay: %v", err)
	}
	if want := append([]byte("echo:"), msg...); !bytes.Equal(buf[:n], want) {
		t.Fatalf("got %q, want %q", buf[:n], want)
	}
}

// TestServerRefusesDestinationsOffTheAllowlist is the open-relay guard. A
// customer holds the same key as everyone else on the node, so this is the
// only thing between us and running an open proxy.
func TestServerRefusesDestinationsOffTheAllowlist(t *testing.T) {
	wgAddr, stopWG := wgStub(t)
	defer stopWG()
	// A second listener, NOT on the allowlist, standing in for "any host on
	// the internet the customer would like us to relay to".
	elsewhere, stopElse := wgStub(t)
	defer stopElse()

	key := testKey(t)
	srv, err := NewServer(key, []netip.AddrPort{wgAddr}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	sc, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	srvAddr := sc.LocalAddr().String()
	sc.Close()
	go srv.ListenAndServe(srvAddr)
	time.Sleep(100 * time.Millisecond)

	psk, _ := ParseKey(key)
	conn, err := net.Dial("udp", srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// The allowed destination works — proving the test can tell the two apart.
	ok, _ := Pack(psk, wgAddr, []byte("allowed"))
	conn.Write(ok)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 65535)); err != nil {
		t.Fatalf("the allowed destination did not answer, so this test proves nothing: %v", err)
	}

	// The other one must be dropped in silence.
	bad, _ := Pack(psk, elsewhere, []byte("relay-this-for-me"))
	conn.Write(bad)
	conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	if n, err := conn.Read(make([]byte, 65535)); err == nil {
		t.Fatalf("the relay forwarded to a destination off the allowlist "+
			"(%d bytes came back) — that is an open proxy", n)
	}
}

// TestServerRefusesNonLoopbackAllowlist — a misconfigured node must fail to
// start rather than come up as a relay to the internet.
func TestServerRefusesNonLoopbackAllowlist(t *testing.T) {
	if _, err := NewServer(testKey(t),
		[]netip.AddrPort{netip.MustParseAddrPort("8.8.8.8:53")}, time.Minute); err == nil {
		t.Fatal("a non-loopback destination was accepted into the allowlist")
	}
	if _, err := NewServer(testKey(t), nil, time.Minute); err == nil {
		t.Fatal("an empty allowlist was accepted")
	}
}

// TestKeySizeIsEnforced — a short key must be refused, not padded.
func TestKeySizeIsEnforced(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := ParseKey(short); err == nil {
		t.Fatal("a 16-byte key was accepted for aes-256-gcm")
	}
	if _, err := ParseKey("not base64 at all !!"); err == nil {
		t.Fatal("a non-base64 key was accepted")
	}
}
