package netcheck

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// The probe talks to port 53, so the fake has to be there. Rather than
// needing a privileged port, these tests drive ask() through a resolver on
// an arbitrary port by addressing it directly.
func askAt(t *testing.T, addr string, size int, timeout time.Duration) bool {
	t.Helper()
	q, id := dnsQuery("a.root-servers.net", size)
	ok, err := ask(addr, q, id, timeout)
	if err != nil {
		t.Fatalf("ask %s: %v", addr, err)
	}
	return ok
}

func listener(t *testing.T, maxSize int) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}
			if maxSize == 0 || n > maxSize {
				continue
			}
			if n >= 12 {
				reply := make([]byte, 12)
				copy(reply, buf[:12])
				binary.BigEndian.PutUint16(reply[2:], 0x8183)
				_, _ = pc.WriteTo(reply, addr)
			}
		}
	}()
	return pc.LocalAddr().String(), func() { close(done); pc.Close() }
}

// A query padded to N bytes must actually BE N bytes, or the probe measures
// a size it is not sending and a low-MTU path goes undetected.
func TestQueryIsExactlyTheRequestedSize(t *testing.T) {
	for _, size := range []int{128, 512, 1392, 1472} {
		q, _ := dnsQuery("a.root-servers.net", size)
		if len(q) != size {
			t.Errorf("asked for %d bytes, built %d", size, len(q))
		}
	}
}

// Size 0 means "no padding": the control query must stay small enough to
// cross any path, or the control is as fragile as the thing it controls for.
func TestControlQueryIsSmall(t *testing.T) {
	q, _ := dnsQuery("a.root-servers.net", 0)
	if len(q) > 128 {
		t.Errorf("control query is %d bytes; it has to fit through anything", len(q))
	}
}

// The transaction id has to be checked, or a stray datagram on the socket
// reads as a successful round trip and a broken path reports OK.
func TestStrayDatagramIsNotAnAnswer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		// Reply with a DIFFERENT transaction id, as an unrelated sender would.
		junk := make([]byte, 12)
		binary.BigEndian.PutUint16(junk[0:], 0xFFFF)
		_, _ = pc.WriteTo(junk, addr)
	}()
	q, id := dnsQuery("a.root-servers.net", 0)
	if id == 0xFFFF {
		t.Skip("id collided with the junk id")
	}
	ok, err := ask(pc.LocalAddr().String(), q, id, 600*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("a datagram with someone else's transaction id was accepted as an answer")
	}
}

// The three verdicts, against a responder that behaves like each network.
func TestVerdicts(t *testing.T) {
	const mtu = 1420
	largeSize := mtu - 28

	t.Run("a path that carries everything", func(t *testing.T) {
		addr, stop := listener(t, 65535)
		defer stop()
		if !askAt(t, addr, 0, time.Second) {
			t.Fatal("control query went unanswered on a healthy path")
		}
		if !askAt(t, addr, largeSize, time.Second) {
			t.Error("full-size query went unanswered on a path that carries everything")
		}
	})

	t.Run("a path that drops full-size packets", func(t *testing.T) {
		// Answers small, drops anything near the tunnel's MTU: a 1400-byte
		// path carrying a 1420-byte tunnel.
		addr, stop := listener(t, 600)
		defer stop()
		if !askAt(t, addr, 0, time.Second) {
			t.Fatal("control query must still answer, or the next assertion proves nothing")
		}
		if askAt(t, addr, largeSize, time.Second) {
			t.Error("a full-size query was answered by a responder that drops them")
		}
	})

	t.Run("a resolver that answers nothing", func(t *testing.T) {
		addr, stop := listener(t, 0)
		defer stop()
		if askAt(t, addr, 0, 600*time.Millisecond) {
			t.Error("got an answer from a responder that answers nothing")
		}
	})
}

// Probe's own three-way discrimination, including that a dead resolver is
// NOT reported as an MTU problem — which would send the operator to the
// wrong cause, and the resolver being dead is a bug this product has had.
func TestProbeDoesNotBlameMTUForADeadResolver(t *testing.T) {
	res := Probe("127.0.0.1", 1420, 300*time.Millisecond)
	if res.Verdict == MTUTooHigh {
		t.Error("nothing is listening, so this cannot be an MTU verdict")
	}
	if res.Verdict != NoResolver && res.Verdict != Unknown {
		t.Errorf("unexpected verdict %v (%s)", res.Verdict, res.Detail)
	}
}

func TestProbeRefusesNonsenseInput(t *testing.T) {
	for _, tc := range []struct {
		gw  string
		mtu int
	}{
		{"", 1420}, {"10.64.0.1", 0}, {"10.64.0.1", -1}, {"10.64.0.1", 40},
	} {
		res := Probe(tc.gw, tc.mtu, 100*time.Millisecond)
		if res.Verdict != Unknown {
			t.Errorf("gateway=%q mtu=%d: expected Unknown, got %v",
				tc.gw, tc.mtu, res.Verdict)
		}
	}
}
