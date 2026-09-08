package obfs

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

// bufSize is the read buffer for a single datagram. A WireGuard packet on a
// 1500-byte path never approaches this; the slack costs one page and means a
// jumbo-frame path does not silently truncate.
const bufSize = 65535

// Relay is the client half of the obfuscated transport: a UDP socket on
// loopback that WireGuard talks to as though it were the node.
//
// WireGuard has no plugin interface and no notion of a transport, so this is
// the only way to wrap it without patching it: the tunnel's Endpoint is
// pointed at 127.0.0.1, and this process carries the datagrams the rest of
// the way. The cost is one extra kernel/userspace round trip per packet on
// the client, which is the honest half of the speed the user gives up when
// they turn obfuscation on. The other half is the same trip on the node.
type Relay struct {
	// Local is the loopback address WireGuard must use as its Endpoint. Only
	// valid after Start returns.
	Local netip.AddrPort

	// LocalPort pins the loopback port instead of taking an ephemeral one.
	// Set it before Start. The connect path needs this because the peer
	// Endpoint has to be written into the WireGuard config BEFORE the relay
	// process exists — there is no moment at which connect could ask a
	// not-yet-started process which port it ended up with.
	LocalPort int

	psk    []byte
	server *net.UDPAddr
	target netip.AddrPort

	down *net.UDPConn // faces WireGuard, on loopback
	up   *net.UDPConn // faces the node

	mu   sync.Mutex
	peer *net.UDPAddr // where WireGuard is talking to us from

	closeOnce sync.Once
	done      chan struct{}
}

// NewRelay prepares a relay. serverAddr is the node's obfuscation listener,
// target is the destination the node is to forward to — published by the
// control plane rather than guessed here, so that a node running its tunnel
// on a non-default port does not need a second place to be told about it.
func NewRelay(serverAddr, pskB64 string, target netip.AddrPort) (*Relay, error) {
	psk, err := ParseKey(pskB64)
	if err != nil {
		return nil, err
	}
	if !target.IsValid() {
		return nil, fmt.Errorf("obfs: no forwarding target")
	}
	srv, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("obfs: server address %q: %w", serverAddr, err)
	}
	return &Relay{psk: psk, server: srv, target: target, done: make(chan struct{})}, nil
}

// Start binds both sockets and begins carrying traffic. It returns as soon
// as the loopback address is known; the pumps run until Close.
func (r *Relay) Start() error {
	down, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.LocalPort})
	if err != nil {
		return fmt.Errorf("obfs: bind loopback: %w", err)
	}
	up, err := net.ListenUDP("udp", nil)
	if err != nil {
		down.Close()
		return fmt.Errorf("obfs: bind upstream: %w", err)
	}
	r.down, r.up = down, up
	r.Local = down.LocalAddr().(*net.UDPAddr).AddrPort()

	go r.pumpOut()
	go r.pumpIn()
	return nil
}

// pumpOut carries WireGuard's datagrams to the node.
func (r *Relay) pumpOut() {
	buf := make([]byte, bufSize)
	for {
		n, from, err := r.down.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-r.done:
			default:
				log.Printf("obfs: loopback read: %v", err)
			}
			return
		}
		r.mu.Lock()
		r.peer = from
		r.mu.Unlock()

		pkt, err := Pack(r.psk, r.target, buf[:n])
		if err != nil {
			log.Printf("obfs: seal: %v", err)
			continue
		}
		if _, err := r.up.WriteToUDP(pkt, r.server); err != nil {
			log.Printf("obfs: upstream write: %v", err)
		}
	}
}

// pumpIn carries the node's replies back to WireGuard.
func (r *Relay) pumpIn() {
	buf := make([]byte, bufSize)
	for {
		n, _, err := r.up.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-r.done:
			default:
				log.Printf("obfs: upstream read: %v", err)
			}
			return
		}
		_, payload, err := Unpack(r.psk, buf[:n])
		if err != nil {
			// Dropped in silence and counted nowhere. A public UDP port
			// receives scanner noise continuously; logging every unopenable
			// packet would let anyone fill the customer's disk.
			continue
		}
		r.mu.Lock()
		peer := r.peer
		r.mu.Unlock()
		if peer == nil {
			continue
		}
		if _, err := r.down.WriteToUDP(payload, peer); err != nil {
			log.Printf("obfs: loopback write: %v", err)
		}
	}
}

// Close tears the relay down. Safe to call more than once.
func (r *Relay) Close() error {
	r.closeOnce.Do(func() {
		close(r.done)
		if r.down != nil {
			r.down.Close()
		}
		if r.up != nil {
			r.up.Close()
		}
	})
	return nil
}

// --- node side ---

// Server is the node half: it opens the datagrams a client sealed and hands
// them to the local WireGuard listener.
//
// The allowlist is the whole security argument, and it is not optional. A
// stock Shadowsocks server forwards to whatever destination the packet names,
// which is exactly what makes it a useful proxy — and exactly what we must
// not run. Every customer on a node holds the same pre-shared key, so an
// unrestricted relay here would be an open proxy that any customer could
// point at any host on the internet, sourced from our node's address, and
// the first thing it would earn is an abuse report naming us. Only the
// node's own loopback WireGuard ports are reachable through it.
type Server struct {
	psk     []byte
	allowed map[netip.AddrPort]bool
	idle    time.Duration

	conn *net.UDPConn

	mu    sync.Mutex
	flows map[string]*flow
}

type flow struct {
	sock *net.UDPConn
	seen time.Time
}

// NewServer builds a relay server. allowed is the exact set of destinations
// it will forward to; anything else is dropped.
func NewServer(pskB64 string, allowed []netip.AddrPort, idle time.Duration) (*Server, error) {
	psk, err := ParseKey(pskB64)
	if err != nil {
		return nil, err
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("obfs: refusing to run with an empty destination allowlist")
	}
	set := make(map[netip.AddrPort]bool, len(allowed))
	for _, a := range allowed {
		if !a.Addr().IsLoopback() {
			return nil, fmt.Errorf("obfs: destination %s is not loopback", a)
		}
		set[a] = true
	}
	if idle <= 0 {
		idle = 3 * time.Minute
	}
	return &Server{psk: psk, allowed: set, idle: idle, flows: map[string]*flow{}}, nil
}

// ListenAndServe binds addr and serves until the socket is closed.
func (s *Server) ListenAndServe(addr string) error {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("obfs: listen address %q: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return fmt.Errorf("obfs: listen: %w", err)
	}
	s.conn = conn
	go s.reap()

	buf := make([]byte, bufSize)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		dst, payload, err := Unpack(s.psk, buf[:n])
		if err != nil {
			// No reply, no log line. A packet that does not authenticate is
			// indistinguishable from noise, and answering it — even with an
			// error — would tell a prober that something speaks here.
			continue
		}
		if !s.allowed[dst] {
			continue
		}
		s.forward(from, dst, payload)
	}
}

// forward sends one payload on, creating the flow's socket if needed.
func (s *Server) forward(from *net.UDPAddr, dst netip.AddrPort, payload []byte) {
	key := from.String()

	s.mu.Lock()
	f := s.flows[key]
	if f == nil {
		sock, err := net.ListenUDP("udp", nil)
		if err != nil {
			s.mu.Unlock()
			log.Printf("obfs: flow socket: %v", err)
			return
		}
		f = &flow{sock: sock}
		s.flows[key] = f
		go s.pumpBack(key, f, from)
	}
	f.seen = time.Now()
	s.mu.Unlock()

	if _, err := f.sock.WriteToUDP(payload, net.UDPAddrFromAddrPort(dst)); err != nil {
		log.Printf("obfs: forward: %v", err)
	}
}

// pumpBack carries WireGuard's replies out to the client that opened this
// flow, resealed.
func (s *Server) pumpBack(key string, f *flow, to *net.UDPAddr) {
	buf := make([]byte, bufSize)
	for {
		n, src, err := f.sock.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt, err := Pack(s.psk, src.AddrPort(), buf[:n])
		if err != nil {
			continue
		}
		s.mu.Lock()
		if cur := s.flows[key]; cur == f {
			f.seen = time.Now()
		}
		s.mu.Unlock()
		if _, err := s.conn.WriteToUDP(pkt, to); err != nil {
			return
		}
	}
}

// reap closes flows nothing has used recently.
//
// This is the bounded-table discipline the admin login limiter had to learn:
// the map is keyed by a source address the sender chooses, so without an
// eviction path a single host spraying spoofed sources — or one ordinary
// IPv6 /64, which is 2^64 of them — would pin a socket and a goroutine per
// packet until the node ran out of file descriptors.
func (s *Server) reap() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-s.idle)
		s.mu.Lock()
		for k, f := range s.flows {
			if f.seen.Before(cutoff) {
				f.sock.Close()
				delete(s.flows, k)
			}
		}
		s.mu.Unlock()
	}
}

// Close stops the server.
func (s *Server) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}
