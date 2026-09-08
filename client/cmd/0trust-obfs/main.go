// Command 0trust-obfs is the node half of the optional obfuscated transport.
//
// It listens on one UDP port, opens the Shadowsocks AEAD packets customers
// who turned obfuscation on are sending, and hands the WireGuard datagrams
// inside to the node's own tunnel listener on loopback. Replies go back the
// same way.
//
// It is deliberately a separate process from meshd. meshd runs as root
// because it drives `wg syncconf`, `nft` and `ip route`; this parses
// attacker-supplied bytes off a public port and needs none of that, so it
// runs unprivileged under its own systemd unit and can be stopped without
// touching the data plane.
//
// The destination allowlist is not optional and not inferred. Every customer
// on a node holds the same pre-shared key, so a relay that forwarded to
// whatever a packet named would be an open proxy with a published password —
// see the package comment in internal/obfs.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/0trust/cli/internal/obfs"
)

func main() {
	var (
		listen  = flag.String("listen", ":443", "UDP address to listen on")
		ports   = flag.String("wg-ports", "", "comma-separated local WireGuard ports to forward to, e.g. 51820,52000-52099")
		keyEnv  = flag.String("key-env", "ZTV_OBFS_KEY", "environment variable holding the base64 pre-shared key")
		idle    = flag.Duration("idle", 3*time.Minute, "drop a client's forwarding socket after this long with no traffic")
		genkey  = flag.Bool("genkey", false, "print a fresh pre-shared key and exit")
		version = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *version {
		fmt.Println("0trust-obfs (shadowsocks-aead udp relay)")
		return
	}
	if *genkey {
		k, err := obfs.NewKey()
		if err != nil {
			log.Fatalf("0trust-obfs: %v", err)
		}
		fmt.Println(k)
		return
	}

	// The key comes from the environment, never a flag: an argument is
	// visible in `ps` to every account on the box, and on a node that is one
	// `ps aux` away from anyone who gets a shell.
	key := os.Getenv(*keyEnv)
	if key == "" {
		log.Fatalf("0trust-obfs: %s is empty — refusing to start without a key", *keyEnv)
	}

	allowed, err := parsePorts(*ports)
	if err != nil {
		log.Fatalf("0trust-obfs: --wg-ports: %v", err)
	}

	srv, err := obfs.NewServer(key, allowed, *idle)
	if err != nil {
		log.Fatalf("0trust-obfs: %v", err)
	}

	// Say what is actually running. An operator who believes obfuscation is
	// on and is wrong should be able to tell from the journal, which is the
	// same reason meshd names its transport at startup.
	log.Printf("0trust-obfs: listening on %s, forwarding to %d loopback port(s), idle %s",
		*listen, len(allowed), *idle)
	log.Fatalf("0trust-obfs: %v", srv.ListenAndServe(*listen))
}

// parsePorts turns "51820,52000-52099" into loopback destinations.
//
// Ranges are here because multi-hop gives every device its own entry port on
// the entry node (52000-59999), and enumerating eight thousand flags is not
// a configuration format.
func parsePorts(spec string) ([]netip.AddrPort, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("no ports given")
	}
	lo := netip.MustParseAddr("127.0.0.1")
	var out []netip.AddrPort
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		first, last, isRange := strings.Cut(part, "-")
		a, err := port(first)
		if err != nil {
			return nil, err
		}
		b := a
		if isRange {
			if b, err = port(last); err != nil {
				return nil, err
			}
		}
		if b < a {
			return nil, fmt.Errorf("range %q runs backwards", part)
		}
		if b-a > 16384 {
			return nil, fmt.Errorf("range %q is %d ports; that is not a configuration, it is a mistake", part, b-a+1)
		}
		for p := a; p <= b; p++ {
			out = append(out, netip.AddrPortFrom(lo, uint16(p)))
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports given")
	}
	return out, nil
}

func port(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("%q is not a port", s)
	}
	return n, nil
}
