package main

import (
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/0trust/cli/internal/obfs"
)

// cmdRelay runs the client half of the obfuscated transport in the
// foreground. `0trust connect --obfuscate` spawns it; it is not a command
// anyone should type.
func cmdRelay(args []string) error {
	var listen, server, target string
	for i := 0; i < len(args); i++ {
		if i+1 >= len(args) {
			break
		}
		switch args[i] {
		case "--listen":
			listen, i = args[i+1], i+1
		case "--server":
			server, i = args[i+1], i+1
		case "--target":
			target, i = args[i+1], i+1
		}
	}
	if listen == "" || server == "" || target == "" {
		return fmt.Errorf("relay: --listen, --server and --target are all required")
	}
	key := os.Getenv(obfs.KeyEnv)
	if key == "" {
		return fmt.Errorf("relay: %s is empty", obfs.KeyEnv)
	}
	lp, err := netip.ParseAddrPort(listen)
	if err != nil {
		return fmt.Errorf("relay: --listen %q: %w", listen, err)
	}
	tgt, err := netip.ParseAddrPort(target)
	if err != nil {
		return fmt.Errorf("relay: --target %q: %w", target, err)
	}

	r, err := obfs.NewRelay(server, key, tgt)
	if err != nil {
		return err
	}
	r.LocalPort = int(lp.Port())
	if err := r.Start(); err != nil {
		return err
	}
	defer r.Close()

	// Wait to be stopped. `0trust disconnect` sends SIGTERM; anything else
	// that ends this process ends the tunnel's transport, which the tunnel
	// itself will notice as a dead handshake.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	return nil
}
