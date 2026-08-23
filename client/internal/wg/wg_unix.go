//go:build !windows

// Unix (Linux + macOS) tunnel control via wg-quick(8) and wg(8).
package wg

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Up brings the tunnel up. Requires root.
func Up() error {
	if IsUp() {
		return nil
	}
	_, err := run("wg-quick", "up", ifname)
	return err
}

// SyncConfig hot-swaps the peer list on an already-up interface using
// `wg syncconf` — preserves the socket, IP, and active connections to peers
// that didn't change. Used for hop-pair rotation.
func SyncConfig(content string) error {
	if !IsUp() {
		return fmt.Errorf("interface %s is not up", ifname)
	}
	path, err := WriteConfig(content)
	if err != nil {
		return err
	}
	_, err = run("wg", "syncconf", ifname, path)
	return err
}

// Down tears the tunnel down. Idempotent.
func Down() error {
	if !IsUp() {
		return nil
	}
	_, err := run("wg-quick", "down", ifname)
	return err
}

// IsUp reports whether the tunnel interface currently exists.
func IsUp() bool {
	out, err := exec.Command("wg", "show", "interfaces").Output()
	if err != nil {
		return false
	}
	for _, name := range strings.Fields(string(out)) {
		if name == ifname {
			return true
		}
	}
	return false
}

// Show returns the raw `wg show` output for the interface.
func Show() (string, error) {
	return run("wg", "show", ifname)
}

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), stderr.String())
	}
	return stdout.String(), nil
}

// LatestHandshake returns the most recent successful handshake across all
// peers, or the zero time if none has happened yet.
//
// `wg-quick up` configures an interface; it does not talk to anybody. So it
// succeeds whether or not the node is reachable, and a client that reports
// success on its exit code tells the user they are protected when the tunnel
// may be carrying nothing. With AllowedIPs capturing the default route, the
// visible symptom is "my internet is broken", which is the worst way to find
// out. A handshake is the only proof the tunnel actually works.
func LatestHandshake() (time.Time, error) {
	out, err := run("wg", "show", ifname, "latest-handshakes")
	if err != nil {
		return time.Time{}, err
	}
	return parseLatestHandshake(out), nil
}
