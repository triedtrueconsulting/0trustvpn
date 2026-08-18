//go:build !windows

// Unix (Linux + macOS) tunnel control via wg-quick(8) and wg(8).
package wg

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
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
