//go:build windows

// Windows tunnel control via the official WireGuard for Windows tunnel service.
//
// We use the "installtunnelservice" / "uninstalltunnelservice" CLI documented at
// https://git.zx2c4.com/wireguard-windows/about/ to register a Windows service
// that runs the tunnel. This is the same mechanism the official WireGuard UI
// uses internally, so we get the kernel-mode WireGuard NT driver
// (`wireguard.sys`) and all of its performance and stability properties.
//
// Prerequisite for end users: WireGuard for Windows must be installed
// (https://www.wireguard.com/install/). Our MSI installer prompts for this
// during setup and bundles a download link.
package wg

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// wireguardExe locates the official wireguard.exe by checking the standard
// install paths first, then PATH. Returns an empty string if not found
// (caller should surface "install WireGuard first").
func wireguardExe() string {
	for _, candidate := range []string{
		`C:\Program Files\WireGuard\wireguard.exe`,
		`C:\Program Files (x86)\WireGuard\wireguard.exe`,
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	if path, err := exec.LookPath("wireguard.exe"); err == nil {
		return path
	}
	return ""
}

// ensureWireguardExe returns the wireguard.exe path or a user-friendly error.
func ensureWireguardExe() (string, error) {
	p := wireguardExe()
	if p == "" {
		return "", fmt.Errorf(`WireGuard for Windows is not installed.

The 0trust client uses the official WireGuard tunnel service for the actual
VPN data plane. Install it from https://www.wireguard.com/install/ and try
again. (The 0trust installer should normally do this for you.)`)
	}
	return p, nil
}

// Up brings the tunnel up by installing the tunnel service for our config.
// The service is named WireGuardTunnel$<ifname> and runs as LocalSystem.
// It survives the user logging out.
func Up() error {
	if IsUp() {
		return nil
	}
	exe, err := ensureWireguardExe()
	if err != nil {
		return err
	}
	cfg := configPath()
	if _, err := os.Stat(cfg); err != nil {
		return fmt.Errorf("config %s not found — run `0trust connect` first", cfg)
	}
	_, err = run(exe, "/installtunnelservice", cfg)
	return err
}

// SyncConfig: on Windows, the tunnel service watches the config file for
// changes. Rewriting it triggers a reload of the peer list without a full
// service restart. We still re-call /installtunnelservice as a belt-and-
// suspenders measure if the service isn't running.
func SyncConfig(content string) error {
	if _, err := WriteConfig(content); err != nil {
		return err
	}
	if !IsUp() {
		return Up()
	}
	// The tunnel service hot-reloads the peer list when the file mtime changes.
	// Touch the file to make sure the watcher fires even on filesystems with
	// coarse mtime resolution.
	cfg := configPath()
	now := time.Now()
	_ = os.Chtimes(cfg, now, now)
	return nil
}

// Down uninstalls the tunnel service.
func Down() error {
	if !IsUp() {
		return nil
	}
	exe, err := ensureWireguardExe()
	if err != nil {
		return err
	}
	_, err = run(exe, "/uninstalltunnelservice", ifname)
	return err
}

// IsUp checks whether the Windows service WireGuardTunnel$<ifname> exists
// and is currently running.
func IsUp() bool {
	// sc.exe is in System32, always available
	cmd := exec.Command("sc.exe", "query", "WireGuardTunnel$"+ifname)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "RUNNING")
}

// Show returns a status summary. WireGuard for Windows doesn't have a `wg show`
// equivalent, so we return service state + the config file location.
func Show() (string, error) {
	state := "STOPPED"
	if IsUp() {
		state = "RUNNING"
	}
	return fmt.Sprintf("Service: WireGuardTunnel$%s  State: %s\nConfig: %s\n",
		ifname, state, configPath()), nil
}

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %s", name, strings.Join(args, " "),
			strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
