// Package wg manages the 0trust WireGuard tunnel.
//
// Implementation strategy varies by platform:
//   - Linux:   shells out to wg-quick(8) + wg(8)
//   - macOS:   shells out to wg-quick(8) + wg(8) (via Homebrew or
//              the WireGuard for macOS app's CLI tools)
//   - Windows: integrates with WireGuard for Windows via the tunnel
//              service IPC (wireguard.exe /installtunnelservice)
//
// Keys are now generated in pure Go (Curve25519) so the binary does not
// depend on `wg(8)` being in PATH just to mint a keypair — that lets the
// installer create a usable client config the first time it runs without
// requiring the user to have WireGuard already installed.
package wg

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/0trust/cli/internal/api"
)

const ifname = "0trust0"

// GenKeypair generates a Curve25519 keypair using crypto/ecdh from the
// Go stdlib (no external deps). Returns (privateKey, publicKey), each
// base64-encoded per WireGuard convention.
func GenKeypair() (string, string, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("x25519 keygen: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// BuildConfig serializes a wg-quick / WireGuard-for-Windows compatible config.
func BuildConfig(privKey, interfaceIP string, dns []string, peers []api.Peer) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", privKey)
	fmt.Fprintf(&b, "Address = %s\n", interfaceIP)
	if len(dns) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(dns, ", "))
	}
	b.WriteString("\n")
	for _, p := range peers {
		b.WriteString("[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.PersistentKeepalive)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// configPath returns the canonical config file location for this platform.
func configPath() string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join("/usr/local/etc/wireguard", ifname+".conf")
	case "windows":
		// %ProgramData%\0trust\0trust0.conf — readable by the WireGuard
		// Tunnel Service running as LocalSystem
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "0trust", ifname+".conf")
	default:
		return filepath.Join("/etc/wireguard", ifname+".conf")
	}
}

// WriteConfig writes a wg-quick config atomically with mode 0600.
func WriteConfig(content string) (string, error) {
	path := configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}
