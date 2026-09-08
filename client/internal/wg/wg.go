// Package wg manages the 0trust WireGuard tunnel.
//
// Implementation strategy varies by platform:
//   - Linux:   shells out to wg-quick(8) + wg(8)
//   - macOS:   shells out to wg-quick(8) + wg(8) (via Homebrew or
//     the WireGuard for macOS app's CLI tools)
//   - Windows: integrates with WireGuard for Windows via the tunnel
//     service IPC (wireguard.exe /installtunnelservice)
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
	"strconv"
	"strings"
	"time"

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

// Option tunes the generated config.
type Option func(*buildOpts)

type buildOpts struct {
	killSwitch bool
	mtu        int
}

// WithMTU pins the interface MTU instead of letting wg-quick derive one.
//
// This is not a tuning knob. wg-quick's derivation assumes the tunnel's
// packets go straight onto the path, and that stops being true the moment
// the obfuscation relay wraps each datagram in 55 more bytes: the derived
// MTU then produces outer packets larger than the path carries, which the
// network drops. The handshake is small enough to fit either way, so the
// tunnel comes up and looks healthy while full-size packets vanish. The
// control plane publishes the right number per transport; this writes it.

func WithMTU(mtu int) Option { return func(o *buildOpts) { o.mtu = mtu } }

// WithKillSwitch blocks any traffic that is not going through the tunnel, so
// a tunnel that drops takes the connection down with it instead of quietly
// failing open onto the local network.
func WithKillSwitch() Option { return func(o *buildOpts) { o.killSwitch = true } }

// killSwitchLines returns the PostUp/PreDown rules for this platform.
//
// Linux gets the rule from wg-quick(8)'s own documentation: reject anything
// leaving a non-tunnel interface that is not marked as ours and is not
// destined for a local address. Traffic to the LAN is blocked too — that is
// the point of a strict kill switch, and it does mean local printers and
// network shares stop working while it is on.
//
// macOS gets nothing: wg-quick there drives pf, not iptables, and emitting
// rules it cannot run would abort the tunnel rather than protect it. Saying
// so is better than pretending.
//
// Windows gets nothing here either, and needs nothing: WireGuard for Windows
// turns on its own kill switch whenever AllowedIPs covers all of v4 and v6,
// which ours does.
func killSwitchLines() []string {
	if runtime.GOOS != "linux" {
		return nil
	}
	// %i is wg-quick's own placeholder for the interface name; it is passed
	// through to the shell verbatim, not formatted here.
	const rule = "! -o %i -m mark ! --mark $(wg show %i fwmark) " +
		"-m addrtype ! --dst-type LOCAL -j REJECT"
	return []string{
		"PostUp = iptables -I OUTPUT " + rule,
		// Tolerated failure, on purpose. A host with no ip6tables binary
		// would otherwise fail PostUp and take the whole tunnel down, and
		// IPv6 is already fail-closed: AllowedIPs claims ::/0 while the
		// interface has no v6 address, so v6 has nowhere to go.
		"PostUp = ip6tables -I OUTPUT " + rule + " || true",
		// PreDown must never fail: `iptables -D` on a rule that is not there
		// returns non-zero, and wg-quick would then refuse to bring the
		// tunnel down — leaving the user with no way to get back online.
		"PreDown = iptables -D OUTPUT " + rule + " || true",
		"PreDown = ip6tables -D OUTPUT " + rule + " || true",
	}
}

// OptionsFor turns the persisted setting into build options. One place, so a
// code path that forgets it cannot silently ship a config without the kill
// switch the user asked for — which is exactly what rotate used to do.
func OptionsFor(killSwitch bool, mtu ...int) []Option {
	var opts []Option
	if killSwitch {
		opts = append(opts, WithKillSwitch())
	}
	if len(mtu) > 0 && mtu[0] > 0 {
		opts = append(opts, WithMTU(mtu[0]))
	}
	return opts
}

// KillSwitchSupported reports whether WithKillSwitch does anything here.
func KillSwitchSupported() bool { return runtime.GOOS == "linux" || runtime.GOOS == "windows" }

// BuildConfig serializes a wg-quick / WireGuard-for-Windows compatible config.
func BuildConfig(privKey, interfaceIP string, dns []string, peers []api.Peer, opts ...Option) string {
	return buildConfig(privKey, []string{interfaceIP}, dns, peers, opts...)
}

// BuildConfigDual is BuildConfig with an IPv6 address as well. An empty
// interfaceIP6 gives exactly the v4-only config BuildConfig would.
func BuildConfigDual(privKey, interfaceIP, interfaceIP6 string, dns []string,
	peers []api.Peer, opts ...Option) string {
	addrs := []string{interfaceIP}
	if interfaceIP6 != "" {
		addrs = append(addrs, interfaceIP6)
	}
	return buildConfig(privKey, addrs, dns, peers, opts...)
}

func buildConfig(privKey string, addrs []string, dns []string, peers []api.Peer,
	opts ...Option) string {
	var o buildOpts
	for _, fn := range opts {
		fn(&o)
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", privKey)
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(addrs, ", "))
	if len(dns) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(dns, ", "))
	}
	if o.mtu > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", o.mtu)
	}
	if o.killSwitch {
		for _, line := range killSwitchLines() {
			b.WriteString(line + "\n")
		}
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
//
// ZTV_WG_CONFIG_DIR overrides the directory. That exists for the test suite,
// which drives the real binary and must not write into the host's actual
// /etc/wireguard to do it — it had been doing exactly that, and a check that
// "no kill-switch rules are present" passed by reading a file that was not
// where the test thought it was. In normal use the override is unset and
// wg-quick's own lookup by interface name requires the standard location
// anyway.
func configPath() string {
	if dir := os.Getenv("ZTV_WG_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, ifname+".conf")
	}
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

// parseLatestHandshake reads `wg show <iface> latest-handshakes` output —
// one "<pubkey>\t<unix seconds>" line per peer — and returns the most recent
// non-zero timestamp. Peers that have never handshaked report 0.
func parseLatestHandshake(out string) time.Time {
	var newest int64
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		// Exactly two fields, not "at least two". `wg show <iface>
		// latest-handshakes` emits "<pubkey>\t<seconds>" and nothing else,
		// so anything wider is some other output that happens to end in a
		// number — "listening port: 51820" would otherwise be read as a
		// handshake in 1970 and reported as a working tunnel.
		if len(fields) != 2 {
			continue
		}
		ts, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || ts <= 0 {
			continue
		}
		if ts > newest {
			newest = ts
		}
	}
	if newest == 0 {
		return time.Time{}
	}
	return time.Unix(newest, 0)
}

// WaitForHandshake polls until a peer handshakes or the deadline passes.
// A zero time with a nil error means "no handshake yet", not a failure to
// look — the caller decides what to tell the user.
func WaitForHandshake(timeout time.Duration) (time.Time, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		hs, err := LatestHandshake()
		if err == nil && !hs.IsZero() {
			return hs, nil
		}
		if err != nil {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return time.Time{}, lastErr
		}
		time.Sleep(500 * time.Millisecond)
	}
}
