package wg

import (
	"runtime"
	"strings"
	"testing"

	"github.com/0trust/cli/internal/api"
)

func samplePeers() []api.Peer {
	return []api.Peer{{
		PublicKey:           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Endpoint:            "203.0.113.10:51820",
		AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
		PersistentKeepalive: 25,
	}}
}

// A tunnel that is up but has never handshaked is not a working tunnel, and
// the difference is the whole point of the check. `wg show` reports 0 for a
// peer that has never completed one.
func TestParseLatestHandshake(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want int64
	}{
		{"no peers", "", 0},
		{"never handshaked", "PUBKEY\t0\n", 0},
		{"one peer", "PUBKEY\t1700000000\n", 1700000000},
		{"newest of several",
			"A\t1700000000\nB\t1700000900\nC\t0\n", 1700000900},
		{"junk is ignored", "garbage\nA\tnotanumber\nB\t1700000001\n", 1700000001},
		{"negative is not a handshake", "A\t-5\n", 0},
	} {
		got := parseLatestHandshake(tc.out)
		if tc.want == 0 {
			if !got.IsZero() {
				t.Errorf("%s: expected no handshake, got %v", tc.name, got)
			}
			continue
		}
		if got.Unix() != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, got.Unix(), tc.want)
		}
	}
}

// The config is the product. Anything malformed here is a tunnel that either
// refuses to come up or comes up wrong.
func TestBuildConfigBasics(t *testing.T) {
	cfg := BuildConfig("PRIVKEY", "10.64.0.5/32", []string{"10.64.0.1"}, samplePeers())
	for _, want := range []string{
		"[Interface]", "PrivateKey = PRIVKEY", "Address = 10.64.0.5/32",
		"DNS = 10.64.0.1", "[Peer]", "Endpoint = 203.0.113.10:51820",
		// Without a keepalive the tunnel dies silently behind NAT once the
		// router drops the mapping, typically after 30-180 seconds idle.
		"PersistentKeepalive = 25",
		// ::/0 with no v6 address on the interface is what stops IPv6
		// leaking around the tunnel on a dual-stack host.
		"AllowedIPs = 0.0.0.0/0, ::/0",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, "PostUp") {
		t.Error("kill switch rules present without WithKillSwitch")
	}
	if strings.Contains(cfg, "%!") {
		t.Errorf("format artefact in config:\n%s", cfg)
	}
}

func TestKillSwitch(t *testing.T) {
	cfg := BuildConfig("P", "10.64.0.5/32", []string{"10.64.0.1"},
		samplePeers(), WithKillSwitch())
	if strings.Contains(cfg, "%!") {
		t.Fatalf("format artefact in config:\n%s", cfg)
	}
	if runtime.GOOS != "linux" {
		if strings.Contains(cfg, "PostUp") {
			t.Errorf("emitted iptables rules on %s, where wg-quick cannot run them",
				runtime.GOOS)
		}
		return
	}
	for _, want := range []string{
		"PostUp = iptables -I OUTPUT",
		"PostUp = ip6tables -I OUTPUT",
		"PreDown = iptables -D OUTPUT",
		"PreDown = ip6tables -D OUTPUT",
		// wg-quick substitutes %i; it must survive into the config verbatim.
		"! -o %i",
		"$(wg show %i fwmark)",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("kill switch missing %q:\n%s", want, cfg)
		}
	}
	// `iptables -D` on a rule that is not installed exits non-zero. If that
	// fails, wg-quick refuses to bring the tunnel down and the user is stuck
	// with no route to the internet and no way to remove it.
	for _, line := range strings.Split(cfg, "\n") {
		if strings.HasPrefix(line, "PreDown") && !strings.HasSuffix(line, "|| true") {
			t.Errorf("PreDown must not be able to fail: %q", line)
		}
	}
}

func TestOptionsFor(t *testing.T) {
	if len(OptionsFor(false)) != 0 {
		t.Error("OptionsFor(false) should add nothing")
	}
	on := BuildConfig("P", "10.64.0.5/32", nil, samplePeers(), OptionsFor(true)...)
	off := BuildConfig("P", "10.64.0.5/32", nil, samplePeers(), OptionsFor(false)...)
	if runtime.GOOS == "linux" && on == off {
		t.Error("OptionsFor(true) produced the same config as (false)")
	}
}
