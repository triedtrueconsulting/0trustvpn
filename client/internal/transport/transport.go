// Package transport decides how a tunnel's packets reach the node, and owns
// the relay process when they go the obfuscated way.
//
// It exists as its own package because there are three callers — `0trust
// connect`, `0trust rotate` and the GUI's connect handler — and every one of
// them has to make the same decision. Leaving the logic in the CLI and
// letting the window reimplement it is precisely how rotate came to write
// configs without the kill switch the customer had asked for: a second copy
// of a decision is a second chance to forget half of it.
package transport

import (
	"fmt"
	"net/netip"

	"github.com/0trust/cli/internal/api"
	"github.com/0trust/cli/internal/config"
	"github.com/0trust/cli/internal/obfs"
)

// Result is what Apply decided.
type Result struct {
	// MTU to write into the WireGuard config. Never zero unless the control
	// plane sent nothing, in which case the caller leaves it to wg-quick.
	MTU int
	// Active is whether the tunnel is REALLY going through a relay. It is
	// false whenever the customer asked and could not have it, which is a
	// normal outcome and must be reported as such.
	Active bool
	// Notes are lines to show the user. They exist because every "we could
	// not do what you asked" path here has to be visible: silently
	// connecting directly when someone turned on DPI protection would leave
	// them believing their traffic is unrecognizable when it is not.
	Notes []string
}

// Apply stops any relay left from a previous connection, starts a new one if
// the customer wants obfuscation and this node offers it, and rewrites the
// peer endpoints to point at it.
//
// It always stops the old relay first, even when obfuscation is off. A relay
// from a previous connect is aimed at whichever node that connect chose,
// which after a rotate or a region change is not this one — leaving it
// running holds a loopback port and sends the new tunnel's packets to the
// old node.
//
// The caller must Save() the state afterwards.
func Apply(st *config.State, resp *api.RegisterResp) Result {
	Stop(st)

	res := Result{MTU: resp.MTU}
	if !st.Obfuscate {
		return res
	}
	if resp.Obfuscation == nil {
		res.Notes = append(res.Notes,
			"obfuscation requested, but this node does not run a relay",
			"connecting directly — the tunnel is encrypted as always, but on",
			"the wire it is recognizably WireGuard")
		return res
	}

	ob := resp.Obfuscation
	if ob.Kind != "shadowsocks" {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"this node offers an obfuscation kind this client does not "+
				"implement (%q) — connecting directly", ob.Kind))
		return res
	}
	tgt, err := netip.ParseAddrPort(ob.Target)
	if err != nil {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"the node published an unusable relay target (%q) — connecting directly",
			ob.Target))
		return res
	}
	port, err := obfs.FreeLoopbackPort()
	if err != nil {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"no free loopback port for the relay (%v) — connecting directly", err))
		return res
	}
	pid, err := obfs.Spawn(port, ob.Endpoint, tgt.String(), ob.Key)
	if err != nil {
		res.Notes = append(res.Notes, fmt.Sprintf(
			"could not start the relay (%v) — connecting directly", err))
		return res
	}

	local := fmt.Sprintf("127.0.0.1:%d", port)
	// WireGuard now talks to the relay. The node's real endpoint is what the
	// relay dials; the tunnel never sees it.
	for i := range resp.Peers {
		resp.Peers[i].Endpoint = local
	}
	st.RelayActive, st.RelayPID = true, pid
	st.RelayLocal, st.RelayServer = local, ob.Endpoint

	res.Active = true
	res.MTU = ob.MTU
	if res.MTU <= 0 {
		res.MTU = resp.MTU
	}
	res.Notes = append(res.Notes,
		fmt.Sprintf("obfuscation ON — %s via %s", ob.Method, ob.Endpoint),
		"the handshake is sealed, so DPI cannot identify this as WireGuard",
		"it does not hide that you are talking to this address, or how much")
	return res
}

// Stop ends the recorded relay and clears the state that named it. Safe when
// there is nothing running. The caller must Save().
func Stop(st *config.State) {
	if st.RelayPID > 0 {
		_ = obfs.Stop(st.RelayPID)
	}
	st.RelayActive, st.RelayPID = false, 0
	st.RelayLocal, st.RelayServer = "", ""
}

// Running reports whether the recorded relay process is still alive.
func Running(st *config.State) bool {
	return st.RelayActive && obfs.Running(st.RelayPID)
}

// Describe is the one-line transport summary every surface shows.
//
// It reads the live process, never the setting. "The customer asked for
// obfuscation" and "the traffic is obfuscated" are different facts, and
// showing the first where the second belongs is the one mistake this feature
// must not make.
func Describe(st *config.State) string {
	switch {
	case Running(st):
		return "obfuscated (shadowsocks via " + st.RelayServer + ")"
	case st.RelayActive:
		return "obfuscation was ON but the relay is not running — " +
			"the tunnel cannot be carrying traffic"
	case st.Obfuscate:
		return "direct (obfuscation is on, but this node offers no relay)"
	default:
		return "direct"
	}
}

// Short is Describe in one or two words, for a status field with no room.
func Short(st *config.State) string {
	switch {
	case Running(st):
		return "obfuscated"
	case st.RelayActive:
		return "relay stopped"
	case st.Obfuscate:
		return "direct (no relay on this node)"
	default:
		return "direct"
	}
}
