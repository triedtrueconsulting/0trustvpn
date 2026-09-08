// Package config handles local state: the account token, device pubkey,
// and any cached server info.
//
// State lives in:
//
//	Linux/macOS:  ~/.config/0trust/state.json   (mode 0600)
//	Windows:      %APPDATA%\0trust\state.json
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type State struct {
	Token       string `json:"token"`
	DeviceName  string `json:"device_name,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	InterfaceIP string `json:"interface_ip,omitempty"`
	APIBase     string `json:"api_base,omitempty"`

	// Multi-hop session state — populated after connect/rotate
	EntryRegion string `json:"entry_region,omitempty"`
	ExitRegion  string `json:"exit_region,omitempty"`
	// The control plane resolved entry and exit to the same machine — a
	// single-VPS test deployment. Persisted because the window renders the
	// multi-hop privacy claim from it, and after a reload it would otherwise
	// go back to making that claim on a deployment that cannot keep it.
	SameHost  bool  `json:"same_host,omitempty"`
	ExpiresAt int64 `json:"expires_at,omitempty"` // hop pair expiry (epoch s)

	// KillSwitch: block traffic that is not going through the tunnel.
	// Sticky, because a kill switch you have to remember to re-enable on
	// every connect is not a kill switch.
	KillSwitch bool `json:"kill_switch,omitempty"`

	// The IPv6 mesh address the last connect was given, if any. Empty means
	// the exit node had no v6 egress, so v6 is blackholed rather than
	// carried. Recorded so `0trust status` can say which it is instead of
	// leaving the customer to guess.
	InterfaceIP6 string `json:"interface_ip6,omitempty"`

	// Obfuscate: route the tunnel through the node's relay so it does not
	// look like WireGuard on the wire. Sticky for the same reason the kill
	// switch is — a protection you have to remember to re-enable on every
	// connect is not one you can rely on — and off by default, because it
	// costs throughput and most people are not being filtered.
	Obfuscate bool `json:"obfuscate,omitempty"`

	// State of the relay the last connect started. RelayActive distinguishes
	// "the customer asked for obfuscation" (Obfuscate) from "the tunnel is
	// actually running through a relay right now", which are different
	// whenever the node they landed on does not offer one. Reporting the
	// wish as though it were the fact is the single worst thing this feature
	// could do: someone would believe their traffic is unrecognizable when
	// it is plain WireGuard.
	RelayActive bool   `json:"relay_active,omitempty"`
	RelayPID    int    `json:"relay_pid,omitempty"`
	RelayLocal  string `json:"relay_local,omitempty"`
	RelayServer string `json:"relay_server,omitempty"`
}

func configDir() (string, error) {
	if runtime.GOOS == "windows" {
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return "", errors.New("APPDATA not set")
		}
		return filepath.Join(appdata, "0trust"), nil
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		xdg = filepath.Join(home, ".config")
	}
	return filepath.Join(xdg, "0trust"), nil
}

func statePath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "state.json"), nil
}

// Load reads state from disk. Returns an empty State (not an error) if
// the file doesn't exist yet.
func Load() (*State, error) {
	path, err := statePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &State{APIBase: defaultAPIBase()}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	if s.APIBase == "" {
		s.APIBase = defaultAPIBase()
	}
	return &s, nil
}

// Save writes state to disk atomically with mode 0600.
func (s *State) Save() error {
	path, err := statePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Clear wipes the local state file (logout).
func Clear() error {
	path, err := statePath()
	if err != nil {
		return err
	}
	err = os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func defaultAPIBase() string {
	if v := os.Getenv("ZTV_API_BASE"); v != "" {
		return v
	}
	return "https://0trustvpn.com"
}
