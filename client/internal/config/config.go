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
	ExpiresAt   int64  `json:"expires_at,omitempty"` // hop pair expiry (epoch s)
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
