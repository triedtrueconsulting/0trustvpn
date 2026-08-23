// Package export builds standalone WireGuard config files that can be
// imported into the official WireGuard apps for iOS/Android/macOS/etc.
//
// This is the pragmatic mobile path: until we ship native mobile apps,
// customers use the free official WireGuard apps and import a config we
// hand them as either a .conf file or a QR code (since WireGuard mobile
// apps read QR codes via the camera).
package export

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/0trust/cli/internal/api"
	"github.com/0trust/cli/internal/config"
	"github.com/0trust/cli/internal/wg"
	qrcode "github.com/skip2/go-qrcode"
)

type Result struct {
	Config     string // raw wg-quick config
	ConfigPath string // where we wrote the .conf file
	PNGPath    string // where we wrote the QR PNG, if requested
	QRASCII    string // ASCII QR for printing in the terminal
	Multihop   bool
	EntryNode  string
	ExitNode   string
}

// Options controls what export produces.
type Options struct {
	Region     string // entry region
	ExitRegion string // empty = single-hop
	OutDir     string // where to write files (default: cwd)
	WritePNG   bool   // write a PNG QR code file (in addition to ASCII)
	WriteConf  bool   // write a .conf file
	Name       string // basename for output files (default: "0trust-mobile")
}

// Build creates a WireGuard config for a new mobile device. It calls
// /api/v1/wg/register with a freshly-generated keypair so the device gets
// its own peer entry; the caller's CLI keypair is unaffected.
//
// CAUTION: the private key is embedded in the returned config. Treat it
// like a password. The QR code likewise contains the private key — anyone
// who photographs the screen owns that device's mesh identity.
func Build(opts Options) (*Result, error) {
	if opts.Region == "" {
		opts.Region = "zur"
	}
	if opts.Name == "" {
		opts.Name = "0trust-mobile"
	}
	if opts.OutDir == "" {
		opts.OutDir = "."
	}

	st, err := config.Load()
	if err != nil {
		return nil, err
	}
	if st.Token == "" {
		return nil, fmt.Errorf("not logged in — run: 0trust login")
	}

	// Fresh keypair for THIS exported device — never the desktop's keypair
	priv, pub, err := wg.GenKeypair()
	if err != nil {
		return nil, fmt.Errorf("keygen: %w", err)
	}

	c := api.New(st.APIBase, st.Token)
	resp, err := c.Register(api.RegisterReq{
		Pubkey:     pub,
		DeviceName: opts.Name,
		Region:     opts.Region,
		ExitRegion: opts.ExitRegion,
	})
	if err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}

	cfg := wg.BuildConfig(priv, resp.InterfaceIP, resp.DNS, resp.Peers)

	res := &Result{
		Config:    cfg,
		Multihop:  resp.Multihop,
		EntryNode: resp.EntryNode,
		ExitNode:  resp.ExitNode,
	}

	// ASCII QR for the terminal (works in any iTerm/Konsole/wt)
	q, err := qrcode.New(cfg, qrcode.Medium)
	if err != nil {
		return nil, fmt.Errorf("qr encode: %w", err)
	}
	res.QRASCII = q.ToString(false)

	if opts.WriteConf {
		path := opts.OutDir + "/" + opts.Name + ".conf"
		if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
			return nil, fmt.Errorf("write .conf: %w", err)
		}
		res.ConfigPath = path
	}
	if opts.WritePNG {
		path := opts.OutDir + "/" + opts.Name + ".png"
		if err := q.WriteFile(512, path); err != nil {
			return nil, fmt.Errorf("write .png: %w", err)
		}
		res.PNGPath = path
	}

	return res, nil
}

// QRDataURL returns a data: URI PNG QR for the given config. Used by the GUI.
func QRDataURL(cfg string) (string, error) {
	q, err := qrcode.New(cfg, qrcode.Medium)
	if err != nil {
		return "", err
	}
	png, err := q.PNG(384)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
