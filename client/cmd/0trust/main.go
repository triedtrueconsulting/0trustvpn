// 0trust — VPN client
//
// Usage:
//
//	0trust login           Enter your account token (stored locally)
//	0trust status          Show subscription + tunnel state
//	0trust regions         List available mesh regions
//	0trust connect [region]   Bring up the tunnel
//	0trust disconnect      Tear down the tunnel
//	0trust logout          Wipe local state
//	0trust version
//
// Run with sudo for connect/disconnect (needs CAP_NET_ADMIN).
package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/0trust/cli/internal/api"
	"github.com/0trust/cli/internal/config"
	"github.com/0trust/cli/internal/export"
	"github.com/0trust/cli/internal/gui"
	"github.com/0trust/cli/internal/wg"
)

const version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "login":
		err = cmdLogin()
	case "logout":
		err = cmdLogout()
	case "status":
		err = cmdStatus()
	case "connect":
		region, exitRegion := "zur", ""
		// killSwitch is a tri-state: unset means "keep whatever was chosen
		// last time". A safety setting that silently switches itself off
		// because the flag was not repeated is worse than not having one.
		var killSwitch *bool
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch {
			case a == "--exit" && i+1 < len(args):
				exitRegion = args[i+1]
				i++
			case a == "--kill-switch":
				t := true
				killSwitch = &t
			case a == "--no-kill-switch":
				f := false
				killSwitch = &f
			case !strings.HasPrefix(a, "--"):
				region = a
			}
		}
		err = cmdConnect(region, exitRegion, killSwitch)
	case "rotate":
		err = cmdRotate()
	case "devices":
		err = cmdDevices()
	case "remove":
		err = cmdRemoveDevice(args)
	case "export":
		err = cmdExport(args)
	case "gui":
		// --no-browser flag suppresses auto-opening (useful when launching
		// via desktop shortcut where the browser opens itself)
		open := true
		for _, a := range args {
			if a == "--no-browser" {
				open = false
			}
		}
		err = gui.Serve(open)
	case "disconnect":
		err = cmdDisconnect()
	case "regions":
		err = cmdRegions()
	case "version", "--version", "-v":
		fmt.Printf("0trust %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "✗ %s\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`0trust — encrypted mesh VPN client

USAGE
  0trust <command> [args]

COMMANDS
  login                          Enter your account token
  logout                         Wipe local state
  status                         Show subscription + tunnel state
  regions                        List available mesh regions
  connect [region] [--exit r]    Bring up the tunnel
        [--kill-switch]          Block any traffic outside the tunnel (sticky)
        [--no-kill-switch]       Turn that back off
                                   region:  entry region (default: zur)
                                   --exit:  enable multi-hop; exit region
  rotate                         Rotate to a fresh entry/exit pair
                                   (only meaningful for multi-hop)
  devices                        List devices registered on this account
  remove <pubkey|this>           Deregister a device and free its slot
                                   ("this" removes the device you're on)
  export [flags]                 Create a config + QR for a mobile device
                                   --region <r>   entry region (default zur)
                                   --exit   <r>   multi-hop exit region
                                   --name   <n>   device name (default 0trust-mobile)
                                   --out    <d>   output directory (default .)
                                   --no-files     QR-only, no .conf or .png on disk
  gui [--no-browser]             Open the desktop GUI in your browser
  disconnect                     Tear down the tunnel
  version                        Print version

EXAMPLES
  0trust connect zur                  single-hop in Switzerland
  0trust connect zur --exit buc       multi-hop: zur entry → buc exit
  0trust rotate                       refresh the multi-hop pair
  0trust export --exit buc --name phone     QR for iOS/Android WireGuard app
  sudo 0trust gui                     graphical client

ROTATION
  Multi-hop pairs expire every 24h. Cron the rotate command to keep your
  tunnel fresh automatically:
    0 4 * * *  /usr/local/bin/0trust rotate

CONNECT / DISCONNECT / ROTATE NEED ROOT
  sudo 0trust connect`)
}

// ---------------------------------------------------------------------------

func cmdLogin() error {
	fmt.Print("Account token: ")
	reader := bufio.NewReader(os.Stdin)
	token, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	token = strings.ToUpper(strings.TrimSpace(token))
	if !validToken(token) {
		return fmt.Errorf("token must be 16 chars in 4-char groups (XXXX-XXXX-XXXX-XXXX)")
	}

	st, _ := config.Load()
	st.Token = token

	// Verify it before saving
	c := api.New(st.APIBase, token)
	status, err := c.Status()
	if err != nil {
		return fmt.Errorf("token rejected: %w", err)
	}

	if err := st.Save(); err != nil {
		return err
	}
	fmt.Printf("✓ logged in — subscription %s (%s remaining)\n",
		status.Status, plural(status.DaysRemaining, "day"))
	return nil
}

func cmdLogout() error {
	if wg.IsUp() {
		fmt.Println("disconnecting first…")
		if err := requireRoot(); err == nil {
			_ = wg.Down()
		}
	}
	return config.Clear()
}

func cmdStatus() error {
	st, err := config.Load()
	if err != nil {
		return err
	}
	if st.Token == "" {
		fmt.Println("⊘ not logged in — run: 0trust login")
		return nil
	}

	c := api.New(st.APIBase, st.Token)
	s, err := c.Status()
	if err != nil {
		return err
	}

	expiryStr := "—"
	if s.ExpiresAt > 0 {
		expiryStr = time.Unix(s.ExpiresAt, 0).Format("2006-01-02")
	}

	mode := "single-hop"
	if st.ExitRegion != "" {
		mode = fmt.Sprintf("multi-hop  %s → %s", st.EntryRegion, st.ExitRegion)
	}
	rotateStr := "—"
	if st.ExpiresAt > 0 {
		remaining := time.Until(time.Unix(st.ExpiresAt, 0)).Round(time.Minute)
		if remaining > 0 {
			rotateStr = fmt.Sprintf("%s  (in %s)",
				time.Unix(st.ExpiresAt, 0).Format("15:04"), remaining)
		} else {
			rotateStr = "due now — run: sudo 0trust rotate"
		}
	}

	// Whether v6 is carried depends on the exit node, so it is a property of
	// this connection rather than of the product. Say which one you have.
	ipv6Str := "blackholed (this exit has no IPv6 — it cannot leak)"
	if st.InterfaceIP6 != "" {
		ipv6Str = st.InterfaceIP6
	}
	killStr := "off"
	if st.KillSwitch {
		killStr = "on"
		if !wg.KillSwitchSupported() {
			killStr = "requested, but NOT available on this platform"
		}
	}

	// The device cap is per-plan — a trial account gets fewer than a paid one
	// — so it has to come from the server. Printing a constant 8 told trial
	// customers they had six devices spare when the next register would 409.
	// Same bug the Android app carried. Fall back only if the field is absent.
	devCap := s.MaxDevices
	if devCap <= 0 {
		devCap = 8
	}

	fmt.Printf(`  account     : %s
  status      : %s
  expires     : %s  (%s)
  devices     : %d / %d
  tunnel      : %s
  mode        : %s
  ipv6        : %s
  kill switch : %s
  next rotate : %s
`,
		maskToken(st.Token), s.Status, expiryStr, plural(s.DaysRemaining, "day"),
		s.DeviceCount, devCap, tunnelState(), mode, ipv6Str, killStr, rotateStr)
	return nil
}

// How long to wait for a peer to answer before telling the user the tunnel is
// not working. WireGuard retries a handshake every 5s, so 15s is three
// attempts — long enough for a slow link, short enough not to feel hung.
const handshakeTimeout = 15 * time.Second

func cmdConnect(region, exitRegion string, killSwitch *bool) error {
	if err := requireRoot(); err != nil {
		return err
	}
	st, err := config.Load()
	if err != nil {
		return err
	}
	if st.Token == "" {
		return fmt.Errorf("not logged in — run: 0trust login")
	}

	// Generate fresh keypair if we don't have one
	if st.PrivateKey == "" || st.PublicKey == "" {
		fmt.Println("→ generating keypair")
		priv, pub, err := wg.GenKeypair()
		if err != nil {
			return err
		}
		st.PrivateKey = priv
		st.PublicKey = pub
		if st.DeviceName == "" {
			host, _ := os.Hostname()
			st.DeviceName = host
		}
		if err := st.Save(); err != nil {
			return err
		}
	}

	if exitRegion != "" {
		fmt.Printf("→ requesting multi-hop route: %s → %s\n", region, exitRegion)
	} else {
		fmt.Printf("→ requesting peers for region %q\n", region)
	}

	c := api.New(st.APIBase, st.Token)
	resp, err := c.Register(api.RegisterReq{
		Pubkey:     st.PublicKey,
		DeviceName: st.DeviceName,
		Region:     region,
		ExitRegion: exitRegion,
	})
	if err != nil {
		var apiErr *api.APIError
		if asAPIErr(err, &apiErr) && apiErr.Status == 409 {
			fmt.Println("→ device already registered, fetching existing peers")
		} else {
			return err
		}
	}

	if killSwitch != nil && *killSwitch != st.KillSwitch {
		st.KillSwitch = *killSwitch
		if err := st.Save(); err != nil {
			return err
		}
	}

	if resp != nil && len(resp.Peers) > 0 {
		st.InterfaceIP = resp.InterfaceIP
		st.InterfaceIP6 = resp.InterfaceIP6
		st.EntryRegion = region
		st.ExitRegion = exitRegion
		st.ExpiresAt = resp.ExpiresAt
		if err := st.Save(); err != nil {
			return err
		}

		cfg := wg.BuildConfigDual(st.PrivateKey, resp.InterfaceIP, resp.InterfaceIP6, resp.DNS, resp.Peers,
			wg.OptionsFor(st.KillSwitch)...)
		path, err := wg.WriteConfig(cfg)
		if err != nil {
			return err
		}
		fmt.Printf("→ config written to %s\n", path)
		if st.KillSwitch {
			if wg.KillSwitchSupported() {
				fmt.Println("→ kill switch ON — traffic outside the tunnel is blocked,")
				fmt.Println("  including your local network. Turn it off with:")
				fmt.Println("  sudo 0trust connect --no-kill-switch")
			} else {
				// Saying nothing here would let someone believe a setting
				// they explicitly turned on is protecting them.
				fmt.Println("⚠ kill switch requested but NOT available on this platform")
				fmt.Println("  (macOS: wg-quick drives pf, not iptables — see docs)")
			}
		}

		if resp.Multihop {
			fmt.Printf("→ multi-hop:  entry=%s  exit=%s\n", resp.EntryNode, resp.ExitNode)
			if resp.SameHost {
				// A single-VPS test deployment: three region codes, one
				// machine. The route is real, so this is worth testing, but
				// printing the privacy claim here would be a plain lie.
				fmt.Printf("              ⚠ entry and exit are the SAME host — this is a\n")
				fmt.Printf("                test deployment. Routing works; nothing is hidden.\n")
			} else {
				fmt.Printf("              entry never decrypts; exit never sees your IP\n")
			}
			for _, p := range resp.Peers {
				fmt.Printf("              relay endpoint  %s\n", p.Endpoint)
			}
			if resp.ExpiresAt > 0 {
				fmt.Printf("              rotates by      %s\n",
					time.Unix(resp.ExpiresAt, 0).Format("2006-01-02 15:04 MST"))
			}
		} else {
			fmt.Printf("→ exit node:\n")
			for _, p := range resp.Peers {
				fmt.Printf("    %s  %s\n", p.ID, p.Endpoint)
			}
		}
	}

	if err := wg.Up(); err != nil {
		return fmt.Errorf("wg-quick up: %w", err)
	}

	// Bringing the interface up proves nothing. wg-quick configures a device
	// and returns; it never contacts the node. Reporting success here told the
	// user they were protected whether or not a single packet could get
	// through — and because AllowedIPs captures the default route, the way
	// they found out was that their internet stopped working.
	hs, err := wg.WaitForHandshake(handshakeTimeout)
	if err != nil {
		// Could not ask (no wg binary, odd platform). Say so rather than
		// claiming either outcome.
		fmt.Println("⚠ tunnel configured, but the handshake could not be verified")
		fmt.Printf("  %v\n", err)
		fmt.Println("  check it yourself with: 0trust status")
		return nil
	}
	if hs.IsZero() {
		fmt.Printf("✗ no handshake after %s — the tunnel is NOT carrying traffic\n",
			handshakeTimeout)
		fmt.Println()
		fmt.Println("  The interface is up and still holds the default route, so")
		fmt.Println("  traffic is being dropped rather than leaking in the clear.")
		fmt.Println("  That is deliberate. To get back online either fix this or")
		fmt.Println("  run: sudo 0trust disconnect")
		fmt.Println()
		fmt.Println("  Most likely causes, in order:")
		fmt.Println("    - UDP is blocked on this network (hotel/corporate wifi).")
		fmt.Println("      Try a different region, or multi-hop, which uses a")
		fmt.Println("      different port: sudo 0trust connect zur --exit rey")
		fmt.Println("    - the node is down — check https://0trustvpn.com/status")
		fmt.Println("    - the subscription lapsed: 0trust status")
		return fmt.Errorf("tunnel up but no handshake")
	}
	fmt.Printf("✓ tunnel up — handshake %s ago\n",
		time.Since(hs).Round(time.Second))
	return nil
}

func cmdRotate() error {
	if err := requireRoot(); err != nil {
		return err
	}
	st, err := config.Load()
	if err != nil {
		return err
	}
	if st.Token == "" {
		return fmt.Errorf("not logged in")
	}
	if st.PublicKey == "" {
		return fmt.Errorf("no device registered — run: 0trust connect")
	}
	if st.ExitRegion == "" {
		fmt.Println("⊘ single-hop session has no hop-pair to rotate (skipping)")
		return nil
	}

	fmt.Printf("→ rotating hop-pair (%s → %s)\n", st.EntryRegion, st.ExitRegion)

	c := api.New(st.APIBase, st.Token)
	resp, err := c.Rotate(api.RotateReq{
		Pubkey:     st.PublicKey,
		Region:     st.EntryRegion,
		ExitRegion: st.ExitRegion,
	})
	if err != nil {
		return fmt.Errorf("rotate failed: %w", err)
	}

	st.ExpiresAt = resp.ExpiresAt
	if err := st.Save(); err != nil {
		return err
	}

	cfg := wg.BuildConfigDual(st.PrivateKey, resp.InterfaceIP, resp.InterfaceIP6, resp.DNS, resp.Peers,
		wg.OptionsFor(st.KillSwitch)...)

	// If the tunnel is up, hot-swap peers in-place. If it's down, just
	// write the new config — next `connect` picks it up.
	if wg.IsUp() {
		if err := wg.SyncConfig(cfg); err != nil {
			return fmt.Errorf("hot-swap failed: %w", err)
		}
		fmt.Println("✓ rotated in place (no tunnel disruption)")
	} else {
		if _, err := wg.WriteConfig(cfg); err != nil {
			return err
		}
		fmt.Println("✓ new config written (tunnel was down)")
	}

	if resp.Multihop {
		fmt.Printf("  new pair:  entry=%s  exit=%s\n", resp.EntryNode, resp.ExitNode)
		if len(resp.Peers) > 0 {
			fmt.Printf("  endpoint:  %s\n", resp.Peers[0].Endpoint)
		}
		fmt.Printf("  expires:   %s\n",
			time.Unix(resp.ExpiresAt, 0).Format("2006-01-02 15:04 MST"))
	}
	return nil
}

func cmdExport(args []string) error {
	opts := export.Options{
		Region: "zur", Name: "0trust-mobile",
		WriteConf: true, WritePNG: true,
	}
	// Parse flags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--exit":
			if i+1 < len(args) {
				opts.ExitRegion = args[i+1]
				i++
			}
		case "--region":
			if i+1 < len(args) {
				opts.Region = args[i+1]
				i++
			}
		case "--name":
			if i+1 < len(args) {
				opts.Name = args[i+1]
				i++
			}
		case "--out":
			if i+1 < len(args) {
				opts.OutDir = args[i+1]
				i++
			}
		case "--no-files":
			opts.WriteConf = false
			opts.WritePNG = false
		}
	}

	fmt.Println("→ creating a new mobile device entry on your account")
	res, err := export.Build(opts)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println(res.QRASCII)
	fmt.Println("Scan this with the official WireGuard app (Add → From QR code).")
	fmt.Println()
	if res.Multihop {
		fmt.Printf("  mode:   multi-hop  %s → %s\n", res.EntryNode, res.ExitNode)
	}
	if res.ConfigPath != "" {
		fmt.Printf("  conf:   %s\n", res.ConfigPath)
	}
	if res.PNGPath != "" {
		fmt.Printf("  png:    %s\n", res.PNGPath)
	}
	fmt.Println()
	fmt.Println("⚠ The .conf file and QR code contain a private key.")
	fmt.Println("  Treat them like a password — share them only with the device you're provisioning.")
	return nil
}

// cmdDevices lists what's registered. The account is capped at 8 devices, so
// there has to be a way to see which slots are taken before freeing one.
func cmdDevices() error {
	st, err := config.Load()
	if err != nil {
		return err
	}
	if st.Token == "" {
		return fmt.Errorf("not logged in — run: 0trust login")
	}
	devices, err := api.New(st.APIBase, st.Token).Devices()
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		fmt.Println("no devices registered")
		return nil
	}
	fmt.Printf("%d of 8 device slots used\n\n", len(devices))
	for _, d := range devices {
		marker := "  "
		if d.Pubkey == st.PublicKey {
			marker = "* " // the device you're running on
		}
		route := "single-hop"
		if d.Multihop {
			route = fmt.Sprintf("multi-hop %s → %s", d.EntryNode, d.ExitNode)
		}
		fmt.Printf("%s%-20s %-16s %s\n", marker, truncate(d.DeviceName, 20), d.MeshIP, route)
		fmt.Printf("    %s\n", d.Pubkey)
		if d.LastSeen > 0 {
			fmt.Printf("    last seen %s\n", time.Unix(d.LastSeen, 0).Format("2006-01-02 15:04"))
		}
	}
	fmt.Println("\n* = this device")
	return nil
}

func cmdRemoveDevice(args []string) error {
	st, err := config.Load()
	if err != nil {
		return err
	}
	if st.Token == "" {
		return fmt.Errorf("not logged in — run: 0trust login")
	}
	if len(args) < 1 {
		return fmt.Errorf("usage: 0trust remove <pubkey|this>  (see: 0trust devices)")
	}
	target := args[0]
	if target == "this" {
		if st.PublicKey == "" {
			return fmt.Errorf("this device isn't registered yet")
		}
		target = st.PublicKey
	}
	if err := api.New(st.APIBase, st.Token).DeleteDevice(target); err != nil {
		return err
	}
	fmt.Printf("✓ removed %s\n", target)
	if target == st.PublicKey {
		// The key is gone server-side; drop it locally so the next connect
		// registers cleanly instead of re-presenting a key that no longer
		// resolves to a device.
		st.PrivateKey, st.PublicKey, st.InterfaceIP = "", "", ""
		if err := st.Save(); err != nil {
			return err
		}
		fmt.Println("  local key cleared — next connect will register a new device")
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func cmdDisconnect() error {
	if err := requireRoot(); err != nil {
		return err
	}
	if !wg.IsUp() {
		fmt.Println("⊘ not connected")
		return nil
	}
	if err := wg.Down(); err != nil {
		return err
	}
	fmt.Println("✓ tunnel down")
	return nil
}

func cmdRegions() error {
	// Static list for now; in v0.2 this could come from the API
	regions := []struct{ code, name string }{
		{"zur", "Zurich, CH"},
		{"rey", "Reykjavik, IS"},
		{"buc", "Bucharest, RO"},
	}
	for _, r := range regions {
		fmt.Printf("  %-5s  %s\n", r.code, r.name)
	}
	return nil
}

// ---------------------------------------------------------------------------

func requireRoot() error {
	if runtime.GOOS == "windows" {
		return nil // separate UAC check on Windows
	}
	if syscall.Geteuid() != 0 {
		return fmt.Errorf("this command needs root — try: sudo 0trust %s", strings.Join(os.Args[1:], " "))
	}
	return nil
}

func validToken(t string) bool {
	if len(t) != 19 {
		return false
	}
	for i, ch := range t {
		if i == 4 || i == 9 || i == 14 {
			if ch != '-' {
				return false
			}
			continue
		}
		if !strings.ContainsRune("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", ch) {
			return false
		}
	}
	return true
}

func maskToken(t string) string {
	if len(t) < 9 {
		return t
	}
	return t[:4] + "-****-****-" + t[len(t)-4:]
}

// plural renders a count with its unit, so a customer on their last day reads
// "1 day" rather than "1 days".
func plural(n int, unit string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, unit)
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

func tunnelState() string {
	if wg.IsUp() {
		return "up"
	}
	return "down"
}

func asAPIErr(err error, target **api.APIError) bool {
	for e := err; e != nil; {
		if apiErr, ok := e.(*api.APIError); ok {
			*target = apiErr
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := e.(unwrapper)
		if !ok {
			break
		}
		e = u.Unwrap()
	}
	return false
}
