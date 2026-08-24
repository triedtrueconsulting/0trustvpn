// Package gui hosts a local HTTP server that serves an embedded HTML UI
// and exposes JSON endpoints that wrap the same operations the CLI uses.
//
// The server binds to 127.0.0.1 on a fixed port (51827) so it's reachable
// only from the local machine. There's no auth on the loopback API — anyone
// who can reach localhost on this machine can already read state.json.
package gui

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/0trust/cli/internal/api"
	"github.com/0trust/cli/internal/config"
	"github.com/0trust/cli/internal/export"
	"github.com/0trust/cli/internal/wg"
)

//go:embed assets/index.html
var indexHTML []byte

//go:embed assets/app.css
var appCSS []byte

//go:embed assets/app.js
var appJS []byte

const ListenAddr = "127.0.0.1:51827"

// Serve starts the GUI server and (optionally) opens the browser. Blocks
// until the user kills the process or the server exits.
// alreadyServing reports whether the thing holding our port is another copy of
// this GUI rather than some unrelated process that happened to take it.
func alreadyServing() bool {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get("http://" + ListenAddr + "/api/state")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.Header.Get("X-0trust-Gui") != ""
}

func Serve(openBrowser bool) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/app.css", handleCSS)
	mux.HandleFunc("/app.js", handleJS)
	mux.HandleFunc("/api/state", handleState)
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/logout", handleLogout)
	mux.HandleFunc("/api/connect", handleConnect)
	mux.HandleFunc("/api/disconnect", handleDisconnect)
	mux.HandleFunc("/api/rotate", handleRotate)
	mux.HandleFunc("/api/regions", handleRegions)
	mux.HandleFunc("/api/export", handleExport)
	mux.HandleFunc("/api/devices", handleDevices)
	mux.HandleFunc("/api/devices/remove", handleRemoveDevice)
	mux.HandleFunc("/api/trial", handleTrial)
	mux.HandleFunc("/api/config", handleConfig)
	mux.HandleFunc("/api/killswitch", handleKillSwitch)

	srv := &http.Server{
		Addr:         ListenAddr,
		Handler:      withSameOrigin(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	url := "http://" + ListenAddr

	// Bind explicitly so we know whether the port is ours.
	lis, err := net.Listen("tcp", ListenAddr)
	if err != nil {
		// Almost always a second launch: the Start Menu shortcut, the Windows
		// autostart entry and the desktop icon all run `0trust gui`, and a
		// user who clicks one twice should get the window, not an error about
		// a socket. Hand them the running instance and exit cleanly.
		if alreadyServing() {
			fmt.Printf("0trust GUI already running: %s\n", url)
			if openBrowser {
				openInBrowser(url)
			}
			return nil
		}
		return fmt.Errorf("listen %s: %w", ListenAddr, err)
	}
	fmt.Printf("0trust GUI: %s\n", url)
	fmt.Println("Press Ctrl-C to stop")

	if openBrowser {
		go openInBrowser(url)
	}

	// Graceful shutdown on SIGINT/SIGTERM
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// withSameOrigin rejects requests that don't come from a same-origin browser
// page. Prevents DNS rebinding / external pages from triggering our endpoints.
func withSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Identifies this server to a second `0trust gui` that finds the port
		// taken, so it can tell "our GUI is already up" from "something else
		// owns 51827" instead of guessing.
		w.Header().Set("X-0trust-Gui", "1")
		// GET static assets: allow any local source
		if r.Method == http.MethodGet && (r.URL.Path == "/" ||
			strings.HasPrefix(r.URL.Path, "/app.")) {
			next.ServeHTTP(w, r)
			return
		}
		// JSON endpoints: enforce Host header is localhost
		host := r.Host
		if !(strings.HasPrefix(host, "127.0.0.1") || strings.HasPrefix(host, "localhost")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// And reject Origin headers from other origins (DNS rebinding defense)
		if origin := r.Header.Get("Origin"); origin != "" {
			if !strings.HasPrefix(origin, "http://127.0.0.1:") &&
				!strings.HasPrefix(origin, "http://localhost:") {
				http.Error(w, "cross-origin denied", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- Static handlers ---

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(indexHTML)
}

func handleCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(appCSS)
}

func handleJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write(appJS)
}

// --- JSON helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// --- /api/state — unified poll endpoint ---

type StateView struct {
	LoggedIn      bool   `json:"logged_in"`
	Token         string `json:"token,omitempty"` // masked
	APIBase       string `json:"api_base"`
	Status        string `json:"status,omitempty"` // active / expired / pending_payment
	ExpiresAt     int64  `json:"expires_at,omitempty"`
	DaysRemaining int    `json:"days_remaining,omitempty"`
	// No omitempty on the counts: zero devices is a real, displayable answer,
	// and omitting it made a brand-new account render "—" as though the load
	// had failed.
	DeviceCount  int    `json:"device_count"`
	Plan         string `json:"plan,omitempty"` // trial | paid
	MaxDevices   int    `json:"max_devices"`
	TunnelUp     bool   `json:"tunnel_up"`
	Multihop     bool   `json:"multihop"`
	EntryRegion  string `json:"entry_region,omitempty"`
	ExitRegion   string `json:"exit_region,omitempty"`
	HopExpiresAt int64  `json:"hop_expires_at,omitempty"`
	// No omitempty: the page renders a switch from this, and a missing field
	// would draw it "off" whatever the real setting is.
	KillSwitch          bool `json:"kill_switch"`
	KillSwitchSupported bool `json:"kill_switch_supported"`
}

// The browser polls /api/state every 3s to keep the tunnel indicator live.
// Tunnel state is local and cheap, but the subscription status is a remote
// call — and at 20 requests a minute it burns rate limit for a value that
// changes about once a month. Cache it and let the fast poll read local state.
var (
	statusMu     sync.Mutex
	statusCache  *api.Status
	statusCached time.Time
)

const statusCacheTTL = 60 * time.Second

// cachedStatus returns the account status, refreshing at most once per TTL.
// force bypasses the cache after an action that changes it (login, connect).
func cachedStatus(c *api.Client, force bool) *api.Status {
	statusMu.Lock()
	defer statusMu.Unlock()
	if !force && statusCache != nil && time.Since(statusCached) < statusCacheTTL {
		return statusCache
	}
	s, err := c.Status()
	if err != nil {
		// Keep serving the last good value if the API is briefly unreachable;
		// a network blip shouldn't blank the subscription panel.
		return statusCache
	}
	statusCache, statusCached = s, time.Now()
	return s
}

// invalidateStatus drops the cache so the next poll re-reads from the API.
func invalidateStatus() {
	statusMu.Lock()
	statusCache, statusCached = nil, time.Time{}
	statusMu.Unlock()
}

func handleState(w http.ResponseWriter, r *http.Request) {
	st, err := config.Load()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	view := StateView{
		LoggedIn:     st.Token != "",
		APIBase:      st.APIBase,
		TunnelUp:     wg.IsUp(),
		Multihop:     st.ExitRegion != "",
		EntryRegion:  st.EntryRegion,
		ExitRegion:   st.ExitRegion,
		HopExpiresAt: st.ExpiresAt,

		KillSwitch:          st.KillSwitch,
		KillSwitchSupported: wg.KillSwitchSupported(),
	}
	if st.Token != "" {
		view.Token = maskToken(st.Token)
		// Best-effort status fetch; don't fail the whole call if API is down
		c := api.New(st.APIBase, st.Token)
		if s := cachedStatus(c, r.URL.Query().Get("refresh") == "1"); s != nil {
			view.Status = s.Status
			view.ExpiresAt = s.ExpiresAt
			view.DaysRemaining = s.DaysRemaining
			view.DeviceCount = s.DeviceCount
			view.Plan = s.Plan
			view.MaxDevices = s.MaxDevices
		}
	}
	writeJSON(w, 200, view)
}

// --- /api/login ---

type loginReq struct {
	Token string `json:"token"`
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	invalidateStatus()
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST only")
		return
	}
	var body loginReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	token := strings.ToUpper(strings.TrimSpace(body.Token))
	if !validToken(token) {
		writeErr(w, 400, "token must be XXXX-XXXX-XXXX-XXXX")
		return
	}

	st, _ := config.Load()
	st.Token = token
	c := api.New(st.APIBase, token)
	if _, err := c.Status(); err != nil {
		writeErr(w, 401, "token rejected by server")
		return
	}
	if err := st.Save(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// --- /api/logout ---

func handleLogout(w http.ResponseWriter, r *http.Request) {
	invalidateStatus()
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST only")
		return
	}
	if wg.IsUp() {
		_ = wg.Down()
	}
	if err := config.Clear(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// --- /api/connect ---

type connectReq struct {
	Region     string `json:"region"`
	ExitRegion string `json:"exit_region"`
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	invalidateStatus()
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST only")
		return
	}
	if err := checkRoot(); err != nil {
		writeErr(w, 403, err.Error())
		return
	}
	var body connectReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if body.Region == "" {
		body.Region = "zur"
	}

	st, err := config.Load()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if st.Token == "" {
		writeErr(w, 401, "not logged in")
		return
	}

	// Generate keypair on first connect
	if st.PrivateKey == "" {
		priv, pub, err := wg.GenKeypair()
		if err != nil {
			writeErr(w, 500, "keygen: "+err.Error())
			return
		}
		st.PrivateKey, st.PublicKey = priv, pub
		if st.DeviceName == "" {
			host, _ := os.Hostname()
			st.DeviceName = host
		}
		if err := st.Save(); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}

	c := api.New(st.APIBase, st.Token)
	resp, err := c.Register(api.RegisterReq{
		Pubkey: st.PublicKey, DeviceName: st.DeviceName,
		Region: body.Region, ExitRegion: body.ExitRegion,
	})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}

	st.InterfaceIP = resp.InterfaceIP
	st.EntryRegion = body.Region
	st.ExitRegion = body.ExitRegion
	st.ExpiresAt = resp.ExpiresAt
	if err := st.Save(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}

	cfg := wg.BuildConfigDual(st.PrivateKey, resp.InterfaceIP, resp.InterfaceIP6, resp.DNS, resp.Peers,
		wg.OptionsFor(st.KillSwitch)...)
	if _, err := wg.WriteConfig(cfg); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if err := wg.Up(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}

	endpoint := ""
	if len(resp.Peers) > 0 {
		endpoint = resp.Peers[0].Endpoint
	}
	writeJSON(w, 200, map[string]any{
		"ok":         true,
		"multihop":   resp.Multihop,
		"entry_node": resp.EntryNode,
		"exit_node":  resp.ExitNode,
		"endpoint":   endpoint,
	})
}

// --- /api/disconnect ---

func handleDisconnect(w http.ResponseWriter, r *http.Request) {
	invalidateStatus()
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST only")
		return
	}
	if err := checkRoot(); err != nil {
		writeErr(w, 403, err.Error())
		return
	}
	if err := wg.Down(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// --- /api/rotate ---

func handleRotate(w http.ResponseWriter, r *http.Request) {
	invalidateStatus()
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST only")
		return
	}
	if err := checkRoot(); err != nil {
		writeErr(w, 403, err.Error())
		return
	}
	st, err := config.Load()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if st.ExitRegion == "" {
		writeJSON(w, 200, map[string]any{"ok": true, "skipped": "single-hop"})
		return
	}

	c := api.New(st.APIBase, st.Token)
	resp, err := c.Rotate(api.RotateReq{
		Pubkey: st.PublicKey, Region: st.EntryRegion, ExitRegion: st.ExitRegion,
	})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	st.ExpiresAt = resp.ExpiresAt
	if err := st.Save(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}

	cfg := wg.BuildConfigDual(st.PrivateKey, resp.InterfaceIP, resp.InterfaceIP6, resp.DNS, resp.Peers,
		wg.OptionsFor(st.KillSwitch)...)
	if wg.IsUp() {
		if err := wg.SyncConfig(cfg); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	} else {
		_, _ = wg.WriteConfig(cfg)
	}

	writeJSON(w, 200, map[string]any{
		"ok":         true,
		"entry_node": resp.EntryNode,
		"exit_node":  resp.ExitNode,
		"expires_at": resp.ExpiresAt,
	})
}

// --- /api/export ---

type exportReq struct {
	Region     string `json:"region"`
	ExitRegion string `json:"exit_region"`
	Name       string `json:"name"`
}

func handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST only")
		return
	}
	var body exportReq
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json")
		return
	}
	if body.Region == "" {
		body.Region = "zur"
	}
	if body.Name == "" {
		body.Name = "0trust-mobile"
	}

	res, err := export.Build(export.Options{
		Region: body.Region, ExitRegion: body.ExitRegion, Name: body.Name,
	})
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	dataURL, err := export.QRDataURL(res.Config)
	if err != nil {
		writeErr(w, 500, "qr: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"qr_data_url": dataURL,
		"config":      res.Config,
		"multihop":    res.Multihop,
		"entry_node":  res.EntryNode,
		"exit_node":   res.ExitNode,
	})
}

// --- /api/regions ---

// --- /api/devices — list what's registered on the account ---

func handleDevices(w http.ResponseWriter, r *http.Request) {
	st, err := config.Load()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if st.Token == "" {
		writeErr(w, 401, "not signed in")
		return
	}
	devices, err := api.New(st.APIBase, st.Token).Devices()
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	// Flag the device this GUI is running on so the user can tell which row
	// is the machine in front of them before they remove the wrong one.
	type row struct {
		api.Device
		This bool `json:"this"`
	}
	out := make([]row, 0, len(devices))
	for _, d := range devices {
		out = append(out, row{Device: d, This: d.Pubkey != "" && d.Pubkey == st.PublicKey})
	}
	writeJSON(w, 200, out)
}

// --- /api/devices/remove ---

type removeReq struct {
	Pubkey string `json:"pubkey"`
}

func handleRemoveDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST only")
		return
	}
	var req removeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Pubkey == "" {
		writeErr(w, 400, "pubkey required")
		return
	}
	st, err := config.Load()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if st.Token == "" {
		writeErr(w, 401, "not signed in")
		return
	}
	if err := api.New(st.APIBase, st.Token).DeleteDevice(req.Pubkey); err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	invalidateStatus()

	// Removing the device we are running on orphans the local key: the server
	// no longer resolves it, so keeping it would make the next connect look
	// like a stranger's key. Drop it and tear the tunnel down.
	if req.Pubkey == st.PublicKey {
		if wg.IsUp() {
			_ = wg.Down()
		}
		st.PrivateKey, st.PublicKey, st.InterfaceIP = "", "", ""
		st.EntryRegion, st.ExitRegion, st.ExpiresAt = "", "", 0
		if err := st.Save(); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "removed_self": true})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// --- /api/trial — claim a free trial without leaving the app ---
//
// The proof-of-work is ground here in Go rather than in the GUI's JavaScript.
// It is the same computation either way, but a native loop finishes in a
// fraction of the time and does not block the page while it runs.

type trialChallenge struct {
	Nonce     string `json:"nonce"`
	Bits      int    `json:"bits"`
	ExpiresAt int64  `json:"expires_at"`
	Signature string `json:"signature"`
}

type trialRedeem struct {
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"expires_at"`
	Signature string `json:"signature"`
	Solution  string `json:"solution"`
	Source    string `json:"source"`
}

type trialResult struct {
	Token      string `json:"token"`
	Plan       string `json:"plan"`
	ExpiresAt  int64  `json:"expires_at"`
	Days       int    `json:"days"`
	MaxDevices int    `json:"max_devices"`
}

// powSolve finds a suffix whose SHA-256 over "nonce:solution" starts with the
// requested number of zero bits. Mirrors _pow_ok in api/main.py.
func powSolve(nonce string, bits int, deadline time.Time) (string, error) {
	whole, rest := bits/8, bits%8
	for i := 0; ; i++ {
		if i%4096 == 0 && time.Now().After(deadline) {
			return "", fmt.Errorf("gave up solving the puzzle after %s",
				time.Until(deadline).Round(time.Second))
		}
		sol := strconv.Itoa(i)
		sum := sha256.Sum256([]byte(nonce + ":" + sol))
		ok := true
		for b := 0; b < whole; b++ {
			if sum[b] != 0 {
				ok = false
				break
			}
		}
		if ok && rest != 0 && sum[whole]>>(8-rest) != 0 {
			ok = false
		}
		if ok {
			return sol, nil
		}
	}
}

func handleTrial(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST only")
		return
	}
	st, err := config.Load()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if st.Token != "" {
		writeErr(w, 409, "already signed in — sign out first to claim a trial")
		return
	}

	base := strings.TrimRight(st.APIBase, "/")
	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Get(base + "/api/v1/trial/challenge")
	if err != nil {
		writeErr(w, 502, "could not reach the server: "+err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		writeErr(w, resp.StatusCode, "trials unavailable: "+string(body))
		return
	}
	var ch trialChallenge
	if err := json.NewDecoder(resp.Body).Decode(&ch); err != nil {
		writeErr(w, 502, "malformed challenge: "+err.Error())
		return
	}

	sol, err := powSolve(ch.Nonce, ch.Bits, time.Now().Add(60*time.Second))
	if err != nil {
		writeErr(w, 504, err.Error())
		return
	}

	payload, _ := json.Marshal(trialRedeem{
		Nonce: ch.Nonce, ExpiresAt: ch.ExpiresAt, Signature: ch.Signature,
		Solution: sol, Source: "gui",
	})
	resp2, err := client.Post(base+"/api/v1/trial", "application/json",
		bytes.NewReader(payload))
	if err != nil {
		writeErr(w, 502, "could not reach the server: "+err.Error())
		return
	}
	defer resp2.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp2.Body, 4096))
	if resp2.StatusCode != 200 {
		writeErr(w, resp2.StatusCode, string(body))
		return
	}
	var out trialResult
	if err := json.Unmarshal(body, &out); err != nil {
		writeErr(w, 502, "malformed trial response")
		return
	}

	// Sign in with the token we were just handed, so the user lands in the
	// app rather than being told to copy a string into a login box.
	st.Token = out.Token
	if err := st.Save(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	invalidateStatus()
	writeJSON(w, 200, out)
}

// handleKillSwitch flips the persisted kill-switch setting.
//
// It deliberately does NOT rewrite the live tunnel. The rules go in as
// wg-quick PostUp/PreDown, so they are applied when the interface comes up;
// changing them under a running tunnel would mean tearing it down and back
// up, and doing that silently to someone who just clicked a checkbox is how
// you drop their connection mid-download. The page says it applies on the
// next connect, and it means it.
func handleKillSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST only")
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeErr(w, 400, "malformed request")
		return
	}
	if body.Enabled && !wg.KillSwitchSupported() {
		writeErr(w, 400, "the kill switch is not available on this platform")
		return
	}
	st, err := config.Load()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	st.KillSwitch = body.Enabled
	if err := st.Save(); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok": true, "kill_switch": st.KillSwitch,
		"applies": "next connect",
	})
}

// handleConfig passes the control plane's public config through to the page.
//
// The trial length is an operator setting, so the GUI cannot hardcode it in
// its copy without eventually advertising an offer we no longer give. If the
// server is unreachable the page keeps whatever it was served with.
func handleConfig(w http.ResponseWriter, r *http.Request) {
	st, err := config.Load()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	base := strings.TrimRight(st.APIBase, "/")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(base + "/api/v1/config")
	if err != nil {
		writeErr(w, 502, "could not reach the server: "+err.Error())
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode != 200 {
		writeErr(w, resp.StatusCode, "config unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(body)
}

func handleRegions(w http.ResponseWriter, r *http.Request) {
	// Static for v0.1; eventually fed from the control plane.
	regions := []map[string]string{
		{"code": "zur", "name": "Zurich, CH"},
		{"code": "rey", "name": "Reykjavik, IS"},
		{"code": "buc", "name": "Bucharest, RO"},
	}
	writeJSON(w, 200, regions)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func checkRoot() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if syscall.Geteuid() != 0 {
		return errors.New("connect/disconnect/rotate need root — start the GUI with sudo")
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

func openInBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
