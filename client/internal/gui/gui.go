// Package gui hosts a local HTTP server that serves an embedded HTML UI
// and exposes JSON endpoints that wrap the same operations the CLI uses.
//
// The server binds to 127.0.0.1 on a fixed port (51827) so it's reachable
// only from the local machine. There's no auth on the loopback API — anyone
// who can reach localhost on this machine can already read state.json.
package gui

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
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

	srv := &http.Server{
		Addr:         ListenAddr,
		Handler:      withSameOrigin(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Bind explicitly so we can fail fast if the port is taken
	lis, err := net.Listen("tcp", ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", ListenAddr, err)
	}
	url := "http://" + ListenAddr
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
	Token         string `json:"token,omitempty"`         // masked
	APIBase       string `json:"api_base"`
	Status        string `json:"status,omitempty"`        // active / expired / pending_payment
	ExpiresAt     int64  `json:"expires_at,omitempty"`
	DaysRemaining int    `json:"days_remaining,omitempty"`
	DeviceCount   int    `json:"device_count,omitempty"`
	TunnelUp      bool   `json:"tunnel_up"`
	Multihop      bool   `json:"multihop"`
	EntryRegion   string `json:"entry_region,omitempty"`
	ExitRegion    string `json:"exit_region,omitempty"`
	HopExpiresAt  int64  `json:"hop_expires_at,omitempty"`
}

func handleState(w http.ResponseWriter, r *http.Request) {
	st, err := config.Load()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	view := StateView{
		LoggedIn:    st.Token != "",
		APIBase:     st.APIBase,
		TunnelUp:    wg.IsUp(),
		Multihop:    st.ExitRegion != "",
		EntryRegion: st.EntryRegion,
		ExitRegion:  st.ExitRegion,
		HopExpiresAt: st.ExpiresAt,
	}
	if st.Token != "" {
		view.Token = maskToken(st.Token)
		// Best-effort status fetch; don't fail the whole call if API is down
		c := api.New(st.APIBase, st.Token)
		if s, err := c.Status(); err == nil {
			view.Status = s.Status
			view.ExpiresAt = s.ExpiresAt
			view.DaysRemaining = s.DaysRemaining
			view.DeviceCount = s.DeviceCount
		}
	}
	writeJSON(w, 200, view)
}

// --- /api/login ---

type loginReq struct {
	Token string `json:"token"`
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
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

	cfg := wg.BuildConfig(st.PrivateKey, resp.InterfaceIP, resp.DNS, resp.Peers)
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

	cfg := wg.BuildConfig(st.PrivateKey, resp.InterfaceIP, resp.DNS, resp.Peers)
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
