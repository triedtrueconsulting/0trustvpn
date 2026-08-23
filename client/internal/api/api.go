// Package api is a thin HTTP client for the 0trust control plane.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		HTTP: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (c *Client) do(method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(buf)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.Token != "" {
		req.Header.Set("X-Account-Token", c.Token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return &APIError{Status: resp.StatusCode, Body: string(b)}
	}

	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// --- Types ---

type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("api %d: %s", e.Status, e.Body)
}

type Status struct {
	Status        string `json:"status"`
	ExpiresAt     int64  `json:"expires_at"`
	DaysRemaining int    `json:"days_remaining"`
	Plan          string `json:"plan"`
	MaxDevices    int    `json:"max_devices"`
	DeviceCount   int    `json:"device_count"`
}

type RegisterReq struct {
	Pubkey     string `json:"pubkey"`
	DeviceName string `json:"device_name"`
	Region     string `json:"region"`
	ExitRegion string `json:"exit_region,omitempty"`
}

type RotateReq struct {
	Pubkey     string `json:"pubkey"`
	Region     string `json:"region"`
	ExitRegion string `json:"exit_region,omitempty"`
}

type Peer struct {
	ID                  string   `json:"id"`
	PublicKey           string   `json:"public_key"`
	Endpoint            string   `json:"endpoint"`
	AllowedIPs          []string `json:"allowed_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
}

type RegisterResp struct {
	InterfaceIP string   `json:"interface_ip"`
	DNS         []string `json:"dns"`
	Peers       []Peer   `json:"peers"`
	Multihop    bool     `json:"multihop"`
	EntryNode   string   `json:"entry_node"`
	ExitNode    string   `json:"exit_node"`
	ExpiresAt   int64    `json:"expires_at"`
	// SameHost is set when the control plane resolved entry and exit to the
	// same machine — a single-VPS test deployment. The route is real; the
	// privacy property multi-hop exists for is not, and the client says so
	// rather than printing the usual claim.
	SameHost bool `json:"same_host"`
}

// --- Calls ---

func (c *Client) Status() (*Status, error) {
	var s Status
	return &s, c.do("GET", "/api/v1/account/status", nil, &s)
}

func (c *Client) Register(req RegisterReq) (*RegisterResp, error) {
	var r RegisterResp
	return &r, c.do("POST", "/api/v1/wg/register", req, &r)
}

func (c *Client) Rotate(req RotateReq) (*RegisterResp, error) {
	var r RegisterResp
	return &r, c.do("POST", "/api/v1/wg/rotate", req, &r)
}

// Device is one registered device on the account.
type Device struct {
	Pubkey     string `json:"pubkey"`
	DeviceName string `json:"device_name"`
	MeshIP     string `json:"mesh_ip"`
	CreatedAt  int64  `json:"created_at"`
	LastSeen   int64  `json:"last_seen"`
	Multihop   bool   `json:"multihop"`
	EntryNode  string `json:"entry_node"`
	ExitNode   string `json:"exit_node"`
}

func (c *Client) Devices() ([]Device, error) {
	var d []Device
	return d, c.do("GET", "/api/v1/devices", nil, &d)
}

// DeleteDevice deregisters a device by its WireGuard public key, freeing the
// account slot and releasing the mesh IP.
func (c *Client) DeleteDevice(pubkey string) error {
	// Public keys are standard base64 and routinely contain '/' and '+', so
	// the key has to be escaped rather than pasted into the path.
	return c.do("DELETE", "/api/v1/devices/"+url.PathEscape(pubkey), nil, nil)
}
