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

// The largest response this API produces is a device list — 8 devices of a
// few hundred bytes each. 1 MB is three orders of magnitude of headroom and
// still small enough to be harmless.
const maxResponseBytes = 1 << 20

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

	// Cap what we are willing to read. Every response this API sends is a
	// small JSON object — the largest is a device list, a few KB — but
	// io.ReadAll and json.Decoder will both consume whatever arrives, and
	// the 20s client timeout is a lot of bytes on a fast link. The endpoint
	// is not always ours in practice: ZTV_API_BASE points elsewhere in
	// testing, and a captive portal will happily answer with a page of its
	// own. Bounding it turns "the client ate all the memory on the laptop"
	// into an ordinary parse error.
	limited := io.LimitReader(resp.Body, maxResponseBytes)

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(limited)
		return &APIError{Status: resp.StatusCode, Body: string(b)}
	}

	if out == nil {
		return nil
	}
	return json.NewDecoder(limited).Decode(out)
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
	InterfaceIP string `json:"interface_ip"`
	// Set only when the exit node has working IPv6 egress. Empty means v6
	// stays blackholed by the ::/0 AllowedIPs below — which is the point:
	// the tunnel always claims v6 so it cannot leak around us, and only
	// carries it where there is somewhere for it to go.
	InterfaceIP6 string   `json:"interface_ip6"`
	DNS          []string `json:"dns"`
	Peers        []Peer   `json:"peers"`
	Multihop     bool     `json:"multihop"`
	EntryNode    string   `json:"entry_node"`
	ExitNode     string   `json:"exit_node"`
	ExpiresAt    int64    `json:"expires_at"`
	// SameHost is set when the control plane resolved entry and exit to the
	// same machine — a single-VPS test deployment. The route is real; the
	// privacy property multi-hop exists for is not, and the client says so
	// rather than printing the usual claim.
	SameHost bool `json:"same_host"`
	// MTU for this config. Differs between the direct and obfuscated
	// transports, so it is answered per response rather than assumed — see
	// the note on WG_MTU in the API. Zero means an older control plane said
	// nothing; leave the interface MTU to wg-quick in that case.
	MTU int `json:"mtu"`
	// Obfuscation is non-nil when the node this config points at runs the
	// relay. Its presence is a capability, not an instruction: whether to
	// use it is the customer's choice, made locally, with no round trip.
	Obfuscation *Obfuscation `json:"obfuscation"`
}

// Obfuscation describes a node's relay. Nil means that node does not run
// one — which is a normal state, not an error, and must not stop a client
// connecting directly.
type Obfuscation struct {
	Kind     string `json:"kind"`     // "shadowsocks"
	Method   string `json:"method"`   // "aes-256-gcm"
	Endpoint string `json:"endpoint"` // where the relay listens, host:port
	Key      string `json:"key"`      // base64, 32 bytes; shared per node
	Target   string `json:"target"`   // what the relay forwards to, on its loopback
	MTU      int    `json:"mtu"`      // interface MTU to use with this transport
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

// Notice is a message waiting for this account. There is no email address on
// file — that is the product — so this is the only channel the service has to
// reach a customer, and the only warning they get before a subscription ends.
type Notice struct {
	ID        int64  `json:"id"`
	Severity  string `json:"severity"`
	Subject   string `json:"subject"`
	Body      string `json:"body"`
	CreatedAt int64  `json:"created_at"`
}

func (c *Client) Notices() ([]Notice, error) {
	var n []Notice
	return n, c.do("GET", "/api/v1/notices", nil, &n)
}

// MarkNoticeRead stops a notice coming back on the next status check.
func (c *Client) MarkNoticeRead(id int64) error {
	return c.do("POST", fmt.Sprintf("/api/v1/notices/%d/read", id), nil, nil)
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

// TopupReq opens another invoice against the account this client holds.
type TopupReq struct {
	Months int `json:"months"`
	// Empty asks the control plane for its default coin. Naming one this
	// deployment cannot issue an address for is refused server-side rather
	// than sending the customer to an address that does not exist.
	Currency string `json:"currency,omitempty"`
}

// TopupResp is the same shape as signup, minus the token: a top-up never
// mints one, because the caller already holds theirs and the control plane
// does not store it in a form it could echo back.
type TopupResp struct {
	InvoiceID   string  `json:"invoice_id"`
	CheckoutURL string  `json:"checkout_url"`
	AmountUSD   float64 `json:"amount_usd"`
}

// PayMethod is one way to pay an invoice.
type PayMethod struct {
	Currency string `json:"currency"`
	Address  string `json:"address"`
	Amount   string `json:"amount"`
	// URI is the wallet-app link. Worth preferring over the bare address:
	// it carries the amount, and the amount is the half a customer gets
	// wrong when retyping.
	URI string `json:"uri"`
}

type PayMethods struct {
	Methods     []PayMethod `json:"methods"`
	CheckoutURL string      `json:"checkout_url"`
}

// PayStatus is the invoice's settlement state.
type PayStatus struct {
	Status        string `json:"status"`
	Confirmations int    `json:"confirmations"`
	Required      int    `json:"required"`
}

// Topup opens an invoice that extends this account.
func (c *Client) Topup(req TopupReq) (*TopupResp, error) {
	var out TopupResp
	if err := c.do("POST", "/api/v1/account/topup", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PaymentMethods lists how to pay an invoice. No auth: the invoice id is the
// only secret needed, which is why nothing may log the path it appears in.
func (c *Client) PaymentMethods(invoiceID string) (*PayMethods, error) {
	var out PayMethods
	if err := c.do("GET", "/api/v1/payment/"+invoiceID+"/methods", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PaymentStatus polls an invoice.
func (c *Client) PaymentStatus(invoiceID string) (*PayStatus, error) {
	var out PayStatus
	if err := c.do("GET", "/api/v1/payment/"+invoiceID+"/status", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
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
