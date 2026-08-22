# 0trust VPN

Anonymous WireGuard mesh VPN service. No email. No name. No password. Pay in
crypto, get a 16-character token, route traffic through a mesh that doesn't
know you.

```
                              ┌─────────────────────┐
                              │   BTCPay Server     │
                              │  (separate host)    │
                              └──────────┬──────────┘
                                         │ webhook
                                         ▼
        ┌──────────┐   nginx 443    ┌─────────────────┐
USER ──▶│ 0trust.  │ ───────────▶   │  Control Plane  │
        │  vpn     │                │  ─────────────  │
        └──────────┘                │  - FastAPI      │
                                    │  - SQLite       │
                                    │  - Hop scheduler│
                                    └────────┬────────┘
                                             │ /wg/peers   (exits)
                                             │ /wg/forwards (entries)
                              ┌──────────────┼──────────────┐
                              ▼              ▼              ▼
                       ┌────────────┐ ┌────────────┐ ┌────────────┐
                       │ ENTRY      │ │ ENTRY      │ │ EXIT       │
                       │ zur-04     │ │ rey-12     │ │ buc-02     │
                       │ nftables   │ │ nftables   │ │ wireguard  │
                       │ DNAT only  │ │ DNAT only  │ │ + NAT      │
                       │ (no crypto)│ │ (no crypto)│ │ jurisdic-  │
                       │            │ │            │ │ tion: RO   │
                       └─────┬──────┘ └─────┬──────┘ └──────┬─────┘
                             │              │               │
                             │ UDP forward  │               │ NAT to
                             └──────────────┴──────────────►│ internet
                                                            ▼
                                                      ┌──────────┐
                                       wg handshake   │ public   │
                                       (e2e to exit)  │ internet │
                                                      └──────────┘
                              ▲
                              │ wg packets, encrypted to exit's pubkey
                              │
                        ┌─────┴─────┐
                        │  Customer │
                        │  device   │
                        └───────────┘
```

## Repository layout

```
0trust-vpn/
├── web/                      Static landing site (nginx serves it)
│   └── index.html            Calls /api/v1/account on signup
├── api/                      FastAPI control plane
│   ├── main.py               Routes, schemas, DB
│   ├── btcpay.py             BTCPay Server client
│   ├── sweep.py              Hourly expiry sweeper
│   └── requirements.txt
├── client/                   Go CLI + embedded GUI (cross-platform)
│   ├── cmd/0trust/main.go    Entry point: login/connect/status/rotate/gui
│   ├── internal/api/         HTTP client for control plane
│   ├── internal/config/      Local credential storage
│   ├── internal/wg/          wg(8) / wg-quick(8) wrapper
│   ├── internal/gui/         Embedded HTTP server + HTML UI for 0trust gui
│   ├── systemd/              0trust-rotate.{service,timer} for clients
│   ├── go.mod
│   └── Makefile              Cross-compile to 5 platforms
├── nginx/                    Reverse proxy + TLS + rate limits
│   ├── 0trustvpn.com.conf
│   └── 0trust-proxy.conf
├── wireguard/                Mesh node syncer + cloud-init for ephemerals
│   ├── 0trust-meshd.py
│   └── cloud-init-ephemeral.yaml   RAM-only node provisioning
├── systemd/                  Service units + env templates
│   ├── 0trust-api.service
│   ├── 0trust-sweep.{service,timer}
│   ├── 0trust-meshd.service
│   └── api.env.example
├── mobile/
│   └── android/              Production Android app
│       ├── app/src/main/     Kotlin + Compose UI, VpnService, encrypted prefs
│       ├── build.gradle.kts  AGP 8.5, Compose BOM, wireguard-android dep
│       └── README.md         Build, sign, F-Droid/Play submission
├── installer/
│   ├── windows/              WiX MSI installer (Start Menu, PATH, auto-start)
│   └── linux/                .deb (Debian/Ubuntu) + AppImage (universal)
├── btcpay/                   BTCPay Server deployment + integration
│   ├── scripts/              bootstrap, configure, test, backup (full + lite)
│   ├── docker/               Compose override for remote XMR
│   └── runbook.md            Operations playbook
├── mobile/
│   ├── android/              Complete Kotlin/Compose app (wireguard-android)
│   └── ios/                  Skeleton — out of scope for v0.1 (QR-export path)
├── support/                  PGP-based support workflow
│   ├── scripts/generate-key.sh    Generate support PGP key + WKD layout
│   └── templates/auto-reply.txt   Auto-responder text
├── tor/                      Tor onion service mirror
│   └── scripts/bootstrap.sh       Stand up tor + .onion + nginx integration
├── canary/                   Warrant canary system
│   ├── templates/canary.txt
│   ├── scripts/              generate.sh (signing), check.sh (staleness)
│   └── systemd/              Daily staleness check timer
├── web/
│   ├── index.html            Landing page (Apps showcase, jurisdictions)
│   ├── status.html           Public status page (renders /api/v1/status/public)
│   ├── download.html         Binary downloads + PGP verification
│   ├── help.html             FAQ
│   ├── audit.html            Customer-friendly audit summary
│   ├── privacy.html          Privacy policy (binding version of audit claims)
│   ├── terms.html            Terms of service + acceptable use + refunds
│   ├── security-policy.html  Vulnerability disclosure policy
│   └── vendor/               Self-hosted third-party JS (pinned, SRI-checked)
├── scripts/
│   ├── install.sh            One-shot VPS installer (test / production modes)
│   ├── bootstrap.sh          Forwarder to install.sh, kept for old runbooks
│   ├── bootstrap-node.sh     Set up a WireGuard mesh node (+ abuse egress filter)
│   ├── audit-verify.sh       Run the full no-logs verification matrix
│   ├── backup.sh             Encrypted nightly DB backup + rotation
│   ├── vendor-third-party.sh Fetch + verify pinned vendor JS
│   ├── release.sh            Sign + bundle a release
│   └── verify-release.sh     End-user release verifier
└── docs/
    ├── README.md             (this file)
    ├── LAUNCH.md             Concrete operator launch playbook
    ├── AUDIT.md              No-logs audit pack for third-party auditors
    ├── ABUSE.md              DMCA / spam / law-enforcement handling runbook
    └── DR.md                 Disaster recovery procedures (6 scenarios)
```

## Components

### 1. Static site (`web/`)

Single-file HTML/CSS/JS landing page. Lives at `/var/www/0trust` and is served
directly by nginx. The signup flow generates a UUID-derived token via
`crypto.getRandomValues` for the demo; in production the token MUST come from
`POST /api/v1/account` so it's persisted server-side.

### 2. Control plane API (`api/main.py`)

FastAPI app on `127.0.0.1:8080`. Endpoints:

| Method | Path                              | Auth            | Purpose                              |
|--------|-----------------------------------|-----------------|--------------------------------------|
| POST   | `/api/v1/account`                 | none            | Mint token + open invoice            |
| GET    | `/api/v1/account/status`          | X-Account-Token | Subscription status                  |
| POST   | `/api/v1/account/topup`           | X-Account-Token | New invoice on existing account      |
| GET    | `/api/v1/payment/{id}/methods`    | none            | Per-currency addresses + amounts     |
| GET    | `/api/v1/payment/{id}/status`     | none            | Poll for settlement                  |
| POST   | `/api/v1/payment/webhook`         | BTCPay HMAC     | Settlement notifications             |
| GET    | `/api/v1/regions`                 | none            | Regions with at least one active node |
| GET    | `/api/v1/trial/challenge`         | none            | Proof-of-work challenge for a free trial |
| POST   | `/api/v1/trial`                   | solved stamp    | Redeem it for a 1-month trial account |
| GET    | `/api/v1/devices`                 | X-Account-Token | List devices on the account          |
| DELETE | `/api/v1/devices/{pubkey}`        | X-Account-Token | Deregister a device, free its slot   |
| POST   | `/api/v1/wg/register`             | X-Account-Token | Register device, get peers (single- or multi-hop) |
| POST   | `/api/v1/wg/rotate`               | X-Account-Token | Atomically swap to a fresh entry/exit pair        |
| GET    | `/api/v1/wg/peers?node_id=…`      | X-Node-Psk      | Peer manifest, scoped to that node   |
| GET    | `/api/v1/wg/forwards?node_id=…`   | X-Node-Psk      | Entry-node DNAT rules                |
| POST   | `/api/v1/node/provision`          | X-Provision-Token (one-shot) | Ephemeral node self-registration  |
| POST   | `/api/v1/node/heartbeat`          | X-Node-Psk      | Liveness ping (ephemeral nodes)      |
| GET    | `/api/v1/status/public`           | none            | Sanitized health for /status page (60s cache) |
| GET    | `/api/v1/health`                  | none            | Liveness probe                       |

**Token model.** A 16-char Crockford-base32 string in 4-char groups
(e.g. `7K2M-9X4P-AQ8R-J3WN`) ≈ 80 bits of entropy. Stored only as SHA-256
hash. There is no recovery flow — by design.

**Database.** SQLite (WAL mode) at `/var/lib/0trust/0trust.db`. Migrate to
Postgres when you have >10k active accounts.

### 3. Crypto payments

We don't roll our own. **BTCPay Server** on a separate host handles:

- **Bitcoin** (watching-only via xpub — private keys never on the BTCPay box)
- **Monero** (hot wallet — operator sweeps weekly to cold storage)

Two idempotency rules hold the money and device paths together:

- **`wg/register` is idempotent on the pubkey.** Clients persist their keypair,
  so every reconnect presents the same key. That returns the device's existing
  config and keeps its mesh IP rather than creating a second device.
- **Each invoice is credited once.** BTCPay retries deliveries it didn't get a
  2xx for, and the HMAC on a captured delivery stays valid indefinitely, so
  settlement is guarded on `invoices.status` rather than on the signature.

Devices are capped at 8 per account. `GET /api/v1/devices` shows what's
registered and `DELETE /api/v1/devices/{pubkey}` releases a slot along with its
mesh IP and any hop pair — from the CLI, `0trust devices` and `0trust remove`.

BTCPay sends HMAC-signed webhooks to `/api/v1/payment/webhook`. On
`InvoiceSettled` we mark the account active and extend `expires_at` by the
purchased duration.

Full deployment is automated in `btcpay/`. There are two modes — pick
based on your hardware budget:

**Lite** (~15GB disk, ~$5-10/mo VPS, 2-3 hours to ready):
```bash
sudo BTCPAY_HOST=pay.0trustvpn.com \
     LETSENCRYPT_EMAIL=0trustvpn@proton.me \
     ./btcpay/scripts/bootstrap-lite.sh
```
Pruned Bitcoin + remote Monero daemon. Trades some XMR query privacy
for not running a 100GB blockchain.

**Full** (~200GB disk, ~$30-50/mo VPS, 1-3 days to ready):
```bash
sudo BTCPAY_HOST=pay.0trustvpn.com \
     LETSENCRYPT_EMAIL=0trustvpn@proton.me \
     ENABLE_MONERO=1 \
     ./btcpay/scripts/bootstrap.sh
```
Full BTC and XMR nodes locally. Maximum self-sovereignty, no third
parties in the payment path.

Then for either mode:
```bash
# 2. Configure the store + wallets + webhook + API key
sudo BTCPAY_HOST=pay.0trustvpn.com \
     BTCPAY_ADMIN_EMAIL=0trustvpn@proton.me \
     BTCPAY_ADMIN_PASSWORD='...' \
     BTC_XPUB='zpub6j...' \
     CONTROL_HOST=0trustvpn.com \
     ./btcpay/scripts/configure.sh

# 3. End-to-end smoke test
sudo ./btcpay/scripts/test-integration.sh
```

`bootstrap.sh` wraps BTCPay's official Docker installer with the right
fragments (Bitcoin fastsync + pruning, Monero plugin); `configure.sh` uses
BTCPay's Greenfield API to create the store, set the BTC payment method
to your xpub (so BTCPay only watches, never spends), enable Monero, register
our webhook, and mint a least-privilege API key.

See `btcpay/runbook.md` for full operations docs — wallet management,
backups, disaster recovery, debugging webhook delivery.

### 4. WireGuard mesh nodes

The production deployment is **three nodes**, in three jurisdictions, all
outside the Five/Nine/Fourteen Eyes intelligence-sharing alliances:

| Code | Location | Role |
|------|----------|------|
| `zur` | Zurich, Switzerland | both |
| `rey` | Reykjavik, Iceland | both |
| `buc` | Bucharest, Romania | both |

Each node has a **role**: `entry`, `exit`, or `both`.

**Exit nodes** terminate client WireGuard tunnels, decrypt traffic, and NAT
it out to the internet. They run a full WireGuard listener and pull the
device peer list from `/api/v1/wg/peers`.

**Entry nodes** are glorified UDP proxies. They never decrypt anything.
They run nftables DNAT rules that forward specific UDP ports to specific
exit nodes. They pull these rules from `/api/v1/wg/forwards`.

`role=both` means each node serves either function depending on the
customer's chosen route. With three `both` nodes you get 3 single-hop
options + 6 multi-hop combinations (3 entries × 3 exits, minus the 3
self-pairs). The 24h auto-rotation cycles through these.

For real zero-trust separation later, deploy multiple boxes per region
with distinct `entry`-only and `exit`-only roles. The schema and routing
already support it; just bootstrap more nodes.

### Multi-hop (zero-trust path)

When a client passes `exit_region` to `/api/v1/wg/register`, the control
plane:

1. Picks an entry node in `region` and an exit node in `exit_region`
2. Allocates a unique UDP port (52000–59999) on the entry node
3. Stores the mapping in `hop_pairs`
4. Returns a peer config with `Endpoint=entry-ip:allocated-port` but
   `PublicKey=exit's-pubkey`

The next time the entry node polls `/api/v1/wg/forwards`, it sees the new
mapping and adds an nftables DNAT rule. The next time the exit node polls
`/api/v1/wg/peers`, it sees the client's pubkey and adds it as a WG peer.

Once both are in place:

```
client encrypts pkt to exit's pubkey
   │
   └─► UDP to entry-ip:52817
          │
          └─► nftables: udp dport 52817 dnat to exit-ip:51820
                 │
                 └─► exit decrypts (only it has the private key)
                        │
                        └─► NAT to internet
```

The entry node sees: client IP, encrypted blob.
The exit node sees: entry IP, decrypted destination.
**Neither sees both.**

This is the same architecture Mullvad uses for their multi-hop feature.

The control plane only knows pubkeys + mesh IPs. No correlation between
account token and traffic.

### 5. CLI client + GUI (`client/`)

Single Go binary, cross-compiled to Linux/macOS/Windows × amd64/arm64 at
~5.4MB each. The same binary runs:

- **CLI:** `0trust login`, `connect`, `disconnect`, `rotate`, `status`, etc.
- **GUI:** `sudo 0trust gui` — opens a local HTTP server at
  `http://127.0.0.1:51827` and points your browser at it. Same operations
  as the CLI, in a clickable UI.

```
$ 0trust login
Account token: 7K2M-9X4P-AQ8R-J3WN
✓ logged in — subscription active (89 days remaining)

$ 0trust status
  account     : 7K2M-****-****-J3WN
  status      : active
  expires     : 2026-08-21  (89 days)
  devices     : 1 / 8
  tunnel      : up
  mode        : multi-hop  zur → buc
  next rotate : 04:00  (in 17h 53m)

# Single-hop connection
$ sudo 0trust connect zur
→ generating keypair
→ requesting peers for region "zur"
→ config written to /etc/wireguard/0trust0.conf
✓ tunnel up

# Multi-hop: entry in Zurich, exit in Bucharest
$ sudo 0trust connect zur --exit buc
→ requesting multi-hop route: zur → buc
→ config written to /etc/wireguard/0trust0.conf
→ multi-hop:  entry=zur-04  exit=buc-02
              entry never decrypts; exit never sees your IP
              relay endpoint  185.180.143.27:52817
              rotates by      2026-05-25 04:00 UTC
✓ tunnel up

# Hot-swap to a fresh entry/exit pair (no tunnel disruption)
$ sudo 0trust rotate
→ rotating hop-pair (zur → buc)
✓ rotated in place (no tunnel disruption)
  new pair:  entry=zur-07  exit=buc-04
  endpoint:  185.180.143.31:54219
  expires:   2026-05-26 04:00 UTC

# See what's registered, free a slot
$ 0trust devices
3 of 8 device slots used

* laptop               10.64.0.2        multi-hop zur-04 → buc-02
    kZ8Q...w4A=
    last seen 2026-05-24 09:12
  phone                10.64.0.3        single-hop
    b2Vh...T1E=
  old-laptop           10.64.0.4        single-hop
    9xQm...Lp0=

* = this device

$ 0trust remove 9xQm...Lp0=
✓ removed 9xQm...Lp0=

# Launch the GUI
$ sudo 0trust gui
0trust GUI: http://127.0.0.1:51827
Press Ctrl-C to stop
```

Build the full release matrix:

```bash
cd client/
make all       # produces dist/0trust-0.1.0-{linux,darwin,windows}-{amd64,arm64}
make build     # current platform only
```

#### Automatic hop-pair rotation

Multi-hop pairs expire 24h after creation. To rotate automatically, install
the client-side systemd timer (Linux):

```bash
sudo cp client/systemd/0trust-rotate.{service,timer} /etc/systemd/system/
sudo systemctl enable --now 0trust-rotate.timer
```

The timer fires every 6h with a 15-minute random jitter, well inside the
24h pair TTL. On macOS or Windows, schedule `0trust rotate` from `launchd` /
Task Scheduler.

#### GUI architecture notes

The GUI is **the same binary** — `0trust gui` starts an HTTP server with
HTML/CSS/JS embedded via `//go:embed` and opens the default browser. This
trades a "real native window" for cross-platform simplicity (no Tauri/Electron
toolchain, no separate codebase). The server binds to `127.0.0.1` only and
enforces a same-origin guard on API endpoints to block DNS-rebinding attacks.

State is stored in `~/.config/0trust/state.json` (mode 0600). The private
WireGuard key is generated locally on first connect and never sent to the
server — only the pubkey is.

### 6. Mobile (`mobile/`)

Two paths to running 0trust on a phone:

**Today (pragmatic path) — `0trust export`.** Generate a fresh device
config from the desktop CLI or GUI and scan the QR into the official
WireGuard app on iOS or Android:

```
$ 0trust export --exit buc --name phone
→ creating a new mobile device entry on your account

[QR rendered as ASCII in the terminal — also saved as phone.png]

Scan this with the official WireGuard app (Add → From QR code).

  mode:   multi-hop  zur-04 → buc-02
  conf:   ./phone.conf
  png:    ./phone.png

⚠ The .conf file and QR code contain a private key.
  Treat them like a password — share them only with the device you're provisioning.
```

The GUI has the same flow under **Add mobile device** → modal with QR.

**Branded Android app (`mobile/android/`).** A complete Compose-based
Android app, not a skeleton. Builds with Android Studio Hedgehog+, uses
the official `wireguard-android` library (GoBackend) for the data plane,
stores tokens via `EncryptedSharedPreferences`, persistent foreground
notification with a Disconnect action, single-hop + multi-hop with the
three jurisdictions baked in, auto-connect on boot, Material 3 dark
theme matching the web design system. See `mobile/android/README.md`
for build/sign/F-Droid/Play submission.

**iOS deliberately out of scope.** The QR-export path works for iOS
users with the official WireGuard app from the App Store. Building a
branded iOS app requires the Apple Developer Program ($99/yr), explicit
Apple approval of the Network Extension entitlement, and App Store
review for VPN apps — all of which are real money and weeks of process.
Revisit after launch when revenue justifies it.

### 7. Warrant canary (`canary/`)

A PGP-signed weekly statement that 0trust has not received specific kinds
of legal demands. If it stops being signed, the absence is the signal.

```
canary/
├── templates/canary.txt           # Master template (8 statements + freshness)
├── scripts/
│   ├── generate.sh                # Render + PGP-sign + deploy
│   └── check.sh                   # Alarm if file > 7 days old
└── systemd/0trust-canary-check.{service,timer}
```

To publish a fresh canary:

```bash
export CANARY_SIGNER_NAME="Operator Name"
export CANARY_SIGNER_KEY=0xDEADBEEF…
sudo -E ./canary/scripts/generate.sh
```

The script fetches the current Bitcoin block hash and prompts you for
four recent news headlines — both serve as proof-of-freshness anchors
that prove the document could not have been pre-signed.  It then prompts
GPG to sign with `CANARY_SIGNER_KEY` and deploys `canary.txt`,
`canary.txt.sig`, and `pubkey.asc` to `/var/www/0trust/`.

Nginx serves all three with `Cache-Control: no-store`, so a CDN can't
serve a stale-but-still-cached copy after the original was withdrawn.

The check service fires daily and alerts (via `wall` + optional webhook)
if the canary on disk is older than 7 days.

### 8. RAM-only ephemeral mesh nodes

`wireguard/cloud-init-ephemeral.yaml` is a cloud-init template that
provisions a mesh node entirely in RAM:

- `/var/0trust`, `/etc/0trust`, and `/etc/wireguard` are tmpfs mounts
- swap is disabled (no chance of paging private keys to disk)
- journald is set to `Storage=volatile` so even system logs are RAM-only
- WireGuard keys are generated fresh on boot, never persisted
- the node self-registers with the control plane using a one-shot
  provisioning token (X-Provision-Token), receiving a `node_id` and
  per-node PSK in response

Mint a provisioning token before launching the instance:

```bash
sudo -u 0trust python3 /opt/0trust/api/mint-provision-token.py \
    --region zur --role entry --ttl 3600

Token (single-use, valid 3600s):

  YqL6m-8FRk_uHcZ3xa9pSjN2qP4D-eW5tBvgKn1HxOAo

Place this in cloud-init user-data as ZTV_PROVISION_TOKEN.
After first use it cannot be replayed.
```

Substitute the token + region + role into `cloud-init-ephemeral.yaml`
and use it as the user-data when launching a fresh Ubuntu 24.04 cloud
instance. The cloud-init handler does the rest. Within 60 seconds the
node calls `/api/v1/node/provision`, gets its mesh identity, and starts
serving traffic.

The sweeper (`api/sweep.py`) deactivates ephemeral nodes whose heartbeat
has been stale for >5 minutes and garbage-collects their rows after 1
hour. A rebooted instance comes back with a new `node_id` and new keys —
the old row is dead weight and gets cleaned up.

Trade-off: every reboot causes momentary capacity loss in that region
because customers' hop pairs pointed at the old `node_id`. The 24h pair
rotation makes this a non-issue in practice — affected customers get a
fresh pair on their next rotation anyway, or sooner via `0trust rotate`.

### 9. No-logs audit pack (`docs/AUDIT.md` + `scripts/audit-verify.sh`)

`docs/AUDIT.md` is the document a third-party auditor (Cure53, Assured AB,
etc.) reads first. It enumerates every place the system touches data,
what's stored, where, for how long, and why. Thirteen sections covering:

- §3 — Data we collect and don't collect at each stage of the customer flow
- §4 — Web-tier (nginx) logging and its IP-anonymization
- §5 — Mesh-node behavior, including ephemeral RAM-only verification
- §6 — Control-plane database schema audit
- §7 — Application/journald log behavior
- §8 — Encrypted off-host backups (what they contain, what they cannot)
- §9 — Third-party services and exactly what they see
- §11 — Known limitations the operator declares proactively (cdnjs,
        7-day journald retention, 24h rotation default, etc.)

`scripts/audit-verify.sh` is the machine-checkable version. It runs the
verification matrix against the live host and exits non-zero if anything
fails:

```bash
sudo ./scripts/audit-verify.sh
```

Checks include: no plaintext token columns in the DB; no User-Agent in
nginx logs; no `wg show` polling writing to disk anywhere; no nftables
`log` rules; pubkeys never appear in the API journal; backups are
encrypted at rest; canary is fresh; and ephemeral-node-specific checks (tmpfs mounts,
swap off, journald volatile).  Each check has a short ID so the auditor's
report can reference specific findings.

## Threat model

| Adversary | Mitigation |
|-----------|------------|
| Server seizure (single node) | Multi-hop: seizing the entry yields ciphertext + client IP; seizing the exit yields destinations but no client IP. Either way, no traffic correlation from one box. |
| Server seizure (two nodes, collusion) | This is the unbreakable case — if the adversary controls both your entry and exit node, they can correlate. Mitigate by jurisdictional diversity and hop-pair rotation. |
| Traffic correlation by ISP | WireGuard handshakes are timing-correlatable in principle. Mitigate with `PersistentKeepalive=25` (constant chatter) and consider obfuscation in v0.2. |
| Identity linkage | No email/phone/name; tokens uncorrelated with payments. |
| Payment trace | Monero recommended; BTCPay generates fresh addresses per invoice. |
| Subpoena | We genuinely have no user records to hand over. The peer table maps pubkey→mesh IP; nothing connects to a real identity. |
| Rogue mesh node | Per-node PSK rotation; nodes can read peer/forward manifests but not account data, payment data, or token hashes. |
| Web fingerprinting | Static HTML, no third-party JS (except qrcodejs, on the TODO list to self-host), strict CSP, anonymized logs. |
| DoS on signup | Nginx rate limit: 5 signups/min/IP. |

## Deployment

### Prerequisites

- **3 hosts minimum** running Ubuntu 24.04:
  1. Control plane (the box this README's bootstrap targets)
  2. BTCPay Server (separate, follow upstream docs)
  3. At least one WireGuard mesh node
- DNS pointed at the control plane
- Hosting provider that won't snitch (BuyVM, FlokiNET, 1984, etc.)
- Bitcoin/Monero wallet for the BTCPay store

### Control plane

```bash
git clone https://your-private-git/0trust-vpn /opt/0trust-src
cd /opt/0trust-src
sudo DOMAIN=0trustvpn.com ADMIN_EMAIL=0trustvpn@proton.me \
     ./scripts/bootstrap.sh
```

Then edit `/etc/0trust/api.env` to add your BTCPay credentials:

```bash
sudo nano /etc/0trust/api.env
sudo systemctl restart 0trust-api
```

### BTCPay Server

Follow the [official guide](https://docs.btcpayserver.org/Deployment/).
Configure:

- Store: "0trust VPN"
- Payment methods: BTC, XMR, ZEC
- Webhook URL: `https://0trustvpn.com/api/v1/payment/webhook`
- Webhook secret: same value as `BTCPAY_WEBHOOK_SECRET` in `/etc/0trust/api.env`

### Mesh nodes

On each node, grab `NODE_API_PSK` from the control plane's `/etc/0trust/api.env`:

```bash
ssh node1
git clone https://your-private-git/0trust-vpn
cd 0trust-vpn
sudo CONTROL_URL=https://0trustvpn.com \
     NODE_API_PSK=<from control plane> \
     NODE_ID=zur-01 \
     REGION=zur \
     NODE_ROLE=entry \
     ./scripts/bootstrap-node.sh
```

`NODE_ROLE` is one of `entry`, `exit`, or `both` (default). For multi-hop
to actually mean anything you want at least one dedicated `entry` and one
dedicated `exit`, in different jurisdictions.

The script prints a SQL `INSERT` at the end — run it on the control plane
to register the node.

## Operations

```bash
# Service status
systemctl status 0trust-api
systemctl status 0trust-meshd     # on mesh nodes

# Logs
journalctl -u 0trust-api -f
journalctl -u 0trust-meshd -f

# Database
sqlite3 /var/lib/0trust/0trust.db

# Active accounts
SELECT COUNT(*) FROM accounts WHERE status='active' AND expires_at > strftime('%s','now');

# Active devices
SELECT COUNT(*) FROM devices;

# Mesh capacity
SELECT region, COUNT(*) FROM mesh_nodes WHERE active=1 GROUP BY region;
```

## Ready to launch?

The engineering checklist is complete. What remains is operator action:
generating keys, standing up hosts, signing the first canary, cutting
the first release, commissioning the audit.

**See [`LAUNCH.md`](LAUNCH.md)** for a concrete 8-14 day playbook. It
sequences every remaining step with dependencies, timing estimates, and
the recurring weekly/monthly/quarterly tasks for operating the service.

The system also ships with these privacy hardenings beyond what was on
the original checklist:

- **Tor onion mirror** — `.onion` site for browsing/signup/download
  without ISP visibility. Standard among privacy projects. See
  `tor/README.md`.
- **CSP + SRI** — strict content security policy, no third-party
  script origins, SRI hashes pin vendored libraries.
- **`/status` page** — sanitized per-region health, no operational
  details exposed to adversaries.
- **`/help`, `/audit`, `/security-policy`, `/download`** — full
  customer-facing site so support volume stays low and trust is
  established before the first ticket arrives.

## Legal notes

- Operate where your **logging laws are weak**: Iceland, Romania, Panama,
  Seychelles. Avoid 14-eyes if you can.
- Consult a lawyer in your jurisdiction. We can't.
- A warrant canary is a public commitment; once you stop signing it, you've
  said something. Set up the cadence before launch.
- A no-logs claim that turns out to be false is fraud. Audit before you claim.

## License

Pick one. AGPL-3.0 for the server, MIT for the client are common choices for
this kind of project.
