# 0trust — system architecture, as built

Written from the code, not from a design document. Where the code and the
project's own prose disagree, this file follows the code and says so.

Audit date: 2026-10-17. Commit: see `git log` at the time of reading.

---

## 1. What the system is

A commercial mesh VPN service. A customer pays in cryptocurrency, receives a
16-character token, and uses that token — and nothing else — as their entire
identity. There is no email address, no password, no account recovery. The
token is the credential.

Traffic is carried by WireGuard through three nodes in three jurisdictions
(`zur` Zurich, `rey` Reykjavik, `buc` Bucharest), either single-hop or
multi-hop (enter in one country, exit in another).

The privacy claims are the product. That makes claim-vs-reality drift the
highest-severity defect class in this codebase, above memory safety or
availability, and the test suite is built around that judgement.

## 2. Component map

| Area | Lines | What it is |
|---|---:|---|
| `api/` | 7,341 | FastAPI + SQLite control plane |
| `client/` | 7,203 | Go CLI, 6 platform targets, browser GUI, obfuscation relay |
| `web/` | 8,652 | Landing, legal, status, funnel and SEO pages |
| `scripts/` | 7,954 | Installer, bootstraps, key tooling, release, audit verifier |
| `mobile/android/` | 3,001 | Kotlin/Compose app |
| `mobile/ios/` | 2,139 | SwiftUI app + WireGuardKit extension |
| `proxy/` | 1,040 | `/surf` visitor web proxy |
| `wireguard/` | 625 | `meshd`, the node-side peer synchroniser |
| `installer/` | 781 | WiX MSI, .deb, AppImage |
| `systemd/` | 422 | Units and timers |
| `tests/` | 15,241 | Emulation suite, 30 modules |

Tests are the largest single area in the repository. That ratio is the
correct one for this product and is worth preserving.

## 3. Control plane

**Process model.** `uvicorn` running `api/main.py` behind nginx. SQLite with
WAL. 22 HTTP routes.

**Wire contract.** snake_case JSON. Authentication is the
`X-Account-Token` header — not `Authorization: Bearer`. The token is the
credential; there is no session, no refresh, no OAuth.
`client/internal/api/api.go` is the canonical definition and the Android and
iOS clients are required to match it field for field. A `validate.sh` check
(`auth-header`) enforces the header across all clients, because a mismatch
here has broken the Android client completely once before.

**Routes, grouped by what they do:**

- *Unauthenticated, public:* `/health`, `/config`, `/regions`,
  `/status/public`
- *Account lifecycle:* `POST /account` (paid signup),
  `GET /trial/challenge` + `POST /trial` (proof-of-work free trial),
  `GET /account/status`, `POST /account/topup`
- *Payments:* `GET /payment/{id}/methods`, `GET /payment/{id}/status`,
  `POST /payment/webhook`
- *Tunnel:* `POST /wg/register`, `POST /wg/rotate`, `GET /devices`,
  `DELETE /devices/{pubkey:path}`
- *Node-facing:* `POST /node/provision`, `POST /node/heartbeat`,
  `GET /wg/peers`, `GET /wg/forwards`
- *Notices:* `GET /notices`, `POST /notices/{id}/read`

An admin dashboard lives in `api/admin.py` with its own session cookie,
login throttling and audit log.

**Schema.** 16 tables: `accounts`, `devices`, `invoices`, `mesh_nodes`,
`address_index`, `ops_events`, `provision_tokens`, `admins`,
`admin_sessions`, `admin_audit`, `settings`, `notices`, `notice_reads`,
`device_nodes`, `trial_grants`, `hop_pairs`.

Two invariants hold this together and both exist because they were violated:

- Any handler that *allocates* (a mesh IP, an entry port, a node id, a
  payment address index) must take `db(write=True)`, which opens
  `BEGIN IMMEDIATE`. Read-then-write without it is a UNIQUE-constraint 500
  under more than one uvicorn worker.
- Any bulk delete must clear dependents first. `hop_pairs` references
  `mesh_nodes` and `trial_grants` references `accounts` with
  `ON DELETE SET NULL`, so a sweep that assumes CASCADE raises and takes the
  rest of the sweep down with it.

## 4. Address allocation and the mesh

IPv4 mesh is `10.64.0.0/10`. IPv6 is `fd0e:5f7a:c21b::/48`, a ULA, and a
device's v6 address is its v4 address embedded in the low 32 bits — so
`10.64.0.5` becomes `fd0e:5f7a:c21b::a40:5`. One allocator, not two racing
ones.

That derivation is implemented three times — `mesh_ip6()` in the API,
`_derive_gateway6()` in meshd, `ztv_mesh_ip6()` in `node-runtime.sh` — and a
test asserts all three agree. This is a real duplication risk that is
managed rather than removed, because the three run in three languages on two
machines.

`::/0` is always claimed in AllowedIPs; a v6 *address* is handed out only
when the exit node's heartbeat reports working v6 egress. Dropping `::/0`
would let v6 leak around the tunnel on a dual-stack host. Claiming it
without an address blackholes v6, which is the safe failure.

**One peer per config.** WireGuard's AllowedIPs is a routing table, so a
second peer claiming `0.0.0.0/0` silently takes that prefix off the first.
`_pick_node` returns exactly one node: live before stale, roomiest first by
capacity minus assigned devices, requested region preferred between two live
candidates. Failover is the client reconnecting after its handshake check
fails — not a peer list.

## 5. Nodes

A node is a RAM-only Ubuntu 24.04 VPS: tmpfs paths, swap off, volatile
journald, fresh WireGuard keys on boot. The intent is that seizing a node
reveals nothing operational beyond the customers it was itself routing, and
`/wg/peers` is scoped per node so one node's credential does not enumerate
the customer base.

**A reboot is a rejoin, not an outage.** Because the disk is tmpfs, a
restart loses the node's key, id and PSK. A multi-use enrolment token in
`/etc/0trust-node.env` — the one file deliberately on persistent disk — is
pinned to the node's public IP on first use and re-registers the *same* node
id thereafter, rather than accumulating a row per boot.

**Kernel state is reapplied, not assumed.** `/etc/nftables.conf` does not
include `/etc/nftables.d`, so NAT and the egress filter do not survive a
reboot on their own. `scripts/node-runtime-apply.sh` reapplies them at boot.
This was a real outage mode: an exit node came back doing no masquerading,
customer traffic entered the tunnel and died silently, and the node went on
heartbeating the whole time over its own outbound HTTPS.

**meshd** polls the control plane every 30s, rewrites the node's WireGuard
peer set with `wg syncconf`, installs a `/32` route per peer (`proto static`,
so it never deletes the kernel's own), and replaces its own nftables DNAT
table. Each node must have its own table name or co-located nodes erase each
other every 30 seconds.

**DNS leaves a node over TLS or not at all.** dnsmasq forwards only to a
local stubby stub doing DNS-over-TLS to Quad9, authenticated by certificate
name. There is deliberately no cleartext retry: a silent downgrade is the
same leak, unnoticed.

## 6. Payments

No self-hosted blockchain node. `ZTV_PAYMENT_PROVIDER` selects between
`watch` (default), `btcpay`, `hosted`, and `stripe`/`square`.

`watch` is the only provider that works on a fresh VPS, which is why it is
the installer default. It derives a fresh receive address per invoice from
the operator's extended **public** key and asks a public explorer whether it
was paid. `api/chainwatch.py` cannot sign; it holds no private key and the
code is structured so it cannot acquire one.

The three `watch` coins do not work the same way, and this asymmetry is
load-bearing:

- **BTC and ZEC** derive an address from the xpub and poll an explorer.
  Zcash means transparent `t1` addresses only — a shielded address cannot be
  derived from a public key or seen by an explorer.
- **Monero has neither.** The chain publishes no recipient and no amount, so
  detection requires the private view key and a block scan.
  `monerowatch.py` talks JSON-RPC to a view-only `monero-wallet-rpc`: no
  chain on disk, no spending authority, a subaddress per invoice.

Atomic units are per coin (1e8 BTC/ZEC, 1e12 XMR) and confirmation depth is
enforced per coin (1/5/10). Both depth readers refuse a truncated explorer
response rather than guessing, and they failed in *opposite* directions
before that guard existed: Esplora under-credited silently, Blockchair
over-credited money whose depth was never seen.

Settlement is a polling timer, not a webhook, because a webhook needs a
public callback URL and a TLS certificate while polling needs one outbound
HTTPS request.

## 7. Client

One Go module, six cross-compiled targets, `CGO_ENABLED=0`.

`client/internal/transport` is the single place that decides direct versus
obfuscated transport. Three callers need that decision — connect, rotate and
the GUI's connect handler — and rotate is the reason it is shared: rotating
moves the *entry* node, which is the node the relay dials, so a relay left
running forwards to a box no longer in the route.

Throughout the client, the **setting** and the **fact** are separate values.
`Obfuscate` is what the customer asked for; `RelayActive` is whether a relay
is really carrying traffic. They differ whenever the node a customer landed
on runs no relay, and in that case the client produces a direct tunnel that
*says so* rather than connecting as though the request had been honoured.
The same discipline appears in `0trust connect`, which waits for an actual
handshake before claiming the tunnel works, because `wg-quick up` never
contacts the node and its exit code means nothing.

The GUI is a localhost web server on 127.0.0.1:51827, not a native window —
the same code on all three desktop platforms.

## 8. Obfuscation

Shadowsocks AEAD (aes-256-gcm), pure stdlib, **one implementation serving
both ends** — the node daemon `0trust-obfs` and the client relay are the
same package. Opt-in on both ends; the default is plain WireGuard, which DPI
identifies, and no copy may imply otherwise in either direction.

The node relay is not a Shadowsocks server and must not become one. Every
customer on a node holds the same relay key, so an unrestricted relay is an
open proxy with a published password. Destinations are allowlisted to the
node's own WireGuard ports, hostnames are rejected outright so it never
resolves for anybody, and the flow table is **capped** rather than merely
reaped — a reaper bounds the steady state, not the peak, and a spoofed
source costs an attacker nothing.

What obfuscation does *not* give, stated in `docs/DEPLOY.md` and enforced by
a test: authentication (the key is shared), traffic-analysis resistance
(sizes and timing are unchanged), or a way through a total UDP block.

MTU is published per transport by the server (`WG_MTU` /
`WG_MTU_OBFUSCATED`) and never computed in a client, because the relay's
55-byte overhead still lets a 148-byte handshake through — so getting it
wrong brings the tunnel up healthy and then silently drops full-size
packets.

The **Android app contains a second implementation** of this wire format,
because wireguard-android brings the tunnel up inside the app process and
cannot call the Go binary. Two implementations can disagree, and a
disagreement is a tunnel that silently will not come up in the one country
where the customer needed it. The mitigation is that those Kotlin files
carry no `android.*` reference, so CI compiles them on a plain JVM and
pushes real packets through the real Go relay.

## 9. Web tier

nginx terminates TLS, applies six `limit_req` zones, and serves the static
site. **`scripts/install.sh` generates the deployed config;
`nginx/0trustvpn.com.conf` is a reference file the installer has never
installed.** Anything added to the reference and not to the generator does
not exist on a deployed box. That gap once held the worst defect in the
product — no anonymising log format on a real deployment while privacy.html
said client IPs were truncated to a /24.

Two request paths are secrets and must not be logged:
`DELETE /api/v1/devices/{pubkey}` carries a customer's WireGuard key, and
`GET /api/v1/payment/{id}/status` carries a bearer capability. Both uvicorn
(`--no-access-log`) and nginx (a `$uri_anon` map) drop the secret segment.

Behind Cloudflare, `$remote_addr` is the edge, and four things read it: the
rate-limit zones, `X-Real-IP` (which feeds admin login throttling and the
admin audit log), and the anonymising log map. `install.sh --cloudflare`
installs a verified realip trust list that fails closed — it refuses
`0.0.0.0/0`, a short list, or anything that is not a CIDR, because a
permissive list turns `CF-Connecting-IP` into "pick your own address".
Cloudflare terminates TLS and therefore reads everything it fronts,
including `X-Account-Token`; this is disclosed in privacy.html §5a and
AUDIT.md §9, and a check fires in *both* directions.

## 10. `/surf` proxy

A page reader that covers one browser tab — a funnel, not a product. It runs
as a separate service on a separate port so it can be killed without
touching the control plane.

`proxy/guards.py` is the entire security argument: GET/HEAD only, http/https
only, ports 80/443 only, public unicast destinations re-checked on **every**
redirect, size and time caps, content-type allowlist. `_is_public` names the
tunnelled forms explicitly — IPv4-mapped, 6to4, Teredo, NAT64 — rather than
resting on the standard library's classification, because
`2002:a9fe:a9fe::` is the cloud metadata service in a 6to4 wrapper.

The CSP contains a proxied page's subresources but **not** its navigation:
no shipping directive restricts a top-level navigation, so a `<meta
http-equiv="refresh">` walked the visitor to the origin under our banner.
`rewrite.py` rewrites the refresh target rather than dropping the tag.

## 11. Trust boundaries

| Boundary | Carries | Authenticated by |
|---|---|---|
| Customer → control plane | token, device pubkey | `X-Account-Token` |
| Customer → node | WireGuard data | WG keypair + PSK |
| Node → control plane | peer sync, heartbeat | node PSK (scoped per node) |
| Operator → admin UI | full control | session cookie + throttling |
| Control plane → explorer | invoice addresses | none (public, capped reads) |
| Control plane → Cloudflare | all HTTP, incl. tokens | TLS to the edge only |
| Visitor → `/surf` | arbitrary URLs | none — `guards.py` is the boundary |

The sharpest of these is the last: `/surf` is unauthenticated and takes a
URL from anyone. The second sharpest is the Cloudflare row, which is a real
disclosed trust delegation rather than a control.

## 12. Deliberate non-goals

Recorded so they are not mistaken for gaps:

- No macOS kill switch. The client says so rather than pretending.
- No nginx fail2ban jail. The access log records a /24, so a jail fed by it
  could only ban up to 254 uninvolved people along with the attacker. The
  privacy property and the IP-banner are incompatible and the first is kept.
- No iOS obfuscation. WireGuardKit owns the packet path and leaves nowhere
  for a local UDP relay; the app connects directly, which is the safe
  direction, and its copy must not mention DPI protection.
- No fallback to a direct connection when the Tor control channel fails, and
  no cleartext DNS retry. A silent downgrade restores the signal precisely
  when someone is interfering.
- No system tray (v0.2 backlog).
