# 0trust VPN — Claude Code project guide

> This file is read automatically by Claude Code at the start of every
> session. It carries over the context, locked decisions, conventions, and
> gotchas from the project's design so you don't start cold. Keep it current:
> when a decision changes or a new invariant appears, update this file.

## What this is

**0trust** is a commercial, privacy-first mesh VPN service (a Mullvad-style
product) built as a complete, launch-ready codebase. It is a real business:
it takes crypto payments, provisions WireGuard tunnels, and makes verifiable
no-logs claims. Everything parses/builds/validates; what remains before public
launch is operator action (provisioning servers, signing keys, compiling
installers, legal review), not core engineering.

The product routes customer traffic through a mesh of **three server nodes in
three jurisdictions outside the Five/Nine/Fourteen Eyes alliances**, with
single-hop or multi-hop (enter one country, exit another) routing. Accounts
are anonymous 16-char tokens; there's no email/password/identity.

## Repository layout

```
api/            FastAPI + SQLite control plane (main.py is the core)
                payments.py (BTCPay / hosted gateway), btcpay.py (legacy client),
                sweep.py (expiry sweeper), mint-provision-token.py,
                smoke_test.py
client/         Go module github.com/0trust/cli (Go 1.22, dep: skip2/go-qrcode)
  cmd/0trust/main.go              CLI entrypoint + help text
  internal/api/api.go             Backend HTTP client — CANONICAL wire contract
  internal/config/                Local state (~/.config/0trust/state.json)
  internal/wg/                     Cross-platform WireGuard control:
    wg.go        Shared: GenKeypair (stdlib crypto/ecdh), BuildConfig, WriteConfig
    wg_unix.go   Linux/macOS: wg-quick + wg syncconf
    wg_windows.go Windows: wireguard.exe /installtunnelservice (official service)
  internal/gui/gui.go             Browser GUI server on 127.0.0.1:51827
  internal/gui/assets/            index.html, app.css, app.js (embedded)
  internal/export/export.go       Mobile QR config export
mobile/android/                   Complete Kotlin/Compose app (wireguard-android)
mobile/ios/                       Skeleton — OUT OF SCOPE for v0.1 (QR-export covers iOS)
installer/windows/                WiX v4 MSI (0trust.wxs)
installer/linux/deb/              build.sh → .deb (amd64+arm64), TESTED working
installer/linux/appimage/         build.sh → AppImage (auto-fetches appimagetool)
btcpay/                           BTCPay Server deploy + integration (lite path)
canary/                           Warrant canary (PGP-signed weekly statements)
support/                          PGP support workflow (WKD, auto-reply)
tor/                              v3 onion mirror (serves browsing, NOT /api)
nginx/0trustvpn.com.conf          Main site config (rate limits, routes, TLS)
scripts/                          bootstrap.sh, bootstrap-node.sh, audit-verify.sh,
                                  backup.sh, release.sh, verify-release.sh,
                                  install.sh (one-shot VPS), node-runtime.sh
                                  (sysctl/NAT/egress/resolver, shared by the
                                   node bootstrap and the test installer)
systemd/                          api / sweep / backup / meshd .service + .timer
proxy/                            Visitor web proxy (/surf):
                                  guards.py (the security argument),
                                  rewrite.py, server.py
tests/emulation/                  Full-stack suite: boots the product, drives it
web/                              Landing + status/download/help/audit/privacy/
                                  terms/security + trial.html (free-trial signup)
docs/                             README, LAUNCH, AUDIT, ABUSE, DR
```

## LOCKED operator decisions — do not change without explicit instruction

- **Domain:** `0trustvpn.com` (brand mark "0trustvpn", no slash). A backup
  domain at a different registrar is a launch to-do.
- **Contact email:** `0trustvpn@proton.me` — SINGLE inbox. All role addresses
  (security@, support@, abuse@, legal@) are optional aliases that route here.
  Every web page uses the proton.me address directly.
- **Bitcoin xpub:** `zpub6msFuvuWJzY7eGzgLkT2omB8HqBQ5z3KkbVD43Fj2iKGTPDLxyZJphYyJAnJwkDYRYtvTnHB1zJhDC6iFrEmF7puQDD3e11d6zKtQdvP1xU`
- **Three mesh nodes only**, all outside Five/Nine/Fourteen Eyes:
  - `zur` = Zurich, Switzerland
  - `rey` = Reykjavik, Iceland
  - `buc` = Bucharest, Romania
  (Norway was rejected earlier — it's in Nine Eyes. Romania replaced it.)
  **These region codes must be identical everywhere** — CLI, GUI, Android,
  iOS skeleton, API defaults, docs, landing-page terminal demo.
- **Currencies: BTC, XMR, ZEC.** ETH and LTC were dropped. The codes live in
  `payments.CURRENCIES`, the BTCPay checkout config, and web/index.html's
  crypto tabs — keep them in step.
- **No self-hosted blockchain node.** `ZTV_PAYMENT_PROVIDER` picks between
  `watch` (default: derive a receive address per invoice from the operator's
  own xpub and confirm via a public explorer — non-custodial, no account
  anywhere, no chain data, BTC only), `btcpay` (your own or somebody else's
  BTCPay instance — non-custodial, more coins, but something has to run
  BTCPay), `hosted` (a commercial gateway, no infrastructure at all, but
  custodial and usually KYC'd), and `stripe`/`square` (cards, which mean a
  real identity behind every payment). `api/payments.py` documents the
  trade-off; if the audit pack ever leans on the payment path, reconcile it
  with whichever provider is actually configured.
- **`watch` is the only provider that works on a fresh VPS**, which is why it
  is the installer default: paste `WALLET_BTC` and paid signup works. It has
  no webhook — settlement is `0trust-poll.timer` asking an Esplora explorer
  once a minute — because a webhook needs a public callback URL and a TLS
  certificate, and polling needs one outbound HTTPS request.
- **Never put a private key anywhere near this.** `api/chainwatch.py` takes an
  extended PUBLIC key and cannot sign. Its derivation is checked against the
  BIP84/BIP173 vectors in `test_chainwatch.py`, and against private derivation
  computed independently in the test — never against its own output. A bug
  here sends customers to addresses the operator cannot spend, silently, with
  every health check green.
- **One address per invoice.** The index comes from the `address_index`
  counter inside `db(write=True)`; two signups sharing an address makes two
  payments of the same amount impossible to attribute. A plain address in
  `WALLET_BTC` is accepted but reused, and the dashboard says so.
- **Free trial: one week, no identity.** A browser grinds a proof-of-work
  stamp, redeems it for an ordinary anonymous token, and the account expires in
  `ZTV_TRIAL_DAYS` days (default 7) with a lower device cap. Paying converts the
  same account and stacks the paid months on whatever the trial had left.
  **Nothing hardcodes the length in copy.** `GET /api/v1/config` publishes
  `trial.days` and a phrased `trial.label`; the landing page, trial page,
  /surf banner and desktop GUI all render from it, so an operator changing the
  setting in the dashboard never leaves a page advertising the old offer. The
  proxy keeps a word-for-word copy of the phrasing for when the control plane
  is unreachable, and a test asserts the two never disagree.
- **`/surf` is a funnel, not a product.** A page reader that covers one browser
  tab. Separate service, separate port, so it can be killed without touching
  the control plane — and the UI must keep saying plainly what it is not.
  Overstating it would be claim-vs-reality drift on our most visible page.
- **iOS:** dropped from v0.1 scope. QR-export into the official WireGuard app
  covers iOS users. Do not build a branded iOS app without explicit go-ahead
  (needs Apple Developer Program + Network Extension entitlement + review).
- **Design system:** warm-dark palette
  `--bg #0c0c0a  --ink #f4ede0  --amber #d4a574  --terra #c44536  --moss #7d8f5a  --line #2a2820`.
  Fonts: Instrument Serif (headings), JetBrains Mono (technical/labels),
  IBM Plex Sans (body). Dark-only product.

## Architecture invariants (things that must stay true)

- **API wire contract is snake_case**, auth via `X-Account-Token` header (NOT
  Bearer/OAuth — the token IS the credential). `client/internal/api/api.go` is
  the canonical definition; any other client (Android, iOS) must match it
  field-for-field. See "Recurring bug classes" below — this has bitten us.
- **Mesh network is `10.64.0.0/10`** (`MESH_NETWORK` in the API). The node
  egress filter's `CLIENT_NET` and the masquerade rule must match this.
- **IPv6 mesh is `fd0e:5f7a:c21b::/48`** (`MESH_NETWORK6`), a ULA. A device's
  v6 address is its v4 address embedded in the low 32 bits — 10.64.0.5 becomes
  `fd0e:5f7a:c21b::a40:5` — so there is one allocator, not two racing ones.
  That derivation exists three times (`mesh_ip6()` in the API,
  `_derive_gateway6()` in meshd, `ztv_mesh_ip6()` in node-runtime.sh) and a
  test asserts all three agree; a mismatch hands a client an address its node
  does not answer on.
- **`::/0` is always claimed, a v6 address is not.** Clients get a v6 address
  only when the exit node reports working v6 egress (`mesh_nodes.ipv6`, set
  from the heartbeat). Dropping `::/0` to "fix" v6 is how v6 leaks around the
  tunnel on a dual-stack host — without an address it is blackholed, which is
  the safe failure. v6 leaves the exit masqueraded (NAT66), not on a
  per-customer prefix, which would be a tracking identifier.
- **Multi-hop requires entry ≠ exit.** Enforced by `_validate_regions()` in
  the API, shared by both register and rotate endpoints.
- **RAM-only ephemeral nodes:** tmpfs paths, swap off, fresh WG keys on boot,
  journald volatile. A seized node reveals nothing operational beyond the
  customers it was itself routing — `/wg/peers` is scoped per node, so one
  node's PSK does not enumerate the customer base. See `device_nodes`.
- **No-logs claims must match reality.** The privacy policy (web/privacy.html),
  terms (web/terms.html), and audit pack (docs/AUDIT.md) all make the SAME
  claims. If you change what the system collects/retains, you MUST update all
  three, and `scripts/audit-verify.sh` must still pass. See discipline note below.
- **`/wg/peers` is scoped to the calling node.** A node gets only the devices
  routed through it, tracked in `device_nodes` and rewritten on every
  register/rotate. The node must identify itself — its own PSK, or `node_id`
  with the shared one. Returning the full roster to anything holding a node
  credential is what the seizure claim above rules out.
- **Device registration is idempotent on the pubkey.** Clients persist their
  keypair, so reconnects re-present the same key. Registering it again returns
  the existing device's config and keeps its mesh IP; it never creates a second
  device or errors. Deregistering is `DELETE /api/v1/devices/{pubkey}` — the
  8-device cap needs an exit or customers get permanently stuck.
- **The proxy never becomes a general-purpose relay.** `proxy/guards.py` is the
  entire security argument: GET/HEAD only, http/https only, ports 80/443 only,
  public unicast destinations re-checked on every redirect, size and time caps,
  content-type allowlist. Read it before touching anything under `proxy/`, and
  keep `test_proxy_guards` passing with nothing patched.
- **`install.sh --mode test` puts the whole product on one VPS**, VPN included:
  three WireGuard interfaces (`wg0/wg1/wg2` = zur/rey/buc, udp 51820-51822),
  three meshd instances via `0trust-meshd@.service`, real keys in `mesh_nodes`,
  NAT + egress filter + resolver from `scripts/node-runtime.sh`. `--no-vpn`
  restores the old placeholder-rows behaviour. It is a test rig and says so:
  no TLS, one jurisdiction wearing three names, and multi-hop that routes
  correctly but hides nothing because entry and exit are the same host. Never
  soften that wording — it is the difference between a demo and a lie.
- **One nftables table per node, never a shared name.** meshd replaces its
  whole DNAT table on every poll (`ZTV_NFT_TABLE`, default `ztv_forward`), so
  several nodes on one host must each get their own or they erase each other
  every 30s. The test installer sets `ztv_fwd_<iface>`.
- **meshd installs a /32 route per peer.** `wg syncconf` sets AllowedIPs, which
  picks the peer once a packet is on the interface — it does not route anything
  there. One node gets away with it via the `/10` connected route; three
  interfaces in one `/10` do not, and replies go to the wrong interface. Routes
  carry `proto static` so the daemon never deletes the kernel's own.
- **Clients are handed `DNS = 10.64.0.1` (plus the v6 gateway where v6 is
  carried), so something must answer there.**
  `dnsmasq` on the mesh gateway, `bind-interfaces` (an open resolver on the
  public IP is a DNS-amplification abuse report waiting to happen), forwarding
  to `ZTV_DNS_UPSTREAM` (Quad9 by default). **Query logging must stay off** —
  privacy.html §4d and `audit-verify.sh`'s `node-dns-no-query-log` both say so.
- **One peer per config, never a list.** WireGuard's AllowedIPs is a routing
  table: a second peer claiming `0.0.0.0/0` takes that prefix off the first.
  Handing the client three "for failover" left one working peer, two inert
  ones, an API naming a node it was not using, and the customer's key in three
  nodes' manifests. `_pick_node` returns exactly one — live before stale,
  roomiest first (`capacity` minus assigned devices, not the declared number),
  requested region preferred between two live nodes. Failover is the client
  reconnecting after its handshake check fails.
- **`0trust connect` proves the tunnel works before saying so.** `wg-quick up`
  never contacts the node, so its exit code means nothing. The client waits for
  a handshake and, if none arrives, says the tunnel is NOT carrying traffic and
  exits non-zero — leaving the interface up, because it still holds the default
  route and dropping traffic beats leaking it.
- **Kill switch is opt-in, sticky, and Linux-only.** `--kill-switch` writes
  wg-quick `PostUp`/`PreDown` iptables rules; `PreDown` must always end in
  `|| true` or a failed teardown strands the user offline. Windows needs
  nothing (WireGuard for Windows does it natively when AllowedIPs covers both
  families); macOS is unsupported and the client says so rather than pretending.
- **`ops_events` never holds customer data.** Node ids, provider names, counts
  and infrastructure detail only. It is the single table that keeps a running
  narrative of the system's state over time, so an account id in it turns it
  into the activity log privacy.html denies keeping. Alerts fire on
  *transitions*, not states, or the operator gets an hourly stream and silence
  stops meaning anything.
- **The GUI is browser-based, not native.** `0trust gui` runs a localhost web
  server; it's the same code on all 3 desktop OSes. No system tray (v0.2 —
  systray libs were blocked in the original build env).

## Build & validation commands

```bash
./scripts/validate.sh          # everything below, in one command
./scripts/validate.sh go api   # only checks whose id contains these
./scripts/validate.sh -l       # list the check ids
```

Treat green across the whole battery as the bar before considering anything
done. Exit code is the number of failed checks. In Claude Code on the web,
`.claude/hooks/session-start.sh` provisions the venv and Go module cache the
script needs; elsewhere, build a venv from `api/requirements-dev.txt`.

CI runs the same script on every push to `main` and every PR against it
(`.github/workflows/validate.yml`), so there is one definition of green rather
than a local one and a CI one that drift apart. A new invariant worth enforcing
belongs in validate.sh, where all three pick it up.

The individual checks, for reference — this is what the script runs:

```bash
# --- Go client: vet + cross-compile all 6 targets ---
cd client
export CGO_ENABLED=0
go vet ./...
for p in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os=${p%/*}; arch=${p#*/}; ext=""; [ "$os" = "windows" ] && ext=".exe"
  GOOS=$os GOARCH=$arch go build -trimpath -ldflags "-s -w" -o dist/0trust-$os-$arch$ext ./cmd/0trust
done
cd ..

# --- Python API: parse + live endpoint smoke test ---
python3 -c "import ast; ast.parse(open('api/main.py').read())"
python3 api/smoke_test.py   # seeds a tmp DB, drives the API via TestClient

# --- Bash: syntax-check every script ---
for f in $(find . -name '*.sh'); do bash -n "$f" || echo "FAIL: $f"; done

# --- HTML: parse every page ---
python3 -c "import html.parser,glob
class P(html.parser.HTMLParser): pass
[P().feed(open(f).read()) for f in glob.glob('web/*.html')]"

# --- Markup validity (full Android build needs Android Studio + NDK) ---
python3 -c "import xml.etree.ElementTree as ET,glob
[ET.parse(f) for f in glob.glob('mobile/android/**/*.xml',recursive=True)
                    + glob.glob('installer/**/*.wxs',recursive=True)]"

# --- Linux packages (needs dpkg-dev; produces real .debs) ---
make -C client linux 2>/dev/null || (cd client && for a in amd64 arm64; do \
  GOOS=linux GOARCH=$a go build -o dist/0trust-linux-$a ./cmd/0trust; done; cd ..)
./installer/linux/deb/build.sh
```

The Android app requires Android Studio Hedgehog+ with the NDK to build an
APK (`./gradlew assembleDebug`). The Windows MSI requires a Windows host with
WiX (`wix build`). Neither can be built in a headless Linux-only environment;
the source is complete and validated as far as it can be without those toolchains.

## Recurring bug classes — check these first when something's off

These have each bitten the project more than once. When you touch related
code, actively check for them:

1. **Stale region codes.** Old codes `ams/fra/lon/sto/nyc/sjc/sgp/tyo` from
   an earlier design leak into defaults, help text, and demos. The ONLY valid
   codes are `zur/rey/buc`. Grep for the old ones after any change:
   `grep -rnE '"(ams|fra|lon|sto|nyc)"' api client mobile`
2. **camelCase vs snake_case wire mismatch.** The API is snake_case. Any new
   API client field must map correctly (Kotlin uses @SerialName; Go uses json
   tags). The Android client was fully broken by this once.
3. **Auth header.** It's `X-Account-Token`, never `Authorization: Bearer`.
4. **Claim-vs-reality drift.** The biggest risk for a privacy product. The
   audit pack once claimed "no backups" while backups existed (and the claim
   was also operationally broken — the token alone can't rebuild subscription
   expiry). If you change data handling, reconcile privacy.html + terms.html +
   AUDIT.md + audit-verify.sh together. Be honest over reassuring.
5. **Empty-slice panics.** `resp.Peers[0]` panics if the peer list is empty.
   Guard with `len(...) > 0` before indexing API responses. The API no longer
   hands back an empty peer list — `_single_hop_peers()` raises 503 instead —
   but the client guard stays as defence in depth.
6. **Read-then-write races.** Allocating a mesh IP, an entry port or a node id
   is a read of what's free followed by an insert. Under more than one uvicorn
   worker two requests read the same free slot and one dies on a UNIQUE
   constraint — a 500 for the customer. Any handler that allocates must take
   `db(write=True)`, which opens BEGIN IMMEDIATE.
7. **Replayable side effects.** The payment webhook is the sharp one: BTCPay
   retries deliveries and the HMAC on a captured delivery never expires, so
   crediting has to be guarded on stored state (`invoices.status`), not on the
   signature being valid.
8. **Foreign keys in scheduled jobs.** `hop_pairs` references `mesh_nodes`.
   The sweeper deletes dead nodes, and a 24h pair routinely outlives the node
   it names, so the delete has to clear dependent pairs first — otherwise it
   raises and takes the rest of the sweep (account expiry, device release)
   down with it.
9. **Platform-specific Go.** `wg_unix.go` / `wg_windows.go` are build-tagged.
   `checkRoot()` returns nil on Windows (UAC handles elevation), requires
   euid 0 on Unix. Always cross-compile all 6 targets after touching wg or gui.

## Discipline for a privacy product

This is a product whose entire value is trustworthiness. Two rules that
overrode convenience throughout:

- **Never make a claim the system doesn't back up.** If marketing/legal/audit
  text says X, the code must do X and audit-verify.sh must prove it.
- **Prefer the honest, specific, falsifiable statement** over the vague
  reassuring one — in docs, legal pages, and the warrant canary alike.

## Current state & what's left

**Done and validated:** control plane, 6-platform CLI, browser GUI, Windows
MSI source, Linux .deb + AppImage (deb build tested), complete Android app,
BTCPay integration, warrant canary, RAM-only node bootstrap with egress
hardening, no-logs audit pack + machine-checkable verifier, Tor onion mirror,
encrypted DB backup + DR runbook, abuse/DMCA runbook, legal pages
(privacy/terms), full landing site with app showcase.

**Remaining — operator action, not engineering:**
1. Provision 5 VPSes (control plane, BTCPay, 3 mesh nodes), run the bootstraps
   (docs/LAUNCH.md is the day-by-day playbook).
2. Generate keys: release-signing PGP, support PGP, age backup key. Replace the
   `DEADBEEF` placeholders in web/download.html, web/security-policy.html, and
   scripts/verify-release.sh with real fingerprints.
3. Compile signed installers on real toolchains: MSI (Windows host), APK
   (Android Studio), .deb/AppImage (Linux host — scripts ready).
4. Legal review of privacy.html + terms.html; set the operating entity name.
5. Commission a third-party audit (Cure53 / Assured AB) — the audit pack is
   built to be their starting point.

**Explicit v0.2 backlog:** system tray icon, native desktop window, branded
iOS app, APT repo for auto-updates, a macOS kill switch (pf, not iptables).

## Conventions

- Keep changes minimal and targeted; this codebase is deliberately lean.
- After any change, run the full validation battery above before declaring done.
- Prose in docs and legal pages avoids over-formatting; match the existing
  voice (direct, specific, honest about limitations).
- When adding a mesh region, it flows from the live `mesh_nodes` table — the
  API's /regions endpoint and REGION_NAMES dict derive from it. Add the display
  name to REGION_NAMES in api/main.py.
