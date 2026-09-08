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
                payments.py (watch / BTCPay / hosted / card providers),
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
mobile/android/                   Complete Kotlin/Compose app (wireguard-android).
                                  gradlew + wrapper jar committed; syntax-check.sh
                                  parses the Kotlin with no Android SDK present.
mobile/ios/                       SwiftUI app + WireGuardKit packet-tunnel
                                  extension. project.yml (XcodeGen) generates
                                  the .xcodeproj; syntax-check.sh is a
                                  STRUCTURAL check, not a compile.
installer/windows/                WiX v4 MSI (0trust.wxs), build.ps1,
                                  resources/make-icon.py -> the committed .ico
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
                                   node bootstrap and the test installer),
                                  preflight.sh (launch gate: is the DEPLOYMENT
                                   finished, as opposed to the code),
                                  generate-keys.sh (the four keys, on the
                                   operator's own machine — never the server),
                                  check-wallet.sh (derive and eyeball the
                                   receive addresses before taking money)
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
- **Operating entity: `0trust GmbH`, jurisdiction Switzerland** (chosen
  2026-09-05). Recorded in `web/.well-known/security.txt`, which terms.html §9
  makes the governing law of the contract. It was `0trust INC.` while the
  jurisdiction was undecided; INC. is not a company form that exists under
  Swiss law, so the two lines together were a self-contradiction in a binding
  clause. `test_audit.py` now checks the entity's form against its own
  jurisdiction and that the name does not drift between security.txt,
  AUDIT.md and LAUNCH.md. **This must match the Handelsregister entry exactly
  once registered, canton included** — the strings are set, the company is
  not. Jurisdiction remains a different question from where the servers are;
  see docs/AUDIT.md §2.6.
- **The Bitcoin xpub is NOT recorded here, deliberately.** It used to be. An
  extended public key reveals the wallet's entire balance and transaction
  history to anyone holding it, forever — you cannot rotate one without moving
  the funds — so committing the live key to a repository puts the operator's
  finances on display to everyone with read access. It lives in `WALLET_BTC`
  in `/etc/0trust/api.env` on the control plane and nowhere else.
  `install.sh --wallet <zpub>` puts it there and validates it on the way in;
  `scripts/check-wallet.sh` derives the first addresses from whatever is
  configured so a human can compare them against the wallet. Do that
  comparison: a wrong key issues addresses the operator cannot spend, and
  nothing anywhere reports an error.
- **The wallet's IDENTITY is pinned, in `scripts/wallet.pin`** — the SHA-256 of
  the chosen extended public key and nothing else. A digest reveals nothing
  about the wallet and still catches the realistic mistake: a truncated or
  wrong-account paste derives perfectly valid addresses belonging to somebody
  else. `check-wallet.sh` exits 3 on a mismatch, and `install.sh --wallet`,
  `scripts/preflight.sh` and `btcpay/scripts/configure.sh` all refuse on it.
  The operator wallet chosen 2026-08-25 is
  `sha256:ac5863cea1b0c134fab8740a50247f1a8e3e6c03c049eaaf01d42377f4bcf484`
  (BIP84, bc1q…). Re-pin with `check-wallet.sh --pin <key>`; never paste the
  key into a file that git tracks. **No extended key belongs anywhere in this
  tree** — `test_audit.py` greps for one, and it has caught a real example key
  in a copy-pasteable runbook command once already.
- **Three mesh nodes only**, all outside Five/Nine/Fourteen Eyes:
  - `zur` = Zurich, Switzerland
  - `rey` = Reykjavik, Iceland
  - `buc` = Bucharest, Romania
  (Norway was rejected earlier — it's in Nine Eyes. Romania replaced it.)
  **These region codes must be identical everywhere** — CLI, GUI, Android,
  iOS app, API defaults, docs, landing-page terminal demo.
- **Currencies: BTC, XMR, ZEC, ETH** (LTC was dropped; ETH was dropped and
  then re-added). The codes live in `payments.CURRENCIES`, the BTCPay checkout
  config, and web/index.html's crypto tabs — keep them in step.
  **But what a deployment can actually take depends on its provider**, and
  `currencies_for()` is the authority: `watch` returns BTC alone, card
  providers return "USD (card)", everything else returns all four. The
  checkout replaces its tabs from `/api/v1/payment/{id}/methods`, and the
  static copy is written for the FLOOR — what `currencies_for("watch")` can
  take, i.e. Bitcoin — because that is the state a fresh install launches in.
  A page may upgrade itself from `/api/v1/config`; index.html does. Never
  write a coin into copy that the default provider cannot issue an address
  for: `test_site.py` fails on it, and it once shipped a MONERO ACCEPTED
  ticker over a deployment that could only take BTC.
- **The `watch` provider takes BTC, ZEC and XMR, and the three do NOT work
  the same way.** BTC and ZEC derive a fresh address per invoice from the
  operator's extended PUBLIC key (`chainwatch.py`) and ask a public explorer
  whether it was paid — Esplora for BTC (`NODE_RPC_BTC`), Blockchair or
  Esplora for ZEC (`NODE_RPC_ZEC`), the reader chosen from the URL. **Zcash
  means TRANSPARENT t1 addresses only**; shielded ones cannot be derived from
  a public key or seen by an explorer, and are never offered.
  **Monero has neither.** The chain publishes no recipient and no amount, so
  no explorer can answer for it — detection needs the private view key and a
  block scan. `monerowatch.py` talks JSON-RPC to a view-only
  `monero-wallet-rpc` (`MONERO_WALLET_RPC`) pointed at a public remote node:
  no chain on disk, no spending authority, a subaddress per invoice allocated
  by the wallet. Never write a Monero scanner here.
- **Atomic units are per coin: 1e8 for BTC and ZEC, 1e12 for XMR**
  (`payments.COIN_UNITS`). The poller hardcoded 1e8, which made a dust
  payment settle a whole XMR invoice. Never compare amounts as floats.
- **Confirmation depth is enforced, per coin, and it is not the same as
  "in a block".** `ZTV_BTC_CONFIRMATIONS` (1), `ZTV_ZEC_CONFIRMATIONS` (5) and
  `XMR_CONFIRMATIONS` (10) decide when an invoice credits. Only Monero honoured
  its setting; BTC and ZEC read an explorer's `chain_stats`, which counts a
  transaction from the moment it is mined, so Zcash credited one block deep
  while the dashboard label said five. Depth costs an extra explorer call
  (`/blocks/tip/height` plus the address's txs for Esplora, `utxo[].block_id`
  against `context.state` for Blockchair) and is taken only when the operator
  asked for more than one. `/api/v1/config` publishes `confirmations` so no
  page restates the numbers — the site used to say "activates on the first
  confirmation", which was false for two of the three coins.
- **The default provider is `watch`, defined once in
  `payments.DEFAULT_PROVIDER` and read through `payments.provider_name()`.**
  The literal `"btcpay"` was the fallback at six call sites and in
  `systemd/api.env.example`, so an operator who copied the example, or who
  lost the line, got a provider they had not configured — and
  `poll_invoices.py` returns immediately unless the provider is `watch`, so
  that deployment took real payments and credited none of them.
- **`currencies_for("watch")` asks the provider, and the provider asks the
  configuration.** A coin with no wallet behind it is not offered — otherwise
  the checkout sends a customer to an address that does not exist. Adding a
  coin means adding a wallet setting AND a way to be told it was paid.
- **USD conversion is its own dependency** (`ZTV_PRICE_API`, Kraken by
  default). It used to come from Esplora's `/v1/prices`, which only
  mempool.space serves — pointing `NODE_RPC_BTC` at another Esplora silently
  broke invoice creation while address lookups kept working.
- **No self-hosted blockchain node.** `ZTV_PAYMENT_PROVIDER` picks between
  `watch` (default: derive a receive address per invoice from the operator's
  own xpub and confirm via a public explorer — non-custodial, no account
  anywhere, no chain data; BTC and ZEC by explorer, XMR by view-only wallet,
  whichever have a wallet configured), `btcpay` (your own or somebody else's
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
- **iOS:** the branded app was built on explicit go-ahead (2026-09-04). The
  source under `mobile/ios/` is complete — SwiftUI app plus a WireGuardKit
  packet-tunnel extension, `project.yml` generates the Xcode project — but
  **nothing has ever compiled it**: there is no Swift toolchain in the build
  environment and SwiftUI/NetworkExtension have no Linux SDK. Treat the first
  `xcodegen generate && xcodebuild` on a Mac as the real gate and expect to fix
  compile errors there. Shipping it still needs the Apple Developer Program,
  the `packet-tunnel-provider` entitlement (a request to Apple, weeks, can be
  refused) and App Review. Until then QR-export into the official WireGuard app
  remains the supported iOS path, and the download page must not promise an
  iOS app that cannot be installed.
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
- **A node joins the mesh by registering itself, never by hand-written SQL.**
  `install.sh --mode node` on a fresh Ubuntu 24.04 VPS does the whole thing:
  RAM-only hardening, a keypair generated in tmpfs, `POST /api/v1/node/provision`
  with a token minted on the control plane, meshd, NAT, egress filter, resolver.
  `scripts/bootstrap-node.sh` remains the manual path for a node you want to
  name yourself, and it still prints an INSERT for the operator to run.
- **A reboot must be a rejoin, not an outage.** The node's disk is tmpfs, so a
  restart loses its WireGuard key, its node id and its PSK — and a one-shot
  provisioning token cannot bring it back. `provision_tokens.max_uses > 1`
  mints an enrolment token instead: pinned to the node's public IP on first
  use (`bind_ip`), re-registering the SAME node id thereafter rather than
  accumulating a row per boot, and revocable (`revoked_at`). It lives in
  `/etc/0trust-node.env`, the one 0trust file deliberately on persistent disk.
  `scripts/node-enroll.sh` runs on every boot, before meshd.
- **NAT and the egress filter are kernel state that nothing replays.**
  `/etc/nftables.conf` does not include `/etc/nftables.d`, so an exit node came
  back from a reboot doing no masquerading — customer traffic entered the
  tunnel and died silently while meshd went on heartbeating over its own
  outbound HTTPS. `scripts/node-runtime-apply.sh` reapplies them at boot, via
  the enrolment unit on a RAM node and `0trust-node-runtime.service` on a
  manual one.
- **A node's registered endpoint carries the port it actually listens on.**
  `/api/v1/node/provision` used to write `:51820` regardless of `wg_port`, so
  a node on any other port was advertised at an address nothing answered on —
  and looked healthy the whole time, because the heartbeat is a separate
  outbound call.
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
- **Upstream DNS leaves a node over TLS, or not at all.** dnsmasq's only
  forwarder is a local stubby stub (`ZTV_DNS_STUB`, 127.0.0.1#5353) doing
  DNS-over-TLS to Quad9, authenticated by certificate name — not a pinned
  key, so nothing goes stale, and no resolver list to fetch at boot. It
  forwarded straight to 9.9.9.9 on UDP 53 before, which meant the tunnel
  encrypted the customer's half of the path and published the other half.
  If TLS cannot be established the lookup FAILS; there is deliberately no
  cleartext retry, because a silent downgrade is the same leak unnoticed.
  `ZTV_DNS_ENCRYPTED=0` reverts, loudly, in a comment in the config.
  privacy.html §4d, `docs/AUDIT.md`'s third-party table and
  `node-dns-encrypted-upstream` all state this and must move together.
- **Nodes run plain WireGuard: no obfuscation, and DPI identifies it.** Never
  let copy imply otherwise. What exists is port-level camouflage
  (`--wg-port 443`, recommended, blends with QUIC in netflow), WireGuard's own
  silence to unauthenticated packets, a jittered meshd check-in
  (`ZTV_POLL_JITTER`) so the beacon is not metronomic, and keepalive chatter.
  Obfuscation proper is v0.2 and is a client change as much as a node one.
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
- **`scripts/install.sh` GENERATES the nginx config; `nginx/0trustvpn.com.conf`
  is a reference file it has never installed.** Anything added to the
  reference and not to `render_zones`/`render_common_locations`/the server
  blocks does not exist on a deployed box. That gap held the worst
  claim-vs-reality defect in the product: no `log_format`, no `access_log`,
  no anonymizing map and no logrotate meant a real deployment fell through to
  nginx's stock `combined`, keeping full client IPs, User-Agents and Referers
  for fourteen rotations while privacy.html said the IP was truncated to a
  /24 before it was written. The CSP header and the `/canary.txt` no-store
  block were missing the same way — a cached canary cannot stop appearing,
  which is the only thing a canary does. `test_install.py` [3b] now asserts
  the privacy properties of the RENDERED bytes, and audit-verify reads
  `sites-enabled/0trust` and `conf.d/0trust-zones.conf`, the names the
  installer actually writes.
- **The request path is a secret on two routes, so nothing logs it.**
  `DELETE /api/v1/devices/{pubkey}` carries a customer's WireGuard key and
  `GET /api/v1/payment/{invoice_id}/status` carries a bearer capability, so
  both uvicorn (`--no-access-log` in `0trust-api.service`) and nginx (the
  `$uri_anon` map, not `$uri`) have to drop the secret segment. It leaked in
  both places at once for months while privacy.html said device keys never
  appear in our logs and AUDIT.md claimed the access lines were "filtered out
  at the log-format level" — nothing did any filtering. `api-no-access-log`
  and `nginx-log-no-secret-paths` are the gates; `api-log-no-pubkeys` now
  matches a key in either encoding, having previously matched only the JSON
  shape, which is the one place a key is never logged.
- **An `async def` handler must not block.** FastAPI runs a plain `def` in
  the threadpool and an `async def` on the event loop, so a blocking call in
  the second one stalls every other request on that worker. `/surf` was
  `async def` around a urllib fetch with a 12s-per-hop timeout — an
  unauthenticated GET froze the whole service. `payment_webhook` has to stay
  async to read the raw body for its signature, so its blocking half goes
  through `run_in_threadpool`. Grep for `async def` before adding one.
- **Anything read from a third party is read with a cap.** The watch
  provider's whole design is that we run no chain, so settlement is a request
  to a public explorer — and the invoice address is published to whoever is
  paying, so dust-spamming it inflates that address's history for free.
  `payments.MAX_RESPONSE_BYTES` and the matching cap in `monerowatch` turn
  that into a `PaymentError` and a retry next minute. The Go client bounds
  its side too (`api.maxResponseBytes`).
- **An in-memory table keyed by anything an attacker picks has to be
  bounded.** `admin._login_attempts` is keyed by source address and attempted
  username and pruned only the key it was asked about, so an address seen
  once stayed forever — and one IPv6 /64 is 2^64 addresses. It sweeps above
  `_ATTEMPTS_SOFT_CAP` now, dropping aged-out counters first.
- **`ops_events` never holds customer data.** Node ids, provider names, counts
  and infrastructure detail only. It is the single table that keeps a running
  narrative of the system's state over time, so an account id in it turns it
  into the activity log privacy.html denies keeping. Alerts fire on
  *transitions*, not states, or the operator gets an hourly stream and silence
  stops meaning anything.
- **The GUI is browser-based, not native.** `0trust gui` runs a localhost web
  server; it's the same code on all 3 desktop OSes. No system tray (v0.2 —
  systray libs were blocked in the original build env). A second `0trust gui`
  finding the port taken hands the user the running instance instead of an
  error — the Start Menu shortcut, desktop icon and autostart entry all run
  the same command.
- **The Android app declares no VpnService of its own.** wireguard-android's
  `GoBackend` brings up its own, and Android resolves an app's always-on VPN
  service by requiring exactly *one* match on the `android.net.VpnService`
  intent filter — a second declaration silently makes Always-on VPN
  impossible to enable. `ZeroTrustVpnService` is a plain foreground service
  that owns the notification.
- **The mobile device keypair is generated once and persisted — both apps.**
  iOS keeps it in the keychain (`DeviceIdentity.loadOrCreate`), Android in
  encrypted preferences. Registration
  is idempotent on the pubkey, so a stored key means a reconnect reuses the
  same device and mesh IP. Generating one per connect — which it did — burns
  the account's device cap in a handful of connects and then locks the
  customer out. The app also has a device list and a delete for the same
  reason the CLI does.
- **User-facing product name is `0trustvpn`; the CLI binary is `0trust`.**
  Launcher label, Start Menu entry and ARP display name all say 0trustvpn;
  the executable, package files and release artifacts are named 0trust.

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

The Android app needs Android Studio Hedgehog+ and SDK 34 to build an APK
(`./gradlew assembleDebug`) — no NDK: `com.wireguard.android:tunnel` ships the
Go data plane prebuilt. The Windows MSI needs a Windows host with WiX
(`installer/windows/build.ps1`). Neither can be built in a headless Linux-only
environment, and Google's Maven repo is usually unreachable from one too, so:

- `mobile/android/syntax-check.sh` parses every Kotlin source with the real
  compiler front-end (downloaded from Maven Central), which catches anything
  malformed without the SDK. It must stay green.
- The `apps` emulation module checks what a compiler would not anyway: the
  Kotlin `@SerialName` keys against real JSON from a live control plane, the
  manifest invariants, and the MSI's referenced files and uninstall behaviour.

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
10. **Asserting on a clock-derived value across two reads.** `days_remaining`
   is computed from `now` on every request, so it ticks down on its own. A test
   that samples it, does some work, samples again and asserts equality passes
   only when both reads land in the same second — green locally, red on a
   loaded runner. It took CI red twice before anyone looked. Assert on
   `expires_at`, which is the absolute stored timestamp and cannot tick.
   `days_remaining` **rounds up**, so an active account never displays 0 days
   while it still has time left.
11. **Per-plan values hardcoded in a client.** The device cap is 8 paid, 2 on
   trial, and `/api/v1/account/status` publishes it as `max_devices`. Printing
   a constant told trial customers they had six slots spare until the next
   register returned 409. This shipped three times — the Android card,
   `0trust status`, `0trust devices` — so treat any literal `8` next to a
   device count as a bug. `/api/v1/devices` returns a bare list and carries no
   cap; it takes a second call.
12. **Prices and copy drifting from `PRICING`.** The landing page quotes
   $5/$13/$48 in `data-price` attributes and the API invoices from `PRICING` in
   `api/main.py`. `test_site.py` ties them together — terms offered, each
   price, and the hand-written "save $N" arithmetic, which is the figure most
   likely to go stale. Change one and the other must move.
13. **A test whose input is randomly generated tests a random subset.**
   `H.genkey()` returns a random base64 pubkey, and only about one in
   sixty-four begins with `+` — the one case where the admin search's
   space-restoration failed, because `.strip()` ate the leading space before
   anything could put it back. It passed twenty-three CI runs and failed the
   twenty-fourth, with nothing in the output explaining why. When a code path
   turns on a property of the input, construct an input that has it (and one
   that doesn't) instead of hoping the draw covers it. Same family as #10:
   green locally, red on a runner, for a reason the test never states.
14. **Ops tooling nothing has ever executed.** Everything under `scripts/`,
   `canary/` and `btcpay/` runs once, on the day it matters, on a box the
   operator is standing at. Rehearsing the launch path end to end found
   `generate-keys.sh` dying on an unbound variable; rehearsing the weekly
   canary on a day that was not a Monday found the period computed for the
   *next* week, an alarm firing a week before the deadline it guarded, and a
   systemd unit whose `ExecStart` no deploy step ever created. A green
   `systemctl enable` is not evidence: the timer reports active whether or not
   the service it triggers can exec anything. `test_canary.py`,
   `test_backup.py`, `test_install.py` and `test_release.py` exist to run
   these for real — extend them rather than trusting a script that parses.

15. **Assuming the host has IPv6.** Three separate installer aborts, all this
   one assumption, all found by RUNNING install.sh on a v4-only Ubuntu 24.04
   box rather than reading it. `nginx -t` binds every listener, so a stray
   `listen [::]` fails with "Address family not supported by protocol"; and
   `sysctl -p` fails on a key the kernel does not have, at install time and on
   every boot after. Each aborted part-way through, after packages, the
   service user, secrets and the database. `ZTV_NGINX_IPV6` and
   `ZTV_HAS_IPV6` force either branch so both are testable anywhere. Note the
   shape: the emulation suite had *worked around* the nginx one (nginx_check
   wraps `nginx -t` precisely because CI has no IPv6), so a green test sat on
   top of a broken install. A workaround in a test is a bug report about the
   product.
16. **An installer that reports success it did not verify.** `install.sh`
   printed a green "The VPN works" unconditionally. `systemctl enable --now`
   returning 0 says nothing about whether meshd created an interface, and on
   a kernel without WireGuard — ordinary on LXC and OpenVZ VPSes — it creates
   none. It now probes `ip link show` for each interface and the summary
   reports what it found. This is the standard `0trust connect` already holds
   itself to: wg-quick's exit code means nothing, so the client waits for a
   handshake before claiming a tunnel. Hold the deploy path to it too.
17. **A gate that cannot see the thing it is named after, or a SKIP standing
   in for a pass.** `api-log-no-pubkeys`
   grepped for `"pubkey": "<44 chars>"` — the JSON body shape — and passed
   green for months on a host writing device keys to journald in the URL,
   percent-encoded, where neither the prefix nor the `=` it matched on
   existed. `nginx_check` wrapping `nginx -t` (#15) is the same shape, and so
   was `audit-verify.sh` aging the canary by mtime. When you add or trust a
   check, break the thing on purpose and confirm the check goes red. A check
   nobody has watched fail is a check nobody has tested — and every fix in
   this file has a mutation behind it for that reason. Watch for the check
   matching its own explanatory comment, too: `grep -- '--no-access-log'`
   found the comment above the flag and passed with the flag deleted.
   And watch the SKIP path hardest of all — `audit-verify.sh`'s nginx checks
   read a filename the installer does not create, so `[[ -f … ]] || exit 77`
   fired on every real host and an auditor got a clean run against a
   deployment logging full client IPs. A SKIP is only honest when the thing
   genuinely does not apply; when the component is present and OUR config is
   the part that is missing, that is the finding.

18. **Dependency pins age into vulnerabilities on their own.** Nothing in the
   build goes red when a pin that was current becomes a CVE. `fastapi==0.115.0`
   resolved `starlette 0.38.6`, which by the time anyone looked carried nine
   advisories — two of them Host/path confusions that make `request.url`
   disagree with the path actually routed. `pip-audit -r api/requirements.txt`
   is the check; run it when touching the pins and periodically regardless.
   Upgrading FastAPI is also when `@app.on_event` finally disappears, which
   fails as "no such table" on the first request rather than as anything
   naming the framework — the app uses `lifespan=` for that reason.

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
2. Generate keys on your own machine: `./scripts/generate-keys.sh`. Then
   publish them with `./scripts/set-fingerprints.sh --release … --canary …
   --support …`, which puts each key where it belongs and refuses a malformed
   fingerprint, the DEADBEEF placeholder, or any key the machine does not
   hold. **The three are not interchangeable**: security-policy.html publishes
   the SUPPORT key, the one people encrypt vulnerability reports to — a
   signing key there has no encryption subkey and reporters cannot use it.
   `./scripts/set-fingerprints.sh --check` reports what is still outstanding.
3. Compile signed installers on real toolchains: MSI (Windows host —
   `installer/windows/build.ps1 -Version X -SignWith "<cert>"`), APK
   (Android Studio), .deb/AppImage (Linux host — scripts ready).
4. Legal review of privacy.html + terms.html **and
   `canary/templates/canary.txt`** — the canary swears to specific
   instruments (BÜPF/VÜPF, NDG, NSL, FISA) and is the one document
   written to be relied on when it stops appearing. The entity name is
   set (`0trust GmbH`); it must match the Handelsregister entry.
5. Commission a third-party audit (Cure53 / Assured AB) — the audit pack is
   built to be their starting point.

**Explicit v0.2 backlog:** system tray icon, native desktop window, APT repo
for auto-updates, a macOS kill switch (pf, not iptables). The iOS app moved out
of the backlog and into `mobile/ios/`; what remains for it is a Mac, a
Developer account and Apple's entitlement approval, not engineering.

## Conventions

- Keep changes minimal and targeted; this codebase is deliberately lean.
- After any change, run the full validation battery above before declaring done.
- Prose in docs and legal pages avoids over-formatting; match the existing
  voice (direct, specific, honest about limitations).
- When adding a mesh region, it flows from the live `mesh_nodes` table — the
  API's /regions endpoint and REGION_NAMES dict derive from it. Add the display
  name to REGION_NAMES in api/main.py.
