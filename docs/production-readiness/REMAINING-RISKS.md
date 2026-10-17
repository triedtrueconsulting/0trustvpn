# Remaining risks

Audit date 2026-10-17. Ordered by what would cost the most if it went
wrong, not by likelihood.

This list is deliberately not reassuring. A privacy product's risk register
is only useful if it is honest about what has not been proven.

---

## R1 — Two extended public keys are in git history, provenance unknown
**Severity: HIGH · Status: OPEN · Owner: operator · Blocking: yes**

See SECURITY-AUDIT.md SEC-1. Recorded by digest in
`scripts/secret-scan.known`.

If either key came from a seed the operator controls, that wallet's entire
balance and payment history is readable by everyone who has ever cloned
this repository, permanently. An extended public key cannot be rotated.

**Mitigation in place:** detection. The scan now reads history, the two are
reprinted as outstanding on every run, and a new one fails the build.
**Mitigation absent:** the exposure itself. Only the operator can close it,
by confirming provenance and moving funds if required.

**Do not treat a history rewrite as the remedy.** The repository has been
pushed; the blobs are already distributed.

## R2 — No part of the WireGuard data path has ever carried a real packet
**Severity: HIGH · Status: OPEN · Owner: operator · Blocking: yes**

No WireGuard kernel module exists in any environment that has run this
code, so no handshake has ever completed, no tunnel has ever carried
traffic, and MTU, DNS leak, IP leak and kill-switch behaviour are all
unverified. See WIREGUARD-TEST-RESULTS.md §1 and §5.

What *has* been verified against a real kernel is substantial and should
not be discounted: the nftables rulesets meshd and the node runtime
generate are loaded by the real `nft` and have real packets pushed through
them, including the multi-hop privacy property that the exit must not see
the client, NAT66, and peer isolation. 107 assertions across three
namespace modules.

But "the firewall rules are right" and "the tunnel works" are different
claims, and only the first is established.

**Mitigation:** the product already refuses to overclaim here — `0trust
connect` waits for a handshake rather than trusting `wg-quick`'s exit code,
and `install.sh` probes `ip link show` rather than trusting
`systemctl enable --now`. Those gates have to be exercised on real
hardware before launch.

## R3 — Neither mobile app has ever been built or run
**Severity: HIGH · Status: OPEN · Owner: operator · Blocking: for those platforms**

**iOS:** nothing has ever compiled it. There is no Swift toolchain in any
build environment and SwiftUI/NetworkExtension have no Linux SDK. The first
`xcodegen generate && xcodebuild` on a Mac is the real gate and compile
errors should be expected. Shipping additionally needs the Apple Developer
Program, the `packet-tunnel-provider` entitlement (a request to Apple,
weeks, refusable) and App Review. **There is no unsigned fallback on iOS** —
unlike Windows, where the MSI ships unsigned on purpose.

**Android:** the Kotlin parses and the app's own copy of the obfuscation
transport is compiled and executed against the real Go relay by CI. But
nothing has run the integration on a device: the endpoint rewrite reaching
GoBackend, the split AllowedIPs actually keeping the relay's socket out of
the tun, and the MTU have never run anywhere.

Expect the AllowedIPs routing exclusion to be the part that needs
attention. Its two failure directions are not symmetric — too little
excluded loops the tunnel loudly, too much routes a slice of the internet
**outside** the VPN silently — and the first version was wrong in the
dangerous direction while passing its test, because `0.0.0.0` is the one
input where setting a bit and flipping it are the same thing.

Until the iOS app ships, QR export into the official WireGuard app is the
supported iOS path and the download page must not promise otherwise.

## R4 — The Android obfuscation transport is a second implementation
**Severity: MEDIUM · Status: MITIGATED, not eliminated · Owner: engineering**

`ObfsCrypto.kt` / `ObfsRelay.kt` cannot call the Go binary, because
wireguard-android brings the tunnel up inside the app process. Two
implementations of one wire format can disagree, and a disagreement is a
tunnel that silently will not come up in the one country where the customer
needed it.

**Mitigation:** those files and `AllowedIps.kt` carry no `android.*`
reference, so CI compiles them on a plain JVM and pushes real packets
through the real `0trust-obfs` binary. A mutation changing the HKDF info
string turns that check red.

**The mitigation is fragile in a specific way:** adding an Android import to
those files deletes the only test that ever executes the app's copy of the
transport. That is a one-line change a future contributor could make
innocently.

## R5 — Ops tooling that runs once, on the day it matters
**Severity: MEDIUM · Status: PARTIALLY MITIGATED · Owner: engineering**

Everything under `scripts/`, `canary/` and `btcpay/` runs once, on a box
the operator is standing at, usually under time pressure. Rehearsing these
has already found `generate-keys.sh` dying on an unbound variable, the
canary computing the period for the wrong week, an alarm firing a week
early, and a systemd unit whose `ExecStart` no deploy step ever created.

`test_canary.py`, `test_backup.py`, `test_install.py` and `test_release.py`
exist to run these for real. They are good, and they are not the same as
having done it on a VPS.

**A green `systemctl enable` is not evidence.** A timer reports active
whether or not the service it triggers can exec anything.

## R6 — A CDN that terminates TLS sits in front of the API
**Severity: MEDIUM · Status: ACCEPTED AND DISCLOSED · Owner: operator**

If `/api/v1/` is on a Cloudflare-proxied hostname, Cloudflare reads
everything it fronts, including `X-Account-Token` — which is the entire
credential, since there is no second factor and no session.

This is a genuine trust delegation, not a control. It is disclosed in
privacy.html §5a and AUDIT.md §9, and a gate fires both ways: behind a CDN
with no disclosure, and disclosing one that is not there.

**The decision to accept it belongs to the operator, not to the code.**
`docs/DEPLOY.md` carries the proxy-the-API decision. Leaving the API on an
unproxied hostname removes this risk and the DDoS protection together.

## R7 — Obfuscation is opt-in on both ends and the default is detectable
**Severity: MEDIUM · Status: BY DESIGN · Owner: product**

Plain WireGuard is what DPI identifies, and that is the default. A node
runs the relay only with `--obfs-port`, and a customer uses it only with
`--obfuscate` or the GUI switch.

The risk is not technical; it is **copy drift in either direction**. A
customer who believes they are obfuscated and is not may act on that belief
in a country where it matters.

**Mitigation:** the setting and the fact are separate values everywhere
(`Obfuscate` vs `RelayActive`, `boot.obfuscate()` vs
`obfuscationActive`), and a node without a relay produces a direct tunnel
that *says so* rather than connecting as though the request had been
honoured. `docs/DEPLOY.md` states all four limits and `test_node.py` fails
if any goes missing. iOS has no switch at all and its copy must not mention
DPI protection.

## R8 — Legal and tax matters with no code behind them
**Severity: MEDIUM · Status: OPEN · Owner: operator + lawyer/accountant · Blocking: yes**

- Legal review of privacy.html, terms.html **and
  `canary/templates/canary.txt`**. The canary swears to specific
  instruments (BÜPF/VÜPF, NDG, NSL, FISA) and is the one document written
  to be relied on when it stops appearing.
- The entity name `0trust GmbH` is set in the code and must match the
  Handelsregister entry exactly, canton included. The strings are fixed;
  the company is not yet registered.
- **VAT.** A Swiss GmbH selling a digital service to EU consumers owes VAT
  in the customer's country, and this product deliberately does not know
  which country that is. Whether pricing is VAT-inclusive is a decision to
  take **before the first sale**.
- Whether an art. 27 EU representative is required.

These are in `docs/REQUESTS.md` and are not engineering.

## R9 — Single control plane, single SQLite database
**Severity: MEDIUM · Status: ACCEPTED · Owner: operator**

One host, one file. The database is the only record of what each customer
paid for — a token cannot rebuild an expiry.

**Mitigation:** encrypted backups with the age public key only, `api.env`
included in the backup set (without it a restored control plane cannot
authenticate its nodes or verify a webhook: the database comes back and the
service does not), and a tested DR runbook.

**Residual:** the recovery time is however long it takes a human to notice
and provision. There is no standby.

## R10 — No third-party audit has been performed
**Severity: MEDIUM · Status: OPEN · Owner: operator**

This audit was performed by the same agent that wrote part of the code
under review. That is a structural conflict and no amount of rigour removes
it. The audit pack in `docs/AUDIT.md` is built to be an external auditor's
starting point; commissioning one (Cure53, Assured AB) remains outstanding.

## R11 — Dependency pins age into vulnerabilities on their own
**Severity: LOW · Status: MITIGATED · Owner: engineering**

Nothing in the build goes red when a current pin becomes a CVE.
`fastapi==0.115.0` once resolved a Starlette carrying nine advisories, two
of them Host/path confusions that make `request.url` disagree with the path
actually routed — which, on a service whose logging guarantees depend on
the request path, is directly load-bearing.

`pip-audit` is now a battery check (`deps-audit`) and currently reports no
known advisories. **`govulncheck` could not be run** — `vuln.go.dev` is
blocked by this environment's proxy — so the Go side is unverified against
the advisory database. The surface is one pure-Go module plus stdlib on
go1.24.7.

## R12 — The `/surf` proxy is unauthenticated and takes a URL from anyone
**Severity: LOW · Status: MITIGATED BY DESIGN · Owner: engineering**

It is the only endpoint of its kind in the product, it runs as a separate
service on a separate port so it can be killed without touching the control
plane, and `proxy/guards.py` is the entire security argument.

The history here is instructive about where the next bug will be: the CSP
contains a proxied page's subresources but not its navigation, so a `<meta
http-equiv="refresh">` walked visitors to the origin under our banner. The
lesson recorded in the code is that anything else a page can use to
navigate itself belongs in `rewrite.py`, not in the CSP.

## R13 — Backlog items a customer may expect to exist
**Severity: LOW · Status: KNOWN · Owner: product**

No macOS kill switch (the client says so rather than pretending), no system
tray, no native desktop window, no APT repo for auto-updates, and no
obfuscation mode that survives a total UDP block — the relay is UDP in, UDP
out, and `docs/DEPLOY.md` states that limit.

The risk is a customer in a UDP-blocked network believing obfuscation will
help. It will not.

---

## What would change the release decision

R1 and R2 are the two that block. R3 blocks the mobile platforms
specifically but not a desktop-and-CLI launch. R8 blocks taking money.

Everything else is either accepted with disclosure, mitigated with a gate,
or scheduled.
