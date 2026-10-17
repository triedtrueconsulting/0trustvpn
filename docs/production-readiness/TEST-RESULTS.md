# Test results

Audit date 2026-10-17. Every number here came from a command run in this
environment on this commit. Where something could not be run, it says so
rather than being omitted.

---

## 1. Headline

| | |
|---|---|
| `./scripts/validate.sh` | **26 passed, 0 failed, 0 skipped** |
| Emulation suite | **2,389 assertions, 0 failed**, across 30 modules |
| Active security probe (written for this audit) | **48 assertions, 0 failed** |
| SAST (`tests/sast/ztv.yml`, 8 rules) | **0 findings** |
| Secret scan (tree + 1,096 blobs over 152 commits) | **0 new**, 2 known exposures outstanding |
| `pip-audit -r api/requirements.txt` | **No known vulnerabilities** |
| `govulncheck ./...` | **COULD NOT RUN** — `vuln.go.dev` blocked by proxy |

Baseline before this audit: 23 passed, 1 failed of 24 checks. Both failing
modules failed on an external-DNS dependency, not a product defect; both
are now hermetic.

## 2. The battery

```
$ ./scripts/validate.sh
  PASS  go-vet                 go vet across the client
  PASS  go-test                go test ./...
  PASS  go-fmt                 client is gofmt clean
  PASS  go-crosscompile        all six release targets build
  PASS  deb-package            .deb builds for amd64 + arm64
  PASS  py-parse               every .py parses
  PASS  api-smoke              control plane end-to-end
  PASS  deps-audit             runtime deps carry no known advisories
  PASS  emulation              full-stack emulation suite
  PASS  sh-syntax              every .sh parses
  PASS  html-parse             web pages + GUI assets parse
  PASS  xml-parse              Android res, MSI source, SVGs parse
  PASS  plist-parse            iOS plists and entitlements parse
  PASS  swift-structure        Swift sources are structurally sound
  PASS  ios-fonts              bundled iOS faces are the ones the app asks for
  PASS  seo-sitemap            sitemap.xml covers the routed pages and is current
  PASS  seo-jsonld             structured data matches the pages and the API's prices
  PASS  vendor-integrity       vendored third-party JS matches its pinned hashes
  PASS  secret-scan            no new secrets in the tree or in git history
  PASS  sast                   no async-blocking, unbound SQL, or fail-open TLS
  PASS  gui-favicon            the GUI favicon matches its generator
  PASS  json-parse             every .json parses
  PASS  yaml-parse             cloud-init node image parses
  PASS  regions-current        only zur/rey/buc appear as regions
  PASS  pipefail-head          no pipeline can die of SIGPIPE under pipefail
  PASS  auth-header            clients send X-Account-Token, never Bearer

  26 passed, 0 failed, 0 skipped
```

`secret-scan` and `sast` are new in this audit.

## 3. Emulation suite, per module

| Module | Assertions | |
|---|---:|---|
| test_site | 384 | 0 failed |
| test_install | 324 | 0 failed |
| test_admin | 168 | 0 failed |
| test_ios | 137 | 0 failed |
| test_watchpay | 124 | 0 failed |
| test_gui | 92 | 0 failed |
| test_lifecycle | 87 | 0 failed |
| test_proxy | 86 | 0 failed |
| test_audit | 79 | 0 failed |
| test_node | 79 | 0 failed |
| test_obfs | 79 | 0 failed |
| test_apps | 74 | 0 failed |
| test_client | 73 | 0 failed |
| test_admin_ui | 61 | 0 failed |
| test_payments | 56 | 0 failed |
| test_release | 54 | 0 failed |
| test_routing | 54 | 0 failed |
| test_security | 49 | 0 failed |
| test_proxy_guards | 41 | 0 failed |
| test_canary | 39 | 0 failed |
| test_site_ui | 34 | 0 failed |
| test_backup | 33 | 0 failed |
| test_meshd | 28 | 0 failed |
| test_trial | 28 | 0 failed |
| test_multihop_netns | 27 | 0 failed |
| test_funnel | 26 | 0 failed |
| test_onebox_netns | 26 | 0 failed |
| test_chainwatch | 25 | 0 failed |
| test_concurrency | 15 | 0 failed |
| test_integration | 7 | 0 failed |
| **TOTAL** | **2,389** | **0 failed** |

`test_install` rose from 315 to 324 — the iproute2 block in §9b.
`test_payments` rose from 37 to 56 in this audit — the money-path abuse
block. `test_audit` rose from 68 to 79 — the history-aware secret scan and
its mutation test.

## 4. Real-kernel network testing

`test_multihop_netns` (27), `test_onebox_netns` (26) and `test_routing`
(54) — 107 assertions — run against real network namespaces, real veth
pairs and rulesets loaded by the real `nft` binary. Full breakdown in
WIREGUARD-TEST-RESULTS.md §2.

The properties established include the one the product's multi-hop claim
rests on: **the exit node does not see the client**, tested by sending a
packet and reading what arrives.

## 5. Security probe written for this audit

48 assertions, 0 failures. Covered: authentication and authorization
boundaries, cross-account device access, node-endpoint scoping, hostile
WireGuard key ingest (including the exact 44-character newline-injection
shape), region and multi-hop validation, price and quantity manipulation,
token entropy and storage, and invoice-id capability entropy.

Every initial failure in this probe turned out to be a defect in the probe,
and each was verified against the code before being dismissed. Details and
the one case that deserved real scrutiny — the deliberately unauthenticated
payment-status route — are in WIREGUARD-TEST-RESULTS.md §3.

The reusable parts are now committed in `test_payments.py` rather than left
as a scratch script.

## 6. Static analysis

```
$ semgrep --metrics=off --config tests/sast/ztv.yml api proxy wireguard btcpay canary support
Ran 8 rules on 15 files: 0 findings.
```

`semgrep.dev` is unreachable from this environment, so the registry packs
could not be fetched and these are local rules encoding this codebase's own
documented bug classes.

All eight rules were mutation-tested against planted violations. Two were
dead on arrival and only discovered that way — semgrep matches an f-string
as a single value and will not match a quote-then-interpolation inside one,
and a `|` YAML block scalar keeps a trailing newline that semgrep matches
literally. The gate itself was then mutation-tested end to end: a blocking
`sleep` and `urlopen` planted in a real `async def` turned it red, naming
file and line; restoring turned it green.

19 SQL-interpolation candidates from a broader first-pass rule were read
individually and all were safe — literal fragments with bound parameters,
generated placeholder lists, or DDL identifiers from module constants. The
rule was narrowed rather than kept, because a gate that is always red gets
switched off.

## 7. Secret scanning

```
$ ./scripts/secret-scan.sh
   321 files scanned (tracked + untracked, excluding gitignored)
   1096 blobs scanned across 152 commits
   gitleaks: clean (no findings outside the register)

── KNOWN EXPOSURES — outstanding operator action ─────────
  sha256:2ca1d13600a428db…
  sha256:37dc8c2ee9531e53…

No NEW secrets. 2 known exposure(s) still outstanding above.
```

The two known exposures are **not resolved** — see SECURITY-AUDIT.md SEC-1.
They are reprinted every run rather than failing the gate, because a
permanently red gate gets switched off and then the next secret goes in
unnoticed.

Mutation-tested: a key committed and then deleted in a throwaway repository
is caught by the history scan while `git grep` over the tree passes, which
is the exact gap that hid these two. The PGP, age and WireGuard rules were
each planted and watched going red, and a clean control passes.

## 8. Dependency scanning

```
$ pip-audit -r api/requirements.txt
No known vulnerabilities found
```

**`govulncheck` could not be run.** `vuln.go.dev` returns 403 through this
environment's proxy. The Go surface is one third-party module
(`skip2/go-qrcode`, pure Go, used only to render a QR of a config the
product generated itself) plus stdlib, built with go1.24.7. This is a real
gap and is listed in REMAINING-RISKS.md R11; it must be run from a host
with access before launch.

## 9b. A real install, and audit-verify against it

`install.sh --mode test` was run for real on this container. It stopped
loudly at `systemctl` (no systemd here, `RC=1`) after completing packages,
users, code, venv, secrets, database, units, website and nginx — and with
`systemctl` stubbed to simulate an LXC VPS it completed while still
reporting `nginx is NOT serving on port 80` and `The VPN is NOT up`. It
probes rather than trusting the service manager. Full detail, including the
customer flow driven against the installed stack, is in
WIREGUARD-TEST-RESULTS.md §3b.

Against that real deployment:

```
audit-verify.sh:  PASS: 28    FAIL: 2    SKIP: 11
```

The nginx privacy checks pass **against the deployed config** rather than
the reference file. The two failures are the verifier working on a test rig
— three nodes sharing a TEST-NET-1 address are correctly called
placeholders, and `cdn-disclosed` correctly fires because privacy.html
names a CDN this deployment is not behind.

That run also found two installer defects, now fixed: a `set -e` +
`pipefail` abort that killed the script mid-install on a host without
iproute2, one line before its own fallback, and a probe that reported a
missing package as a kernel limitation — fatal on `--mode node`, so it
would send an operator to buy a different VPS.

## 9. `audit-verify.sh` in a bare repository

```
PASS: 13    FAIL: 1    SKIP: 27
```

The single FAIL is `nginx-conf-exists`, and **it is the check working
correctly**. nginx is installed in this container (for earlier testing) but
no 0trust site config exists, because this container is not a deployed
control plane. The check deliberately refuses to skip in that situation:

> A SKIP here is only honest on a box with no nginx at all. If nginx is
> installed and our config is not the one it is serving, that is the
> finding — not an absence of evidence.

That logic exists because these checks previously read a filename the
installer does not create, so they skipped on every real host and an
auditor got a clean run against a deployment logging full client IPs.

**This script must be run on the deployed host, not in the repository.**
The 27 skips here are node-role and deployment checks that genuinely do not
apply to a build container; on a real control plane most of them become
live, and that run is a release gate (DEPLOYMENT-CHECKLIST.md §6).

## 10. What was not tested, and why

| Not tested | Reason |
|---|---|
| Real WireGuard handshake, encrypted flow, MTU, DNS/IP leak, kill switch | No WireGuard kernel module; `ip link add type wireguard` → "Unknown device type". No `wg` tools. |
| `govulncheck` | `vuln.go.dev` blocked by the environment proxy |
| Android on a device | No Android SDK/handset; Google's Maven is unreachable |
| iOS compile | No Swift toolchain; SwiftUI/NetworkExtension have no Linux SDK |
| Windows MSI build | Needs a Windows host with WiX |
| Production TLS, live rate limiting under load | Needs a deployed host |
| Any third-party system (Cloudflare, BTCPay, Kraken, explorers) | Out of authorized scope |

No load testing, chaos testing or fault injection was performed against
live infrastructure, because there is no deployed infrastructure to test
against. Fault injection against the *code* — a control plane that goes
away mid-sync, a malformed peer, a truncated explorer response, a replayed
webhook — is covered by the emulation suite.
