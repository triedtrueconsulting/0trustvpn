# Deployment checklist — the release gate

Audit date 2026-10-17.

`docs/LAUNCH.md` is the day-by-day playbook and `docs/DEPLOY.md` is the
reference for DNS, CDN and node configuration. This file is neither. It is
the **gate**: the things that must be true before customer traffic and
customer money are accepted, each with the command that proves it.

An item is not done because someone remembers doing it. It is done when the
command says so.

---

## Stage 0 — Before anything is provisioned

| # | Gate | Command | Blocking |
|---|---|---|---|
| 0.1 | Full battery green | `./scripts/validate.sh` | **Yes** |
| 0.2 | No new secrets in tree or history | `./scripts/secret-scan.sh` | **Yes** |
| 0.3 | **SEC-1 resolved** — provenance of both registered extended keys established, funds moved if either is the operator's | operator judgement, recorded in `scripts/secret-scan.known` | **Yes** |
| 0.4 | Dependency advisories | `pip-audit -r api/requirements.txt` | **Yes** |
| 0.5 | `govulncheck ./...` from a host that can reach `vuln.go.dev` | could not run here — proxy blocked | **Yes** |

0.3 is the one item on this list that no command can close. See
SECURITY-AUDIT.md SEC-1.

## Stage 1 — Keys, on the operator's own machine

Never on a server. `generate-keys.sh` refuses to run in CI and warns
against generating on the server, for the reason that the box you are
hardening against seizure is the worst place to create the keys that
outlive it.

| # | Gate | Command |
|---|---|---|
| 1.1 | Generate release, canary and support keys | `./scripts/generate-keys.sh` |
| 1.2 | Publish each where it belongs | `./scripts/set-fingerprints.sh --release … --canary … --support …` |
| 1.3 | Confirm nothing is outstanding | `./scripts/set-fingerprints.sh --check` |

The three keys are **not** interchangeable. security-policy.html publishes
the SUPPORT key — the one people encrypt vulnerability reports to. A signing
key there has no encryption subkey and reporters cannot use it.

## Stage 2 — Wallet, before any money can arrive

| # | Gate | Command |
|---|---|---|
| 2.1 | The configured key is the intended one | `./scripts/check-wallet.sh` — exits 3 on a pin mismatch |
| 2.2 | **A human has compared the derived addresses against the wallet** | eyeball the output of 2.1 |

2.2 cannot be automated and must not be skipped. A wrong extended key issues
addresses the operator cannot spend, silently, with every health check
green. `install.sh --wallet`, `preflight.sh` and `btcpay/scripts/configure.sh`
all refuse on a pin mismatch, and configure.sh checks **before** it opens a
connection.

## Stage 3 — Control plane

Follow `docs/LAUNCH.md` Day 2. Gates specific to this checklist:

| # | Gate | How it is proven |
|---|---|---|
| 3.1 | Backups have a recipient and the timer is enabled | `--backup-key age1…`; no key means OFF, said out loud |
| 3.2 | Only the PUBLIC half of the age key reached the server | an `AGE-SECRET-KEY-…` is refused with the reason |
| 3.3 | nginx renders the anonymising log format | `audit-verify.sh` reads `sites-enabled/0trust` |
| 3.4 | `--no-access-log` is live on the API unit | gate `api-no-access-log` |
| 3.5 | Secret request paths are dropped by nginx | gate `nginx-log-no-secret-paths` |
| 3.6 | Auto-updates configured, security origins only, no auto-reboot | `install_auto_updates` |
| 3.7 | fail2ban jail installed | `config/fail2ban/0trust.local` |

If a CDN is in front:

| # | Gate | Command |
|---|---|---|
| 3.8 | realip trust list fetched and verified | `install.sh --cloudflare` — refuses `0.0.0.0/0`, a short list, or a non-CIDR |
| 3.9 | The CDN is disclosed, and only if present | gate `cdn-disclosed` fires in both directions |

Without 3.8 every visitor behind one edge shares a rate-limit bucket, eight
failed logins from anywhere lock the operator out, and the anonymised log
truncates an edge address.

## Stage 4 — Mesh nodes (each of the three)

| # | Gate | How it is proven |
|---|---|---|
| 4.1 | Node registered itself; no hand-written SQL | `install.sh --mode node` |
| 4.2 | The registered endpoint carries the port it really listens on | check `mesh_nodes.endpoint` against `wg_port` |
| 4.3 | Swap is off and paths are tmpfs | node bootstrap |
| 4.4 | NAT and egress filter reapply at boot | `node-runtime-apply.sh` wired to the boot unit |
| 4.5 | Each node has its own nftables table name | `ZTV_NFT_TABLE` differs per node |
| 4.6 | Upstream DNS is DoT, with no cleartext retry | gate `node-dns-encrypted-upstream` |
| 4.7 | Query logging is off | gate `node-dns-no-query-log` |
| 4.8 | The enrolment token is IP-pinned and revocable | `provision_tokens.bind_ip`, `revoked_at` |
| 4.9 | The token was not passed in argv | `--provision-token-file` or `ZTV_PROVISION_TOKEN` |

**4.4 is the one most likely to be skipped and has already caused a silent
outage**: `/etc/nftables.conf` does not include `/etc/nftables.d`, so a node
came back from reboot doing no masquerading. Customer traffic entered the
tunnel and died while the node kept heartbeating over its own outbound
HTTPS.

## Stage 5 — Live verification, on real hardware

Nothing in this stage can be run in a CI container. These are the gaps
WIREGUARD-TEST-RESULTS.md §5 names, and they are **blocking**.

| # | Gate |
|---|---|
| 5.1 | A client completes a real handshake and passes traffic |
| 5.2 | No DNS leak on a live tunnel |
| 5.3 | No IPv4 or IPv6 leak on a live dual-stack host |
| 5.4 | MTU correct on both transports, under full-size packets |
| 5.5 | Kill switch stops traffic when the tunnel drops, and `PreDown` cannot strand the user |
| 5.6 | Reboot a RAM node: rejoins under the same id, NAT and egress filter reapplied |
| 5.7 | Multi-hop: the exit genuinely does not see the client |
| 5.8 | Obfuscated transport end to end against a node running the relay |

5.1 has a product-level gate already: `0trust connect` waits for a handshake
and exits non-zero if none arrives, because `wg-quick up` never contacts the
node and its exit code means nothing. `install.sh` holds itself to the same
standard by probing `ip link show` rather than trusting
`systemctl enable --now`.

## Stage 6 — The promise

| # | Gate | Command |
|---|---|---|
| 6.1 | Every no-logs claim matches the deployment | `./scripts/audit-verify.sh` on the real host |
| 6.2 | The full launch gate | `./scripts/preflight.sh` |
| 6.3 | Legal review of privacy.html, terms.html **and the canary** | human |
| 6.4 | Entity name matches the Handelsregister entry, canton included | human |
| 6.5 | VAT and art. 27 EU representative decided **before the first sale** | human, with an accountant |

6.1 must be run **on the deployed host**, not in the repository. Its nginx
checks previously read a filename the installer does not create, so they
skipped on every real host and an auditor got a clean run against a
deployment logging full client IPs. A SKIP is only honest when the thing
genuinely does not apply.

6.5 is not engineering and has no code behind it. A Swiss GmbH selling a
digital service to EU consumers owes VAT in the customer's country, and this
product deliberately does not know which country that is.

## Stage 7 — Release artifacts

| # | Gate | Command |
|---|---|---|
| 7.1 | Installers compiled on real toolchains and signed | MSI on Windows, APK in Android Studio, .deb/AppImage on Linux |
| 7.2 | A customer can verify one downloaded binary | `./scripts/verify-release.sh` |
| 7.3 | `EXPECTED_KEY` is a real 40-character fingerprint, not the placeholder | 7.2 exits 2 on the placeholder |

7.2 must be tested the way a customer runs it — **one** binary, for one
platform. The verifier previously reported "one or more files don't match"
on an ordinary untampered download, because the manifest names every
platform; that message reads as tampering.

The `.ipa` stays out of `releases/` and SHA256SUMS: Apple re-signs what it
distributes, so a published hash would match nothing a customer can
download.
