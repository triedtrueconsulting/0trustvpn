# Security audit

Audit date 2026-10-17. Scope: this repository and the infrastructure it
deploys. No third-party system was tested.

Severity is judged against what this product sells. For a privacy VPN, a
claim the system does not back up is a higher-severity defect than a crash,
because the claim is the product.

---

## Findings

### SEC-1 — Two valid extended public keys in git history
**Severity: HIGH. Status: OPEN — requires operator action.**

Two structurally valid BIP84 extended public keys are reachable in the
object graph, introduced in `f09db4cd` (2026-08-18) in `CLAUDE.md` (8
revisions) and `btcpay/runbook.md`. Recorded by digest only
(`2ca1d13600a428db…`, `37dc8c2ee9531e53…`) in `scripts/secret-scan.known`;
the values appear nowhere in this repository's reports or scan output.

Both derive live `bc1q` addresses through the product's own
`chainwatch.receive_address()`. Neither is the pinned operator wallet
(`ac5863ce…`) nor the BIP84 specification vector (`2257eeb0…`), so they
cannot be waved away as examples without checking.

**Impact.** An extended public key exposes a wallet's entire balance and
transaction history to whoever holds it, forever. It cannot be rotated. If
either key belongs to a seed the operator controls, the operator's finances
are readable by everyone who has ever cloned this repository.

**Remediation.** Confirm provenance of each. If either is the operator's,
**move the funds** — that is the only remedy. If both are throwaway,
annotate the register and close. History rewriting does not help: the
repository has been pushed, and clones already hold the blobs.

**Detection gap, now fixed.** `test_audit.py` checked only the working tree
and was green for months over a history containing both.
`scripts/secret-scan.sh` now reads every blob reachable from every ref, and
`test_audit.py` proves it by planting a key in a throwaway repository and
requiring the scan to fail where the tree grep passes.

### SEC-2 — No automated secret scanning existed
**Severity: MEDIUM. Status: FIXED.**

Nothing scanned for credentials in history, and the working-tree check
covered extended keys only — not age secrets, PGP private keys or WireGuard
private keys, each of which ends a different part of this business.

Fixed by `scripts/secret-scan.sh` (four classes, history-aware, built-in
pass with no dependencies so there is no arrangement of the build where it
silently does not run) plus `.gitleaks.toml` for breadth whose absence is
reported rather than treated as a pass. Findings print a location and a
sha256 prefix, never the value.

### SEC-3 — No static analysis
**Severity: LOW. Status: FIXED.**

Fixed by `tests/sast/ztv.yml` and the `sast` gate. 8 rules, 0 findings on
the real tree, every rule mutation-tested. The registry (`semgrep.dev`) is
unreachable from the build environment, so these are local rules — which
suits this codebase better anyway, since they encode its own documented
invariants.

### SEC-4 — The money path had no abuse coverage
**Severity: LOW (no defect found). Status: FIXED (coverage added).**

`PRICING` is the only place a term costs anything, and nothing exercised a
request that names its own amount or orders a term not for sale. The code
was already correct — `amount = PRICING[req.months]` at both sites, with a
validator refusing any other term — so this added evidence, not a fix.

## Areas reviewed with no defect found

Each of these was actively tested, not merely read.

**Authentication and authorization.** The token is the credential, carried
in `X-Account-Token`; `Authorization: Bearer` is not accepted. Cross-account
device access is refused in both directions (delete and list). A customer
token cannot read the node peer manifest. The peer manifest is scoped per
node, so one node's credential does not enumerate the customer base — which
is what makes the seizure claim in the audit pack true.

**Token handling.** 16 alphabet characters in 4-char groups, unique over 200
draws, no ambiguous `I/O/0/1`, stored only as a SHA-256 hash with case and
dashes normalised first.

**Input validation on the paths that reach root.** A device or node public
key becomes a `PublicKey =` line that `wg syncconf` parses as root, and a
node's `public_ip` is interpolated into an `nft -f` rule. Both are validated
by decoding rather than by length. The sharp case — exactly 44 characters
containing a newline and a directive fragment — is refused; a longer
injection proves nothing because `max_length` catches it.

**Injection.** 19 SQL-interpolation candidates were read individually. All
are safe: the interpolated text is always a source literal carrying a `?`, a
generated `",".join("?" * len(xs))` placeholder list, or a DDL identifier
from a module constant, and every user value is bound. No `shell=True`
anywhere.

**Payment replay.** Crediting is guarded on stored invoice state rather than
on signature validity, because an HMAC on a captured delivery never expires.
Verified for BTCPay, Stripe and Square webhook replays.

**Confirmation depth and truncated explorer responses.** Both depth readers
refuse a short answer rather than guessing. This matters because an invoice
address is published to whoever is paying and BIP84 derivation is
sequential, so a past customer can predict and dust the next addresses.

**Proxy guards.** `/surf` is the only unauthenticated endpoint taking a URL
from anyone. GET/HEAD only, http/https only, ports 80/443, public unicast
re-checked on every redirect, size and time caps, content-type allowlist.
The tunnelled forms — IPv4-mapped, 6to4, Teredo, NAT64 — are named
explicitly rather than left to the standard library, because
`2002:a9fe:a9fe::` is cloud metadata in a 6to4 wrapper.

**Blocking the event loop.** No `async def` contains a blocking call. Now
enforced by a gate rather than by remembering to grep.

**Dependencies.** `pip-audit` against `api/requirements.txt`: no known
vulnerabilities. The Go module has exactly one third-party dependency
(`skip2/go-qrcode`, pure Go), used only to render a QR of a config the
product generated itself.

## Residual risks that are design decisions, not defects

Recorded so a reader does not mistake them for oversights. Each is
disclosed in the product's own documentation.

- **Cloudflare terminates TLS and therefore reads everything it fronts,
  including `X-Account-Token`** if `/api/v1/` is on a proxied hostname.
  This is a real trust delegation, not a control. Disclosed in
  privacy.html §5a and AUDIT.md §9, and a gate fires in both directions.
- **The invoice id is a bearer capability.** Anyone holding one can read
  that invoice's payment state. The id carries 144 bits of entropy and both
  nginx and uvicorn drop the request path from their logs. Holding one
  yields no account token.
- **Obfuscation provides no authentication.** Every customer on a node holds
  the same relay key. The relay is therefore allowlisted to the node's own
  WireGuard ports, rejects hostnames outright, and caps its flow table.
- **No nginx fail2ban jail.** The access log records a /24, so a jail fed by
  it could only ban up to 254 uninvolved people alongside an attacker. The
  privacy property is kept instead; the web tier is defended by
  `limit_req_zone` and in-memory login throttling, both of which use the
  full address without recording it.

## Not tested — out of reach in this environment

Stated so the verification level is not overstated:

- A real WireGuard handshake, encrypted flow, MTU behaviour, DNS/IP leak
  testing and the kill switch. No WireGuard kernel module. See
  WIREGUARD-TEST-RESULTS.md §1.
- `govulncheck` for the Go client — `vuln.go.dev` is blocked by the
  environment's proxy. The dependency surface is one pure-Go module plus
  stdlib; the toolchain in use is go1.24.7.
- Production TLS configuration, live rate limiting under load, and anything
  requiring a deployed host.
- No penetration testing was performed against any third-party system,
  including Cloudflare, BTCPay, Kraken or any block explorer.
