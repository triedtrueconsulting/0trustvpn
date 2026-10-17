# Initial audit — baseline state on arrival

What the repository looked like before this audit changed anything, and
what the first full pass found. Audit date 2026-10-17.

---

## 1. Baseline

The project arrived in good condition. `./scripts/validate.sh` ran 24
checks: **23 passed, 1 failed**. The single failure was the emulation
suite, and both failing modules failed for the same environmental reason
rather than a product defect:

- `test_proxy_guards.py` — resolved `example.com` to exercise the
  public-unicast allow path. No external DNS in the sandbox, so the allow
  path was never executed and the module failed closed.
- `test_install.py` — same dependency, same cause.

Those are now fixed hermetically rather than worked around (see §4), because
a workaround in a test is a bug report about the test.

Nothing in the repository was broken, unbuildable or unparseable. The Go
client cross-compiled to all six targets, the .deb built, the API smoke test
passed end to end, and `pip-audit` reported no known advisories against the
pinned runtime dependencies.

## 2. What this codebase already does well

Stated plainly because it bears on the release decision, and because an
audit that only lists problems misrepresents the thing it audited.

- **The test suite is the largest single area of the repository** — 15,241
  lines against 7,341 for the API it tests. For a product whose value is
  trustworthiness, that ratio is correct.
- **Invariants are written down with the incident that produced them.**
  CLAUDE.md is not a style guide; it is a register of defects that have
  actually happened, each with the reasoning that makes the fix
  non-obvious. That is why this audit could go straight to the sharp edges.
- **The project already practises mutation testing** and names it as a bug
  class (#17): a gate nobody has watched fail is a gate nobody has tested.
  Several checks in the suite exist specifically because an earlier check
  passed while matching its own explanatory comment.
- **Claims are tied to code by machine-checkable gates.** `audit-verify.sh`
  and the `test_site.py` blocks tie privacy.html, terms.html and AUDIT.md to
  what the system actually does, including the arithmetic in "save $N".
- **Failure directions are chosen deliberately and documented.** The node's
  DNS fails closed, the Tor control channel has no direct fallback, the
  Cloudflare range fetch refuses a list it could not verify, and v6 is
  blackholed rather than leaked. Each has a written reason.

## 3. The one finding that outranks everything else

**Two valid BIP84 extended public keys are present in git history.**

| | |
|---|---|
| Locations | `CLAUDE.md` (8 revisions) and `btcpay/runbook.md` |
| Introduced | commit `f09db4cd`, 2026-08-18 |
| Digests | `sha256:2ca1d13600a428db…`, `sha256:37dc8c2ee9531e53…` |
| Status | **Unresolved — requires operator action** |

Both are structurally real: they derive live `bc1q` addresses through the
product's own `chainwatch.receive_address()`. Neither is the operator wallet
pinned in `scripts/wallet.pin` (`ac5863ce…`) and neither is the BIP84
specification test vector (`2257eeb0…`), so "it is just an example" is not
established and should not be assumed.

The values are not reproduced here, in the register, or in any scan output.
Only digests and locations are recorded — printing a secret into a report is
one more place it lives.

**Why this is severe and not merely untidy.** An extended public key cannot
be rotated. It exposes the wallet's entire balance and payment history to
anyone holding it, permanently, and the only remedy is moving the funds. The
repository is cloned in full, so deleting the file achieved nothing: the blob
is still in the pack and still one `git show` away.

**Why it was not caught.** `test_audit.py` refused an extended key in the
**working tree** — `git grep` over `.` — and had been green for months over a
history containing two. CLAUDE.md records one of these two being "caught once
already"; it was caught in the tree it had already been committed to. This is
bug class #17 in its purest form: a gate that cannot see the thing it is
named after.

**Required operator action**, in order:

1. Determine the provenance of each key. If either was generated from a seed
   the operator controls, **move the funds** — the key cannot be rotated.
2. If both are demonstrably throwaway keys from a seed nobody holds, record
   that finding in `scripts/secret-scan.known` and the matter is closed.
3. Rewriting history is **not** a remedy on its own. The repository has been
   pushed; anyone who cloned it holds the blobs regardless.

Fixed in this audit: the gate. `scripts/secret-scan.sh` now reads every blob
reachable from every ref, `test_audit.py` proves it does so by planting a key
in a throwaway repo and requiring the scan to fail where the tree grep
passes, and the two known exposures are reprinted as OUTSTANDING on every run
rather than failing the build — a permanently red gate gets switched off, and
then the next secret goes in unnoticed.

## 4. Changes made during this audit

| Area | Change |
|---|---|
| Secret scanning | `scripts/secret-scan.sh` reads history, not just the tree; four secret classes; findings reported as location + digest, never the value |
| Secret scanning | `.gitleaks.toml` for breadth; absence reported, never treated as a pass |
| Secret scanning | `scripts/secret-scan.known` — the register of already-happened exposures |
| Regression test | `test_audit.py` asserts the scan walks the object graph, and mutation-tests it against a planted-then-deleted key |
| SAST | `tests/sast/ztv.yml` — 8 rules for this codebase's own bug classes, wired in as `validate.sh sast` |
| Money path | `test_payments.py` now covers price and quantity manipulation |
| Test hermeticity | `test_proxy_guards.py` asserts the allow path on literal addresses; hostname cases SKIP honestly when resolution is unavailable |
| Test hermeticity | `test_install.py` pins a TEST-NET-2 host in `/etc/hosts` and restores it |

Three bugs were found **in the scanner this audit wrote**, all by planting
secrets and watching it stay green, and all worth recording because they are
the same shapes the product has been bitten by:

- `git ls-files` lists tracked files only, so the one case the fast
  `--tree` path exists for — a new file about to be committed — was the one
  case it could not see.
- `(?i)` is PCRE; `grep -E` warned and the WireGuard rule matched nothing.
- the PGP pattern begins `-----`, which grep parsed as options, so that rule
  silently matched nothing until a planted key failed to trip it.

And two more in the SAST rules, both of which produced a rule that loaded
cleanly and could never fire: semgrep matches an f-string as a single value
and will not match a quote-then-interpolation inside one, and a `|` YAML
block scalar keeps a trailing newline that semgrep then matches literally.

## 5. Post-audit state

`./scripts/validate.sh` — **26 checks, 26 passed, 0 failed, 0 skipped.**

Full results, including what could not be tested here and why, are in
TEST-RESULTS.md and WIREGUARD-TEST-RESULTS.md.
