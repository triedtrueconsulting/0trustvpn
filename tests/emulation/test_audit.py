#!/usr/bin/env python3
"""
Keep the audit pack and its verifier from drifting apart.

docs/AUDIT.md is what a third-party auditor is handed; audit-verify.sh is what
they run. §10 told them the script "runs the full check matrix" and that "each
check has a short name" — and then never listed one. All 35 names were absent
from the document. An auditor who gets a FAIL for `nginx-anonymizes-ip` had to
read the shell script to find out which claim it defended, which is the
opposite of what an audit pack is for.

So the matrix is in the document now, and this keeps the two in step: a check
with no row, or a row naming a check that no longer exists, is a failure. It is
the same discipline CLAUDE.md already applies to privacy.html, terms.html and
the audit pack — a claim nothing executes, or an executable nothing claims, is
how this product loses the only thing it is selling.
"""
import os, re, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

SCRIPT = os.path.join(H.REPO, "scripts", "audit-verify.sh")
DOC = os.path.join(H.REPO, "docs", "AUDIT.md")
src = open(SCRIPT).read()
doc = open(DOC).read()

print("[1] every check in the script has a row in the audit pack")
script_ids, descs = [], {}
for line in src.splitlines():
    m = re.match(r'^check ([a-z0-9-]+) "([^"]+)"', line)
    if m:
        script_ids.append(m.group(1))
        descs[m.group(1)] = m.group(2)
check(f"the script defines checks ({len(script_ids)})", bool(script_ids))
check("check ids are unique", len(script_ids) == len(set(script_ids)),
      [i for i in script_ids if script_ids.count(i) > 1])

# Only the matrix under "### The checks" — AUDIT.md has other tables whose
# first column is also a backticked lowercase word (region codes, provider
# names), and counting those as documented check ids makes both directions of
# this comparison meaningless.
matrix = doc[doc.index("### The checks"):] if "### The checks" in doc else ""
doc_ids = set(re.findall(r'^\| `([a-z0-9-]+)` \|', matrix, re.M))
missing = sorted(set(script_ids) - doc_ids)
check("no check is undocumented", not missing,
      f"{missing} — an auditor seeing this FAIL has nothing to map it back to")

print("\n[2] and the audit pack lists no check that does not exist")
phantom = sorted(doc_ids - set(script_ids))
check("no documented check is missing from the script", not phantom,
      f"{phantom} — the pack promises a verification that cannot be run")

print("\n[3] the descriptions match")
mismatched = []
for cid in sorted(doc_ids & set(script_ids)):
    m = re.search(r'^\| `' + re.escape(cid) + r'` \| (.+?) \|$', matrix, re.M)
    if m and m.group(1).strip() != descs[cid].strip():
        mismatched.append(f"{cid}: doc {m.group(1)!r} vs script {descs[cid]!r}")
check("every row says what its check says", not mismatched,
      "\n          ".join(mismatched))

print("\n[4] the script does what the pack says it does")
check("AUDIT.md names the script", "scripts/audit-verify.sh" in doc)
check("it explains that SKIP is normal", "SKIP" in doc,
      "a majority of checks skip on any single host; an auditor who does not "
      "know that will read a clean run as a broken one")
check("the script is executable", os.access(SCRIPT, os.X_OK))

# It has to survive being run by an auditor with no privileges and no
# production host, which is how anyone first tries it.
r = subprocess.run([SCRIPT], capture_output=True, text=True, timeout=600,
                   cwd=H.REPO)
check("it runs to completion on a host with nothing installed",
      r.returncode >= 0 and "PASS:" in r.stdout,
      r.stdout[-400:] + r.stderr[-400:])
# Not "zero failures": what this script reports depends on the machine it is
# pointed at, and a stray database somebody left in /tmp is a real finding, not
# a broken test. What must never happen is a check failing because the CHECK is
# broken — an unbound variable, a missing command, a syntax error — because
# that reads to an auditor exactly like a genuine finding.
broken = [l.strip() for l in r.stdout.splitlines() + r.stderr.splitlines()
          if re.search(r'unbound variable|command not found|syntax error'
                       r'|No such file or directory: |: line \d+:', l)]
check("no check fails because the check itself is broken", not broken,
      "\n          ".join(broken[:6]))

summary = re.search(r'PASS:\S*\s+(\d+)\s+\S*FAIL:\S*\s+(\d+)\s+\S*SKIP:\S*\s+(\d+)',
                    r.stdout)
check("it prints a parseable summary", summary is not None,
      r.stdout[-300:])
if summary:
    p_, f_, s_ = (int(x) for x in summary.groups())
    check("every check is accounted for", p_ + f_ + s_ == len(script_ids),
          f"{p_}+{f_}+{s_} != {len(script_ids)} checks defined")
    print(f"      on this host: {p_} pass, {f_} fail, {s_} skip")

# Filtering is documented; make sure it actually filters.
r = subprocess.run([SCRIPT, "backups"], capture_output=True, text=True,
                   timeout=300, cwd=H.REPO)
ran = [i for i in re.findall(r'^  ([a-z0-9-]+)\s+\S.*\.\.\.', r.stdout, re.M)]
check("passing a name runs only the matching checks",
      bool(ran) and all("backups" in x for x in ran), ran)

print("\n[5] the launch gate refuses to call an unfinished deployment ready")
# The one question a green build cannot answer. It has to run anywhere, tell
# the truth about this checkout, and exit non-zero while placeholders remain —
# otherwise it is decoration and somebody ships on it.
PRE = os.path.join(H.REPO, "scripts", "preflight.sh")
check("preflight.sh exists and is executable", os.access(PRE, os.X_OK))
r = subprocess.run([PRE, "--repo"], capture_output=True, text=True, timeout=900,
                   cwd=H.REPO, env={**os.environ, "ZTV_SKIP_VALIDATE": "1"})
check("it runs on a machine with nothing deployed",
      "preflight" in r.stdout.lower(), (r.stdout + r.stderr)[-400:])
check("it does not call this checkout ready", r.returncode > 0,
      "the release key is still DEADBEEF and no wallet is set; saying READY "
      "here is how a placeholder reaches production")
check("and it says NOT READY out loud", "NOT READY" in r.stdout,
      r.stdout[-300:])

# Each blocker has to name the fix, or it is a complaint rather than a gate.
blocked = [l for l in r.stdout.splitlines() if "BLOCKED" in l]
fixes = [l for l in r.stdout.splitlines() if "fix:" in l]
check("every blocker comes with a fix", len(fixes) >= len(blocked),
      f"{len(blocked)} blockers, {len(fixes)} fixes")
print(f"      {len(blocked)} blocker(s) on this checkout, each with a fix")

# The blockers must be the real ones, not a generic scold.
for expect in ("release-key-pinned", "web-no-placeholder-fpr"):
    check(f"it catches {expect}", expect in r.stdout, r.stdout[-400:])

print("\n[6] the wallet check refuses what it must refuse")
# A wrong extended key is the one failure here with no symptom: addresses are
# issued, invoices never settle, every health check stays green. The check
# exists so a human compares the first address against their wallet.
WAL = os.path.join(H.REPO, "scripts", "check-wallet.sh")
check("check-wallet.sh is executable", os.access(WAL, os.X_OK))

# The BIP84 spec's own vector, derived here from the spec's mnemonic rather
# than pasted: an extended key typed from memory is exactly the mistake this
# script exists to catch, and a wrong constant here would assert nothing.
# harness owns that derivation so both modules share one definition.
SPEC_ZPUB = H.account_zpub_from_mnemonic(" ".join(["abandon"] * 11 + ["about"]))
SPEC_FIRST = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
r = subprocess.run([WAL, SPEC_ZPUB], capture_output=True, text=True, timeout=120,
                   cwd=H.REPO)
check("it derives the BIP84 spec's own first address", SPEC_FIRST in r.stdout,
      f"expected {SPEC_FIRST}\n          {r.stdout[-300:]}{r.stderr[-200:]}")

r = subprocess.run([WAL, SPEC_ZPUB.replace("zpub", "zprv", 1)],
                   capture_output=True, text=True, timeout=120, cwd=H.REPO)
check("it refuses an extended PRIVATE key", r.returncode != 0
      and "PRIVATE" in r.stderr,
      "a private key on a server is spending authority on an internet-facing "
      f"box: {r.stdout[-200:]}{r.stderr[-200:]}")

r = subprocess.run([WAL, "zpubTYPO"], capture_output=True, text=True,
                   timeout=120, cwd=H.REPO)
check("it refuses a key that does not parse", r.returncode != 0, r.stdout[-200:])

print("\n[7] key generation refuses the wrong machine")
GEN = os.path.join(H.REPO, "scripts", "generate-keys.sh")
check("generate-keys.sh is executable", os.access(GEN, os.X_OK))
r = subprocess.run([GEN], capture_output=True, text=True, timeout=120,
                   cwd=H.REPO, env={**os.environ, "CI": "1"})
check("it will not run in CI", r.returncode != 0, r.stdout[-200:])
check("and says why", "machine you control" in r.stderr, r.stderr[-200:])
src = open(GEN).read()
check("it warns against generating keys on the server",
      "/etc/0trust" in src and "NOT ON THE SERVER" in src,
      "a signing key on an internet-facing box signs whatever an intruder wants")

print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
