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
import os, re, subprocess, sys, time
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

print("\n[5b] a release the download page over-promises is not launch-ready")
# release.sh refuses to sign a release missing files the page offers, but
# ALLOW_PARTIAL=1 walks past that guard — and preflight, the last thing
# between a partial release and customers, used to bless it: it checked only
# that releases/<v>/ existed and carried a SHA256SUMS.asc. So a release
# without the MSI and APK passed, while download.html went on telling people
# to verify two files SHA256SUMS never covered. On a product whose pitch is
# that you do not have to trust us, that is the hole release.sh's own comment
# calls the worst possible one.
import shutil as _sh, tempfile as _tf

page = open(os.path.join(H.REPO, "web", "download.html"), encoding="utf-8").read()
ver = re.search(r'/releases/([\d.]+)/', page).group(1)
offered = sorted(set(re.findall(r'/releases/[\d.]+/([A-Za-z0-9._+-]+)', page))
                 - {"SHA256SUMS", "SHA256SUMS.asc", "pubkey.asc", "build-info.txt"})
check("the download page offers artifacts to verify", len(offered) >= 2, offered)

sandbox = _tf.mkdtemp(prefix="0trust-partial-")
try:
    # A tree carrying a signed release that is missing exactly the two
    # artifacts no Linux box can build.
    for sub in ("scripts", "web"):
        _sh.copytree(os.path.join(H.REPO, sub), os.path.join(sandbox, sub))
    rel = os.path.join(sandbox, "releases", ver)
    os.makedirs(rel)
    withheld = [a for a in offered if a.endswith((".msi", ".apk"))] or offered[:1]
    for art in offered:
        if art in withheld:
            continue
        open(os.path.join(rel, art), "w").write("x")
    for meta in ("SHA256SUMS", "SHA256SUMS.asc", "pubkey.asc", "build-info.txt"):
        open(os.path.join(rel, meta), "w").write("x\n")

    r2 = subprocess.run([os.path.join(sandbox, "scripts", "preflight.sh"), "--repo"],
                        capture_output=True, text=True, timeout=900, cwd=sandbox,
                        env={**os.environ, "ZTV_SKIP_VALIDATE": "1"})
    line = next((l for l in r2.stdout.splitlines() if "installers-signed" in l), "")
    check("a signed but incomplete release is BLOCKED, not READY",
          "BLOCKED" in line,
          f"withheld {withheld} and preflight still said: {line.strip()!r}")
    for art in withheld:
        check(f"and it names the missing {art}", art in r2.stdout,
              "a gate that will not say what is missing is a complaint, not a gate")

    # And the same tree with everything present must pass, or the gate is
    # simply always-red and nobody can ever ship.
    for art in withheld:
        open(os.path.join(rel, art), "w").write("x")
    r3 = subprocess.run([os.path.join(sandbox, "scripts", "preflight.sh"), "--repo"],
                        capture_output=True, text=True, timeout=900, cwd=sandbox,
                        env={**os.environ, "ZTV_SKIP_VALIDATE": "1"})
    line3 = next((l for l in r3.stdout.splitlines() if "installers-signed" in l), "")
    check("a complete signed release passes the gate", "READY" in line3,
          f"gate is unsatisfiable: {line3.strip()!r}")
finally:
    _sh.rmtree(sandbox, ignore_errors=True)

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
r = subprocess.run([WAL, "--no-pin", SPEC_ZPUB], capture_output=True, text=True,
                   timeout=120, cwd=H.REPO)
check("it derives the BIP84 spec's own first address", SPEC_FIRST in r.stdout,
      f"expected {SPEC_FIRST}\n          {r.stdout[-300:]}{r.stderr[-200:]}")
check("and exits clean on a good key", r.returncode == 0, r.stderr[-200:])

r = subprocess.run([WAL, SPEC_ZPUB.replace("zpub", "zprv", 1)],
                   capture_output=True, text=True, timeout=120, cwd=H.REPO)
check("it refuses an extended PRIVATE key", r.returncode != 0
      and "PRIVATE" in r.stderr,
      "a private key on a server is spending authority on an internet-facing "
      f"box: {r.stdout[-200:]}{r.stderr[-200:]}")

r = subprocess.run([WAL, "zpubTYPO"], capture_output=True, text=True,
                   timeout=120, cwd=H.REPO)
check("it refuses a key that does not parse", r.returncode != 0, r.stdout[-200:])

# A bare address is a real configuration — payments.WatchOnlyProvider reuses
# it — so it must not read as a broken key, or preflight blocks a launch that
# is merely using the worse option.
r = subprocess.run([WAL, "--no-pin", SPEC_FIRST], capture_output=True,
                   text=True, timeout=120, cwd=H.REPO)
check("it accepts a bare address as the reuse configuration",
      r.returncode == 0 and SPEC_FIRST in r.stdout, r.stdout[-200:] + r.stderr[-200:])
check("and says it is reused for every customer", "reused" in r.stdout,
      "two customers owing the same amount become impossible to tell apart")

print("\n[6b] the wallet pin catches the paste this project fears most")
# The whole point: the key never enters the repository, but its identity does,
# so a truncated or wrong-account paste is caught before a customer pays into
# a wallet the operator cannot spend from.
PIN = os.path.join(H.REPO, "scripts", "wallet.pin")
pin_src = open(PIN).read() if os.path.exists(PIN) else ""
check("scripts/wallet.pin exists", bool(pin_src))
pinned = re.search(r'^sha256:([0-9a-f]{64})$', pin_src, re.M)
check("it records a wallet by digest", pinned is not None,
      "without a pin, check-wallet can only say the key derives SOMETHING")
check("and the key itself is nowhere in it",
      not re.search(r'\b[xyz]pub[1-9A-HJ-NP-Za-km-z]{50,}', pin_src),
      "an xpub in the repo hands the operator's entire balance and payment "
      "history to everyone with read access, permanently and unrotatably")

# Nothing anywhere in the tree may carry the extended key.
r = subprocess.run(["git", "grep", "-nIE", r'\b[xyz]pub[1-9A-HJ-NP-Za-km-z]{60,}',
                    "--", ".", ":!tests/", ":!api/test_chainwatch.py"],
                   capture_output=True, text=True, timeout=120, cwd=H.REPO)
check("no extended key is committed anywhere outside the tests",
      r.returncode != 0, r.stdout[:400])

tmp = H.tempdir("0trust-pin-")
mine = os.path.join(tmp, "w.pin")
r = subprocess.run([WAL, "--pin-file", mine, "--pin", SPEC_ZPUB],
                   capture_output=True, text=True, timeout=120, cwd=H.REPO)
check("--pin records a wallet for a different operator", r.returncode == 0
      and re.search(r'^sha256:[0-9a-f]{64}$', open(mine).read(), re.M) is not None,
      r.stdout[-200:] + r.stderr[-200:])
check("and records the digest, never the key",
      SPEC_ZPUB not in open(mine).read(), "the pin file must be commitable")

r = subprocess.run([WAL, "--pin-file", mine, SPEC_ZPUB], capture_output=True,
                   text=True, timeout=120, cwd=H.REPO)
check("the pinned key passes", r.returncode == 0, r.stderr[-200:])

# The realistic mistake: a paste that lost its tail. It still starts with
# zpub, and if it happens to parse it derives somebody else's addresses.
other = H.account_zpub_from_mnemonic(
    " ".join(["abandon"] * 11 + ["about"]), account=1)
r = subprocess.run([WAL, "--pin-file", mine, other], capture_output=True,
                   text=True, timeout=120, cwd=H.REPO)
check("a different account of the SAME seed is rejected", r.returncode == 3,
      f"rc={r.returncode} — this is the wrong-account paste, and it derives "
      "perfectly valid addresses the operator can see but the invoice cannot")
check("and the mismatch names both digests",
      "expected sha256" in r.stderr and "this key" in r.stderr, r.stderr[-200:])

# Everything downstream has to act on that exit code, or the pin is decoration.
inst = open(os.path.join(H.REPO, "scripts", "install.sh")).read()
pre = open(PRE).read()
check("install.sh refuses a key that is not the pinned one",
      "wallet.pin" in inst and re.search(r'3\)', inst) is not None,
      "--wallet must not install a wallet the operator cannot spend from")
check("preflight blocks on it too", "wallet.pin" in pre and "wallet-pinned" in pre,
      pre[-200:])

# ---------------------------------------------------------------------------
# btcpay/scripts/configure.sh, actually executed.
#
# It is the fourth place that refuses an unpinned wallet and the only one
# nothing had ever run — bug class #14, on the script that decides which
# wallet a BTCPay deployment pays into. The two checks above are greps: they
# see the string "wallet.pin" in a file and infer behaviour from it.
#
# The check also used to sit in step 3, after the script had authenticated,
# minted an API key and created a store on the BTCPay host. So this asserts
# the ordering as well as the refusal, by pointing BTCPAY_HOST at a listener
# that records connections: a wrong wallet must produce ZERO of them.
# ---------------------------------------------------------------------------
print("\n[6d] the retention table lists every table the schema creates")
# §10 says "The full schema is in api/main.py. Tables and their content" and
# then lists a selection. Four were missing — ops_events, admin_audit,
# admin_sessions and settings — and three of those had no retention at all,
# which is how a table with no boundary hides in a document whose whole job is
# to say where the boundaries are. None held customer data, which is why the
# omission was comfortable rather than obvious.
_main = open(os.path.join(H.REPO, "api", "main.py")).read()
_schema_tables = set(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", _main))
check("the schema scan found the tables it is meant to check",
      {"accounts", "devices", "ops_events", "admin_sessions"} <= _schema_tables,
      f"found {sorted(_schema_tables)} — the scan has drifted and would pass "
      f"by seeing nothing")

_aud = open(DOC).read()
_sec10 = _aud.split("Tables and their content")[1].split("\n## ")[0]
_listed = set(re.findall(r"^\| `(\w+)`", _sec10, re.M))
_absent = sorted(_schema_tables - _listed)
check("every table in the schema appears in the audit pack's retention table",
      not _absent,
      f"absent from docs/AUDIT.md §10: {_absent}. A table an auditor cannot "
      f"find an answer for is the finding, whether or not it holds customer "
      f"data.")
_phantom = sorted(_listed - _schema_tables)
check("and it lists no table the schema does not create", not _phantom,
      f"listed but not in api/main.py: {_phantom}")

# The three that now have a boundary must actually be swept, not merely
# described. Greps here would restate the document; these are DELETEs.
_sweep = open(os.path.join(H.REPO, "api", "sweep.py")).read()
for _t in ("ops_events", "admin_audit", "admin_sessions"):
    check(f"sweep.py really deletes from {_t}",
          re.search(rf"DELETE FROM {_t}\b", _sweep) is not None,
          f"docs/AUDIT.md gives {_t} a retention window and nothing enforces it")

print("\n[6c] the BTCPay configure script refuses an unpinned wallet, before "
      "it touches the network")
import socket as _socket
import threading as _threading

_seen = []
_lis = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
_lis.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
_lis.bind(("127.0.0.1", 0))
_lis.listen(16)
_port = _lis.getsockname()[1]
_stop = _threading.Event()

def _accept_loop():
    _lis.settimeout(0.5)
    while not _stop.is_set():
        try:
            c, _ = _lis.accept()
        except OSError:
            continue
        _seen.append(1)
        try: c.close()
        except OSError: pass

_t = _threading.Thread(target=_accept_loop, daemon=True); _t.start()

CFG = os.path.join(H.REPO, "btcpay", "scripts", "configure.sh")
check("configure.sh is executable", os.access(CFG, os.X_OK))

def _run_configure(xpub, **extra):
    _seen.clear()
    env = {**os.environ,
           "BTCPAY_HOST": f"127.0.0.1:{_port}",
           "BTCPAY_ADMIN_EMAIL": "op@example.invalid",
           "BTCPAY_ADMIN_PASSWORD": "not-a-real-password",
           "BTC_XPUB": xpub,
           "CONTROL_HOST": "0trustvpn.test"}
    env.pop("ALLOW_UNPINNED_WALLET", None)
    env.update(extra)
    r = subprocess.run([CFG], capture_output=True, text=True, timeout=120,
                       cwd=H.REPO, env=env)
    time.sleep(0.3)          # let the accept loop record anything in flight
    return r, len(_seen)

r, conns = _run_configure(SPEC_ZPUB)
check("a wallet that is not the pinned one is refused", r.returncode != 0,
      f"rc={r.returncode} — BTCPay would have been configured to pay into it")
check("and the refusal names wallet.pin and how to override it",
      "wallet.pin" in r.stderr and "ALLOW_UNPINNED_WALLET" in r.stderr,
      r.stderr[-300:])
check("and it made no connection to the BTCPay host at all", conns == 0,
      f"{conns} connection(s) — the script authenticated and created a store "
      f"before running a local check on an environment variable")

# The positive control. Without it the three checks above are satisfied by a
# script that exits before doing anything, for any reason.
r2, conns2 = _run_configure(SPEC_ZPUB, ALLOW_UNPINNED_WALLET="1")
check("with the override, it gets past the wallet check and reaches BTCPay",
      conns2 > 0,
      f"{conns2} connections — the script stopped for some reason other than "
      f"the wallet pin, so the checks above prove nothing about the pin")

_stop.set(); _lis.close()

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

print("\n[8] the operating entity agrees with its own jurisdiction")
# terms.html §9 makes the Jurisdiction line in security.txt the governing law
# of every customer contract, and the Entity line names who the contract is
# with. The two were written at different times and contradicted each other:
# "0trust INC." under "Jurisdiction: Switzerland" is a company form that does
# not exist under Swiss law. That is not pedantry — it is a self-contradiction
# in a binding clause, on a product whose entire value is being checkable.
SECTXT = os.path.join(H.REPO, "web", ".well-known", "security.txt")
sec = open(SECTXT, encoding="utf-8").read()

def line(field):
    m = re.search(rf'^#?\s*{field}:\s*(.+?)\s*$', sec, re.M)
    return m.group(1) if m else ""

entity = line("Entity")
juris = line("Jurisdiction")
check("an operating entity is named", bool(entity), entity)
check("a jurisdiction is stated", bool(juris), juris)

# Company-form suffixes that actually exist in each jurisdiction. Only the
# ones this project has plausibly considered; an unlisted jurisdiction is not
# failed, because inventing law is worse than not checking.
FORMS = {
    "switzerland": ({"gmbh", "ag", "sa", "sàrl", "sarl"},
                    "Swiss company forms are GmbH, AG, SA or Sàrl"),
    "iceland":     ({"ehf.", "ehf", "hf.", "hf"},
                    "Icelandic company forms are ehf. and hf."),
    "panama":      ({"s.a.", "sa"}, "Panamanian companies are S.A."),
}
# Forms that belong to somewhere else entirely, and are the realistic mistake.
FOREIGN = {"inc.", "inc", "llc", "ltd.", "ltd", "corp.", "corp", "plc", "gmbh",
           "ag", "sa", "sàrl", "sarl", "ehf.", "ehf", "hf.", "hf"}

if entity and juris:
    suffix = entity.split()[-1].lower()
    key = juris.split(",")[0].strip().lower()
    if key in FORMS:
        allowed, why = FORMS[key]
        check(f"the entity form is one that exists in {juris}",
              suffix in allowed,
              f"{entity!r} under {juris!r} — {why}. terms.html §9 makes this "
              f"the governing law of the customer contract.")
    else:
        check(f"jurisdiction {juris!r} is stated (form not checked here)", True)
    check("the entity carries a company form at all",
          suffix in FOREIGN,
          f"{entity!r} ends in {suffix!r}, which is not a company form")

# And the name must not drift between the places that publish it.
for doc in ("docs/AUDIT.md", "docs/LAUNCH.md"):
    text = open(os.path.join(H.REPO, doc), encoding="utf-8").read()
    check(f"{doc} names the same entity as security.txt",
          not entity or entity in text,
          f"security.txt says {entity!r}; {doc} does not contain it")

print("\n[8b] the canary swears against the law that can actually compel us")
# A warrant canary that enumerates only US instruments, signed by a company
# established somewhere else, is boilerplate: the realistic secret demand
# arrives under the law of the jurisdiction the operator is established in,
# and that is the one a reader checks for. The entity moved to Switzerland
# after this template was written and the statements did not follow.
canary_tpl = open(os.path.join(H.REPO, "canary", "templates", "canary.txt"),
                  encoding="utf-8").read()
# Instruments that carry secret legal demands, per jurisdiction. Only the ones
# this project has actually considered — an unlisted jurisdiction is not
# failed, because inventing law is worse than not checking.
INSTRUMENTS = {
    "switzerland": (("BÜPF", "NDG"),
                    "Swiss secret demands arrive under the BÜPF/VÜPF "
                    "surveillance regime or the NDG intelligence act"),
    "iceland":     (("Iceland",), "name the Icelandic route"),
    "panama":      (("Panama",), "name the Panamanian route"),
}
if juris:
    key = juris.split(",")[0].strip().lower()
    if key in INSTRUMENTS:
        needles, why = INSTRUMENTS[key]
        missing = [n for n in needles if n not in canary_tpl]
        check(f"the canary names the instruments of {juris}",
              not missing,
              f"the operating entity is established in {juris} and the canary "
              f"does not mention {missing} — {why}")
    else:
        check(f"canary jurisdiction {juris!r} not checked here", True)

# Every mesh jurisdiction the product claims should be answerable for too:
# a node can be compelled where it sits, regardless of where the company is.
for country in ("Switzerland", "Iceland", "Romania"):
    check(f"the canary accounts for the {country} node jurisdiction",
          country in canary_tpl,
          f"three nodes run in {country} and the canary never says so")

print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
