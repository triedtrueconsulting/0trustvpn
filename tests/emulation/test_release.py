#!/usr/bin/env python3
"""
Cut a real signed release, then verify it the way a customer would.

This is the one path in the product that had never been executed. It matters
more than most: download.html tells people not to trust a binary that does not
verify against the release key, and points them at verify-release.sh. If that
loop is broken, the honest-verifiable-downloads pitch is decoration.

What it found: the page offered nine files — two .debs, an AppImage, an MSI, an
APK and the raw binaries — and release.sh hashed only `dist/0trust-*`. The four
packages, including the one the page marks "recommended" for Linux, went out
with no entry in SHA256SUMS at all. verify-release.sh would print "all 5 files
match" standing next to a .deb it had never looked at.

So: generate a throwaway PGP key, run scripts/release.sh for real, and then run
scripts/verify-release.sh against what came out.

Skips (77) without gpg.
"""
import os, re, shutil, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

if not shutil.which("gpg"):
    print("  SKIP  gpg not installed")
    sys.exit(77)

# Run against the version the download page actually advertises, so the
# artifact names on the page and the ones the build produces are the same
# question.
_page = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "..", "..", "web", "download.html")).read()
VERSION = re.search(r'/releases/([\d.]+)/', _page).group(1)
TMP = H.tempdir("0trust-release-")
GNUPGHOME = os.path.join(TMP, "gnupg")
RELEASE_DIR = os.path.join(TMP, "release")
STAGING_DIR = os.path.join(TMP, "staging")
os.makedirs(GNUPGHOME, mode=0o700)
os.makedirs(STAGING_DIR)

ENV = {**os.environ, "GNUPGHOME": GNUPGHOME,
       "RELEASE_DIR": RELEASE_DIR, "STAGING_DIR": STAGING_DIR}


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=kw.pop("cwd", H.REPO), env=ENV,
                          capture_output=True, text=True, timeout=900, **kw)


print("[1] a throwaway signing key")
batch = os.path.join(TMP, "keyspec")
open(batch, "w").write(
    "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\n"
    "Name-Real: 0trust release test\nName-Email: release-test@example.invalid\n"
    "Expire-Date: 0\n%commit\n")
r = run(["gpg", "--batch", "--generate-key", batch])
check("key generated", r.returncode == 0, r.stderr[-400:])
r = run(["gpg", "--list-secret-keys", "--with-colons"])
fpr = next((l.split(":")[9] for l in r.stdout.splitlines() if l.startswith("fpr:")), "")
check("fingerprint readable", len(fpr) == 40, fpr)
ENV["RELEASE_SIGNER_KEY"] = fpr

# The download page is the source of truth for what a release must contain.
# Bound the filename character class: an unbounded [^"]+ runs past the end of a
# <pre> block and invents artifacts like "0trust-0.1.0-linux-amd64</pre>". The
# same greediness was in release.sh's own extraction and would have made it
# refuse every release.
page = open(os.path.join(H.REPO, "web", "download.html")).read()
MANIFEST = {"SHA256SUMS", "SHA256SUMS.asc", "pubkey.asc", "build-info.txt"}
offered = sorted(set(re.findall(r'/releases/[\d.]+/([A-Za-z0-9._+-]+)', page))
                 - MANIFEST)
print(f"      download.html offers {len(offered)} artifacts for {VERSION}")

# release.sh refuses to build from a dirty tree, and rightly so: a release
# nobody else can reproduce is not a release. So give it a clean tree that is
# nonetheless the CODE UNDER TEST — clone HEAD, lay the working tree over it,
# and commit. Cloning HEAD alone silently tests whatever release.sh looked like
# at the last commit, which is exactly the trap this module fell into first
# time: it reported a passing cross-check that was not in the file yet.
WORK = os.path.join(TMP, "src")
r = subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", H.REPO, WORK],
                   capture_output=True, text=True, timeout=600)
check("pristine clone for the build", r.returncode == 0, r.stderr[-300:])

tracked = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"],
                         cwd=H.REPO, capture_output=True, text=True, timeout=120)
tar = os.path.join(TMP, "worktree.tar")
subprocess.run(["tar", "-cf", tar, "-T", "-"], cwd=H.REPO, input=tracked.stdout,
               text=True, capture_output=True, timeout=300)
subprocess.run(["tar", "-xf", tar, "-C", WORK], capture_output=True, timeout=300)
gitenv = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x",
          "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x"}
subprocess.run(["git", "add", "-A"], cwd=WORK, capture_output=True, timeout=300)
subprocess.run(["git", "commit", "-qm", "working tree"], cwd=WORK, env=gitenv,
               capture_output=True, timeout=300)
dirty = subprocess.run(["git", "status", "--porcelain"], cwd=WORK,
                       capture_output=True, text=True, timeout=120)
check("the build tree is clean and matches the working tree",
      dirty.stdout.strip() == "", dirty.stdout[:300])

print("\n[2] a release that the site over-promises is refused")
r = run(["./scripts/release.sh", VERSION], cwd=WORK)
check("release.sh fails when an offered file is missing", r.returncode != 0,
      "it signed a release that does not contain everything download.html "
      "offers — which is how the .deb shipped unverifiable")
named = [f for f in offered if f in r.stderr]
check("and names what is missing", bool(named), r.stderr[-500:])
print(f"      refused, naming: {', '.join(named[:4])}{'…' if len(named) > 4 else ''}")

print("\n[3] with the other-toolchain artifacts staged, it cuts one")
# The MSI needs Windows, the APK needs Android Studio, and the AppImage needs
# appimagetool off the network. Stand in for whatever this machine could not
# produce — taken from what release.sh itself just said was missing, so the
# test does not hardcode which toolchains happen to be installed here. What is
# under test is that release.sh signs everything the page offers, not how each
# artifact was built.
staged = [f for f in offered if f in r.stderr]
for name in staged:
    open(os.path.join(STAGING_DIR, name), "wb").write(
        b"stand-in for an artifact built on another host\n")
print(f"      staged: {', '.join(staged) or '(nothing needed)'}")
r = run(["./scripts/release.sh", VERSION], cwd=WORK)
check("release.sh succeeds", r.returncode == 0,
      (r.stdout[-800:] + r.stderr[-800:]))

if r.returncode == 0:
    listed = {}
    sums = os.path.join(RELEASE_DIR, "SHA256SUMS")
    check("SHA256SUMS written", os.path.exists(sums))
    if os.path.exists(sums):
        for line in open(sums):
            h, _, name = line.strip().partition("  ")
            listed[name] = h
    print(f"      {len(listed)} artifacts hashed")

    uncovered = [f for f in offered if f not in listed]
    check("every file the download page offers is in SHA256SUMS",
          not uncovered,
          f"{uncovered} — offered to customers, never hashed, never signed")

    for extra in ("SHA256SUMS", "SHA256SUMS.asc", "pubkey.asc", "build-info.txt"):
        check(f"{extra} is not hashed into its own manifest", extra not in listed)

    check("the signature exists",
          os.path.exists(os.path.join(RELEASE_DIR, "SHA256SUMS.asc")))
    check("the public key ships alongside",
          os.path.exists(os.path.join(RELEASE_DIR, "pubkey.asc")))

    print("\n[4] verify-release.sh, the way a customer runs it")
    v = run(["./scripts/verify-release.sh", "--release-dir", RELEASE_DIR], cwd=WORK)
    check("every artifact's checksum matches",
          f"{len(listed)} file(s) match" in v.stdout,
          v.stdout[-400:] + v.stderr[-400:])
    check("no artifact is reported missing when they are all here",
          "not in this directory" not in v.stdout, v.stdout[-300:])
    # Exit 2, not 0, while EXPECTED_KEY is a placeholder — see [6].
    check("it does not report success it did not establish",
          v.returncode == 2,
          f"rc={v.returncode}: with no fingerprint pinned, check 3 of the "
          f"three this script advertises did not run")

    print("\n[4b] the customer who downloaded ONE binary")
    # The realistic case, and the documented default ("verify ./0trust-*").
    # sha256sum -c checks every file the manifest names, so five absent
    # platforms produced "one or more files don't match SHA256SUMS" — which
    # reads as tampering, on an untampered download. A verifier that cries
    # wolf on the normal case is one people stop running.
    partial = os.path.join(WORK, "partial")
    os.makedirs(partial, exist_ok=True)
    for f in ("SHA256SUMS", "SHA256SUMS.asc", "pubkey.asc"):
        shutil.copy(os.path.join(RELEASE_DIR, f), partial)
    names = sorted(listed)
    one = next((f for f in names if f.startswith("0trust-linux-amd64")), names[0])
    shutil.copy(os.path.join(RELEASE_DIR, one), partial)

    v = run(["./scripts/verify-release.sh", "--release-dir", partial], cwd=WORK)
    check("the one binary that IS there is checked",
          "1 file(s) match" in v.stdout, v.stdout[-400:] + v.stderr[-400:])
    check("and the absent ones are named as absent, not as a mismatch",
          "not in this directory" in v.stdout and "MISMATCH" not in v.stdout
          and "don't match" not in v.stdout,
          f"an ordinary download must not read as tampering:\n"
          f"{v.stdout[-500:]}{v.stderr[-300:]}")

    print("\n[4e] the download page shows output this script can produce")
    # download.html walks the customer through downloading ONE binary and then
    # showed "[✓] all files match SHA256SUMS" — a line that session could never
    # produce, because sha256sum -c failed on the five platforms they did not
    # download. The page documented a run that could not happen, which is the
    # same claim-vs-reality failure as any other, on the page that asks people
    # to check our work.
    dl = open(os.path.join(H.REPO, "web", "download.html")).read()
    for _line in ("1 file(s) match SHA256SUMS",
                  "not in this directory"):
        check(f"download.html quotes a line the script really prints: {_line!r}",
              _line in dl,
              "the page shows output the verifier does not produce")
    check("and no longer claims 'all files match' after a one-binary download",
          "all files match SHA256SUMS" not in dl,
          "that line cannot appear when only one of the artifacts is present")
    # The other direction: the strings the page quotes have to come out of the
    # script, not just look plausible.
    vsrc = open(os.path.join(H.REPO, "scripts", "verify-release.sh")).read()
    for _line in ("file(s) match SHA256SUMS", "not in this directory",
                  "DO NOT RUN", "VERIFIED.  Safe to run."):
        check(f"verify-release.sh can actually print {_line!r}",
              _line in vsrc,
              "download.html quotes it; if the script cannot say it, one of "
              "the two is wrong")

    print("\n[4c] a tampered binary in a partial download is still caught")
    victim = os.path.join(partial, one)
    keep = open(victim, "rb").read()
    open(victim, "wb").write(keep + b"\x00tampered")
    v = run(["./scripts/verify-release.sh", "--release-dir", partial], cwd=WORK)
    check("it fails", v.returncode != 0, v.stdout[-300:])
    check("and names the file and says not to run it",
          one in (v.stdout + v.stderr) and "DO NOT RUN" in (v.stdout + v.stderr),
          (v.stdout + v.stderr)[-400:])
    open(victim, "wb").write(keep)

    print("\n[4d] a directory with none of the listed files")
    empty = os.path.join(WORK, "nothing")
    os.makedirs(empty, exist_ok=True)
    for f in ("SHA256SUMS", "SHA256SUMS.asc", "pubkey.asc"):
        shutil.copy(os.path.join(RELEASE_DIR, f), empty)
    v = run(["./scripts/verify-release.sh", "--release-dir", empty], cwd=WORK)
    check("verifying nothing is a failure, not a pass",
          v.returncode != 0,
          "zero files checked must never report VERIFIED")
    check("and it says what to do", "Download the binary" in v.stderr,
          v.stderr[-300:])

    print("\n[5] a tampered artifact is caught")
    victim = next((f for f in offered if f.endswith(".deb")), None) or offered[0]
    target = os.path.join(RELEASE_DIR, victim)
    original = open(target, "rb").read()
    open(target, "wb").write(original + b"\x00tampered")
    v = run(["./scripts/verify-release.sh", "--release-dir", RELEASE_DIR], cwd=WORK)
    check(f"editing {victim} fails verification", v.returncode != 0,
          "a modified package passed the check customers are told to run")
    open(target, "wb").write(original)

    print("\n[6] a re-signed manifest by a different key is caught")
    # The point of pinning EXPECTED_KEY. It is a DEADBEEF placeholder in the
    # repo, so the script warns rather than fails — assert it at least says so
    # out loud, because a silent pass here would be the worst outcome.
    v = run(["./scripts/verify-release.sh", "--release-dir", RELEASE_DIR], cwd=WORK)
    blob = v.stdout + v.stderr
    check("the verifier is explicit about its unpinned key",
          "placeholder" in blob or "cannot tell you the signer" in blob,
          "it neither pins a fingerprint nor says that it does not — a "
          "customer would think the key had been checked")
    # The part that was wrong: it warned on stderr and then printed
    # "VERIFIED. Safe to run." and exited 0. A check that could not run,
    # reported as one that passed — and the green line is the one a customer
    # reads. The signature being valid says the file was not altered after
    # signing; it says nothing about who signed it.
    check("and does not print an unqualified VERIFIED alongside that warning",
          "Safe to run" not in blob,
          "the last line a customer sees said the release was safe while the "
          "identity of the signer had not been established")
    check("nor exits 0, so a wrapper cannot read it as verified",
          v.returncode == 2, f"rc={v.returncode}")

print("\n[9] pinning the real fingerprints, without inventing one")
# Four placeholders across three files plus the verifier, and they are NOT the
# same key: the release key signs downloads, the canary key signs the canary,
# and security-policy.html publishes the key people ENCRYPT vulnerability
# reports to. Replacing every DEADBEEF with the release fingerprint — which is
# what the generator's own instructions used to imply — tells reporters to
# encrypt to a signing key that has no encryption subkey.
#
# The applier is exercised against a COPY of the tree. Nothing here writes a
# fingerprint into the real repo: a realistic-looking fake would pass preflight
# and send customers to verify against a key that does not exist.
import shutil as _sh

SETFPR = os.path.join(H.REPO, "scripts", "set-fingerprints.sh")
check("the applier exists", os.path.exists(SETFPR))

COPY = os.path.join(TMP, "tree")
os.makedirs(COPY, exist_ok=True)
for sub in ("scripts", "web"):
    _sh.copytree(os.path.join(H.REPO, sub), os.path.join(COPY, sub),
                 dirs_exist_ok=True)

def applier(*args, cwd=COPY):
    return subprocess.run([os.path.join(COPY, "scripts", "set-fingerprints.sh"), *args],
                          cwd=cwd, env=ENV, capture_output=True, text=True, timeout=120)

def read(rel):
    return open(os.path.join(COPY, rel), encoding="utf-8").read()

# --- it refuses what it cannot stand behind ---
r = applier("--release", "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
check("a DEADBEEF fingerprint is refused",
      r.returncode != 0 and "placeholder" in (r.stderr + r.stdout).lower(),
      (r.stderr or r.stdout)[-300:])
r = applier("--release", "NOTHEX" * 7)
check("a non-hex fingerprint is refused", r.returncode != 0,
      (r.stderr or r.stdout)[-200:])
r = applier("--release", "ABCD1234")
check("a short fingerprint is refused",
      r.returncode != 0 and "40" in (r.stderr + r.stdout),
      (r.stderr or r.stdout)[-200:])
# 40 valid hex characters for a key nobody holds.
absent = "A" * 40
r = applier("--release", absent)
check("a fingerprint this machine does not hold is refused",
      r.returncode != 0 and "does not hold" in (r.stderr + r.stdout),
      "pinning a key you cannot sign with makes every release unverifiable")
check("and nothing was written on the way to refusing",
      "DEADBEEF" in read("scripts/verify-release.sh"),
      "a rejected argument must leave the tree untouched")

# --- it applies the real thing, each key where it belongs ---
# Three distinct throwaway keys, so a swap between them is visible.
fprs = {"release": fpr}
for role in ("canary", "support"):
    spec = os.path.join(TMP, f"keyspec-{role}")
    open(spec, "w").write(
        "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\n"
        f"Name-Real: 0trust {role} test\nName-Email: {role}@example.invalid\n"
        "Expire-Date: 0\n%commit\n")
    run(["gpg", "--batch", "--generate-key", spec])
lk = run(["gpg", "--list-secret-keys", "--with-colons"])
all_fprs, uid = {}, None
for line in lk.stdout.splitlines():
    if line.startswith("fpr:"):
        last = line.split(":")[9]
    elif line.startswith("uid:"):
        for role in ("release", "canary", "support"):
            if f"0trust {role} test" in line:
                all_fprs[role] = last
check("three distinct throwaway keys exist", len(set(all_fprs.values())) == 3, all_fprs)

r = applier("--release", all_fprs["release"],
            "--canary", all_fprs["canary"],
            "--support", all_fprs["support"],
            "--jurisdiction", "Testland")
check("the applier succeeds with real keys", r.returncode == 0,
      (r.stderr or r.stdout)[-500:])

def spaced(f):
    return " ".join(f[i:i+4] for i in range(0, 40, 4))

verifier = read("scripts/verify-release.sh")
check("EXPECTED_KEY is the release fingerprint",
      f'EXPECTED_KEY="{all_fprs["release"]}"' in verifier,
      [l for l in verifier.splitlines() if "EXPECTED_KEY=" in l][:2])

dl = read("web/download.html").replace("  ", " ")
check("download.html publishes the RELEASE key",
      spaced(all_fprs["release"]) in dl)
check("and not the support key", spaced(all_fprs["support"]) not in dl)
check("and no placeholder survives on it", "DEADBEEF" not in read("web/download.html"))

pol = read("web/security-policy.html").replace("  ", " ")
check("security-policy.html publishes the SUPPORT key — the one reports are "
      "encrypted to", spaced(all_fprs["support"]) in pol)
check("and NOT the release signing key",
      spaced(all_fprs["release"]) not in pol,
      "a signing key has no encryption subkey; reporters would be stuck")

sec = read("web/.well-known/security.txt")
flat = sec.replace("  ", " ")
check("security.txt records the release key under Release signing key",
      spaced(all_fprs["release"]) in flat.split("Warrant canary")[0])
check("and the canary key under Warrant canary signing key",
      spaced(all_fprs["canary"]) in flat.split("Warrant canary")[1])
check("the jurisdiction is set", "Jurisdiction: Testland" in sec)
check("no placeholder survives in security.txt",
      "DEADBEEF" not in sec.split("BEFORE LAUNCH")[-1].split("---")[-1]
      or sec.count("DEADBEEF") == 0,
      [l for l in sec.splitlines() if "DEADBEEF" in l])

# --- and it is idempotent ---
before = read("web/download.html")
r = applier("--release", all_fprs["release"])
check("re-running changes nothing", r.returncode == 0
      and read("web/download.html") == before)

print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
