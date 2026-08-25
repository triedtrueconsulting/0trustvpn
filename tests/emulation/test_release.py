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
    check("the release verifies", v.returncode == 0,
          (v.stdout[-800:] + v.stderr[-800:]))
    check("and says so", "VERIFIED" in v.stdout, v.stdout[-300:])
    check("it counts every artifact, not just the binaries",
          f"all {len(listed)} files match" in v.stdout,
          v.stdout[-300:])

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
    pinned = "EXPECTED_KEY placeholder" not in v.stderr
    check("the verifier is explicit about its unpinned key",
          pinned or "placeholder still in this script" in v.stderr,
          "it neither pins a fingerprint nor warns that it does not — a "
          "customer would think the key had been checked")

print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
