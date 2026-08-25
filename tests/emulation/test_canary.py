#!/usr/bin/env python3
"""
Generate a real warrant canary, verify it, and age it until the checker fires.

The canary is the product's loudest trust claim: privacy.html and audit.html
both point at it, and its meaning depends entirely on it being re-signed on
schedule. Nothing had ever run generate.sh or check.sh.

Two things that were wrong and would only have shown up on the day it
mattered:

  - The placeholders were filled with `sed "s|PLACEHOLDER|$value|"`, and the
    headlines are text the operator pastes in. A headline containing "|" —
    "Reuters | Something happened" is an ordinary shape — ends the expression
    and sed errors out; an "&" silently expands to the whole match. A subtly
    wrong canary is worse than a missing one.
  - check.sh aged the canary by the file's mtime. rsyncing the site,
    reinstalling the host or restoring a backup all touch the file without
    re-signing it, so a canary months stale in content read as fresh.

Skips (77) without gpg.
"""
import atexit, os, re, shutil, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

if not shutil.which("gpg"):
    print("  SKIP  gpg not installed")
    sys.exit(77)

TMP = H.tempdir("0trust-canary-")
# A gpg home under the suite's usual scratch path blows past the ~104-byte
# limit on a UNIX socket path and gpg-agent then fails to start.
GNUPGHOME = tempfile.mkdtemp(prefix="/tmp/ztvg-")
os.chmod(GNUPGHOME, 0o700)
atexit.register(shutil.rmtree, GNUPGHOME, True)
atexit.register(lambda: subprocess.run(
    ["gpgconf", "--homedir", GNUPGHOME, "--kill", "all"],
    capture_output=True, timeout=30))

WEB_ROOT = os.path.join(TMP, "www")
os.makedirs(WEB_ROOT)

# Work in a copy so the repo's own canary/build and canary/archive stay clean.
CANARY = os.path.join(TMP, "canary")
shutil.copytree(os.path.join(H.REPO, "canary"), CANARY)

ENV = {**os.environ, "GNUPGHOME": GNUPGHOME,
       "CANARY_SIGNER_NAME": "A. Operator",
       "CANARY_WEB_ROOT": WEB_ROOT}

# A headline with the characters that broke the old sed substitution, and one
# with the shell/regex metacharacters that tend to come next.
HEADLINES = [
    "Reuters | Central bank holds rates steady",
    "AP: Talks resume after 40% drop & renewed sanctions",
    "BBC — Court rules on surveillance case (2026)",
    r"Guardian: 'What now?' asks $1bn \ industry",
]


def run(cmd, stdin="", **kw):
    return subprocess.run(cmd, cwd=kw.pop("cwd", CANARY), env=ENV, input=stdin,
                          capture_output=True, text=True, timeout=300, **kw)


try:
    print("[1] a throwaway signing key")
    spec = os.path.join(TMP, "keyspec")
    open(spec, "w").write(
        "%no-protection\nKey-Type: eddsa\nKey-Curve: ed25519\n"
        "Name-Real: 0trust canary test\nName-Email: canary@example.invalid\n"
        "Expire-Date: 0\n%commit\n")
    r = run(["gpg", "--batch", "--generate-key", spec])
    check("key generated", r.returncode == 0, r.stderr[-300:])
    r = run(["gpg", "--list-secret-keys", "--with-colons"])
    fpr = next((l.split(":")[9] for l in r.stdout.splitlines()
                if l.startswith("fpr:")), "")
    check("fingerprint readable", len(fpr) == 40, fpr)
    ENV["CANARY_SIGNER_KEY"] = fpr

    print("\n[2] generate.sh, with headlines that used to break it")
    # blockchain.info is not reachable from here, which exercises the manual
    # fallback — a path that used to be dead code, because the failing grep
    # pipeline killed the script under `set -o pipefail` before reaching it.
    BLOCK = ["912345",
             "0000000000000000000123456789abcdef0123456789abcdef0123456789abcd"]
    # height, hash, 4 headlines, then the y/N confirmation.
    stdin = "\n".join(BLOCK + HEADLINES) + "\ny\n"
    r = run(["./scripts/generate.sh"], stdin=stdin)
    check("generate.sh succeeds", r.returncode == 0,
          (r.stdout[-700:] + r.stderr[-700:]))

    out = os.path.join(CANARY, "build", "canary.txt")
    check("a canary was written", os.path.exists(out))

    if os.path.exists(out):
        text = open(out).read()

        print("\n[3] the document says what it was given")
        for i, h in enumerate(HEADLINES, 1):
            check(f"headline {i} is verbatim", h in text,
                  f"expected {h!r}\n          the sed substitution mangled it")
        check("the signer name is in", "A. Operator" in text)
        check("the key fingerprint is in", fpr in text, fpr)
        check("the block reference is in", BLOCK[0] in text and BLOCK[1] in text,
              "the proof-of-freshness anchor is what dates the document")

        leftover = re.findall(
            r'HEADLINE_[0-9]|BLOCK_HEIGHT|BLOCK_HASH|WEEK_NUMBER|NEXT_DEADLINE'
            r'|ISSUED_AT|SIGNER_NAME|KEY_FINGERPRINT', text)
        check("no placeholder survived", not leftover, sorted(set(leftover)))

        m = re.search(r'^Issued at:\s*(\S+)', text, re.M)
        check("it carries a parseable issue date", m is not None,
              "check.sh ages the canary by this line")

        print("\n[4] the signature verifies")
        sig = out + ".sig"
        check("a detached signature exists", os.path.exists(sig))
        v = run(["gpg", "--verify", sig, out])
        check("gpg verifies it", v.returncode == 0, v.stderr[-400:])

        print("\n[5] it was deployed where the site serves it from")
        for name in ("canary.txt", "canary.txt.sig", "pubkey.asc"):
            check(f"{name} deployed", os.path.exists(os.path.join(WEB_ROOT, name)))
        archive = os.path.join(WEB_ROOT, "canary", "archive")
        check("and archived", os.path.isdir(archive) and bool(os.listdir(archive)))

        # nginx serves exactly these three paths plus the archive; a canary
        # deployed under a name the site does not serve is not published.
        conf = open(os.path.join(H.REPO, "nginx", "0trustvpn.com.conf")).read()
        for path in ("/canary.txt", "/canary.txt.sig", "/pubkey.asc"):
            check(f"nginx serves {path}", f"location = {path}" in conf,
                  "the generator deploys a file nothing serves")

        print("\n[6] check.sh: fresh passes, stale fires")
        live = os.path.join(WEB_ROOT, "canary.txt")
        c = run(["./scripts/check.sh"], cwd=CANARY,
                env=None) if False else subprocess.run(
            [os.path.join(CANARY, "scripts", "check.sh")],
            env={**ENV, "CANARY_PATH": live}, capture_output=True, text=True,
            timeout=120)
        check("a fresh canary passes", c.returncode == 0,
              (c.stdout + c.stderr)[-300:])

        # Age the CONTENT, leaving the mtime new — which is what a redeploy,
        # a reinstall or a restore does.
        stale = open(live).read().replace(
            m.group(1), time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                      time.gmtime(time.time() - 30 * 86400)))
        open(live, "w").write(stale)
        os.utime(live, None)          # mtime = now, content 30 days old
        c = subprocess.run([os.path.join(CANARY, "scripts", "check.sh")],
                           env={**ENV, "CANARY_PATH": live},
                           capture_output=True, text=True, timeout=120)
        check("a canary stale in content fires, even with a fresh mtime",
              c.returncode == 2,
              "check.sh is reading mtime; redeploying an old canary would "
              "silence the alarm that exists to catch exactly that")
        check("and says how old it is", "days old" in c.stderr, c.stderr[-200:])

        c = subprocess.run([os.path.join(CANARY, "scripts", "check.sh")],
                           env={**ENV, "CANARY_PATH": live + ".missing"},
                           capture_output=True, text=True, timeout=120)
        check("a missing canary is critical", c.returncode == 1, c.stderr[-200:])

finally:
    pass

print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
