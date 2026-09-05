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

And three more that only showed up by running the whole weekly ritual on a day
that was not a Monday:

  - `date -d "monday this week"` is not the Monday of this week. GNU date
    resolves it to the NEXT Monday on every day except Monday, so a canary
    signed on a Saturday claimed a period beginning two days in the future,
    labelled with a week number that contradicted it.
  - check.sh raised CRITICAL at a flat 7 days from signing, while the document
    published a deadline 7 to 13 days out. A correctly operated canary set the
    alarm off every week.
  - 0trust-canary-check.service runs $PREFIX/canary/scripts/check.sh and
    nothing ever put a canary script under $PREFIX. The timer reported active
    and the check failed 203/EXEC nightly.

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
       "CANARY_WEB_ROOT": WEB_ROOT,
       # Point the block lookup at nothing, so the manual fallback below is
       # exercised on every machine. The test used to rely on this host having
       # no route to blockchain.info: where the fetch SUCCEEDED — a CI runner
       # with ordinary internet — the two block lines fed on stdin were never
       # consumed, every later answer shifted up by two, and the run ended
       # with a headline being read as the y/N confirmation. Green here, red
       # there, for a reason nothing in the output explained.
       "CANARY_BLOCK_URL": "http://127.0.0.1:1/latestblock"}

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
    # The block lookup is pointed at a closed port, which exercises the manual
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

        # The period, the week label and the deadline are computed separately
        # and have to agree. They did not: signed on any day but a Monday, the
        # document swore statements "as of the issue time" over a week that
        # had not started, under a week number belonging to a different week.
        per = re.search(r'^Period:\s+(\S+) \((\d{4}-\d\d-\d\d) to '
                        r'(\d{4}-\d\d-\d\d)\)', text, re.M)
        nxt = re.search(r'^Next signing:\s+(\d{4}-\d\d-\d\d)', text, re.M)
        check("it states a period and a deadline", per and nxt)
        if per and nxt and m:
            import datetime as _dt
            label, a, b = per.group(1), *(
                _dt.date.fromisoformat(x) for x in per.group(2, 3))
            deadline = _dt.date.fromisoformat(nxt.group(1))
            issued = _dt.datetime.strptime(
                m.group(1), "%Y-%m-%dT%H:%M:%SZ").date()
            check("the period is the week it is labelled with",
                  label == a.strftime("%G-W%V"),
                  f"{label} labels a period starting in {a.strftime('%G-W%V')}")
            check("the period runs Monday to Sunday",
                  a.isoweekday() == 1 and (b - a).days == 6, f"{a}..{b}")
            check("the issue date falls inside the period it swears to",
                  a <= issued <= b,
                  f"issued {issued}, period {a}..{b} — statements sworn "
                  f"'as of the issue time' over days that had not happened")
            check("the deadline is after the period ends", deadline > b,
                  f"deadline {deadline}, period ends {b}")

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

        print("\n[6] check.sh judges the canary by the deadline it published")
        import datetime as _d
        live = os.path.join(WEB_ROOT, "canary.txt")
        original = open(live).read()

        def run_check(path):
            return subprocess.run(
                [os.path.join(CANARY, "scripts", "check.sh")],
                env={**ENV, "CANARY_PATH": path},
                capture_output=True, text=True, timeout=120)

        def staged(name, issued_days_ago, deadline_in_days):
            """Write a copy of the live canary with both dates moved."""
            t = original
            t = re.sub(r'^Issued at:.*',
                       "Issued at:        " + (
                           _d.datetime.now(_d.timezone.utc)
                           - _d.timedelta(days=issued_days_ago)
                       ).strftime("%Y-%m-%dT%H:%M:%SZ"), t, flags=re.M)
            t = re.sub(r'^Next signing:.*',
                       "Next signing:     " + (
                           _d.date.today() + _d.timedelta(days=deadline_in_days)
                       ).isoformat(), t, flags=re.M)
            q = os.path.join(TMP, f"canary-{name}.txt")
            open(q, "w").write(t)
            os.utime(q, None)          # mtime always fresh
            return q

        c = run_check(live)
        check("a fresh canary passes", c.returncode == 0,
              (c.stdout + c.stderr)[-300:])

        # The false alarm this replaced. A canary signed eight days ago whose
        # published deadline is still five days away is being operated exactly
        # as designed; the old flat 7-day age limit called it CRITICAL. An
        # alarm that fires weekly on correct operation is one the operator
        # learns to ignore, and it guards the document customers are told to
        # read as a duress signal.
        c = run_check(staged("midcycle", issued_days_ago=8, deadline_in_days=5))
        check("a canary inside its own deadline is silent", c.returncode == 0,
              f"exit {c.returncode}: {(c.stdout + c.stderr)[-200:]}")

        # Due soon is information, not an incident: a non-zero exit here puts
        # the systemd unit into failed state over a canary that is still valid.
        c = run_check(staged("soon", issued_days_ago=6, deadline_in_days=1))
        check("an approaching deadline warns without failing",
              c.returncode == 0 and "NOTICE" in c.stderr,
              f"exit {c.returncode}: {(c.stdout + c.stderr)[-200:]}")

        # Genuinely late — and the mtime is fresh, which is what a redeploy,
        # a reinstall or a restore does.
        q = staged("overdue", issued_days_ago=30, deadline_in_days=-16)
        c = run_check(q)
        check("a canary past its deadline fires, even with a fresh mtime",
              c.returncode == 2,
              "redeploying an old canary would otherwise silence the alarm "
              "that exists to catch exactly that")
        check("and says it is past the published deadline",
              "past its published signing deadline" in c.stderr,
              c.stderr[-200:])

        # No deadline line at all: fall back to the issue age, and say so
        # rather than quietly passing.
        q = os.path.join(TMP, "canary-nodeadline.txt")
        aged = re.sub(r'^Issued at:.*',
                      "Issued at:        " + time.strftime(
                          "%Y-%m-%dT%H:%M:%SZ",
                          time.gmtime(time.time() - 30 * 86400)),
                      original, flags=re.M)
        open(q, "w").write(re.sub(r'^Next signing:.*\n', "", aged, flags=re.M))
        c = run_check(q)
        check("an unreadable deadline falls back to the issue age loudly",
              c.returncode == 2 and "could not read 'Next signing:'" in c.stderr,
              f"exit {c.returncode}: {c.stderr[-300:]}")

        c = run_check(live + ".missing")
        check("a missing canary is critical", c.returncode == 1, c.stderr[-200:])

        print("\n[6b] the alarm's unit runs a path the deploy produces")
        # `systemctl enable --now` on a timer succeeds whether or not the
        # service it triggers can exec anything. This one pointed at
        # $PREFIX/canary/scripts/check.sh while every canary script lived only
        # in the source checkout: active timer, 203/EXEC every night.
        unit = open(os.path.join(H.REPO, "canary", "systemd",
                                 "0trust-canary-check.service")).read()
        exec_start = re.search(r'^ExecStart=(\S+)', unit, re.M)
        check("the unit declares an ExecStart", exec_start is not None)
        if exec_start:
            target = exec_start.group(1)
            installer = open(os.path.join(H.REPO, "scripts", "install.sh")).read()
            rel = target.replace("/opt/0trust/", "")
            check(f"install.sh stages {rel}",
                  f'"$PREFIX/{rel}"' in installer,
                  f"{target} is never created — the timer would fail 203/EXEC "
                  f"nightly while reporting active")
            launch = open(os.path.join(H.REPO, "docs", "LAUNCH.md")).read()
            check("LAUNCH.md points the operator at the installed generator",
                  "/opt/0trust/canary/scripts/generate.sh" in launch,
                  "the runbook and the unit disagree about where the canary "
                  "scripts live")

    print("\n[7] the block reference can be supplied instead of fetched")
    # An operator scripting the weekly signing, or one who would rather read
    # the block from a source they trust than from blockchain.info, should not
    # have to answer two prompts to do it.
    ENV2 = {**ENV, "CANARY_BLOCK_HEIGHT": "913000",
            "CANARY_BLOCK_HASH": "0" * 60 + "beef"}
    r2 = subprocess.run(["bash", os.path.join(CANARY, "scripts", "generate.sh")],
                        cwd=CANARY, env=ENV2,
                        input="\n".join(HEADLINES) + "\ny\n",
                        capture_output=True, text=True, timeout=300)
    check("generate.sh prompts only for the headlines", r2.returncode == 0,
          (r2.stdout[-400:] + r2.stderr[-400:]))
    if r2.returncode == 0:
        txt = open(os.path.join(CANARY, "build", "canary.txt")).read()
        check("the supplied block is the one in the document",
              "913000" in txt and "beef" in txt, txt[:400])

finally:
    pass

print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
