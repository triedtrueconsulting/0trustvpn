#!/usr/bin/env python3
"""
Every `0trust ...` command the CLI PRINTS as advice must actually exist.

sweep.py once told every expiring customer to run `0trust topup` when no such
subcommand existed, and the test for it asserted the notice CONTAINED the
string — so it watched the words and not whether they meant anything.
test_site.py's [renewal] block now reads commands back out of sweep.py and
requires each to resolve.

The CLI prints advice too, and nothing checked it. Writing the path-MTU probe
produced the same defect within minutes: the diagnosis told the customer to
run `sudo 0trust connect --mtu 1280`, and `--mtu` did not exist. A customer
on a network that cannot carry a full-size packet would have been handed a
correct diagnosis and an invalid command — worse than no advice, because it
reads as a fix.

So: lift every "0trust <subcommand>" and every "--flag" out of the strings
the client prints, and require each to be something the dispatcher or the
flag parsers really accept.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAIN = ROOT / "client" / "cmd" / "0trust" / "main.go"
GUI = ROOT / "client" / "internal" / "gui" / "gui.go"

src = MAIN.read_text()

# What the dispatcher really handles: `case "login":` inside the command
# switch. Taking them from the source rather than restating them is the point
# — a hand-kept list here would be the second copy that drifts.
subcommands = set(re.findall(r'^\tcase "([a-z-]+)"(?:, "([a-z-]+)")?:',
                             src, re.M))
subs = {a for pair in subcommands for a in pair if a}
# Flags: `case a == "--kill-switch":` and `a == "--exit" && ...`
flags = set(re.findall(r'a == "(--[a-z-]+)"', src))
# Plus flags consumed by subcommand parsers elsewhere in the file.
flags |= set(re.findall(r'args\[0\] == "(--[a-z-]+)"', src))

if not subs or not flags:
    print("advice-resolves: could not read the dispatcher — refusing to pass",
          file=sys.stderr)
    sys.exit(2)

# Strings the program prints. Only double-quoted Go literals on lines that
# are clearly output, so ordinary identifiers are not mistaken for advice.
printed = []
for path in (MAIN, GUI):
    if not path.exists():
        continue
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if not re.search(r'\b(Print|Printf|Println|Sprintf|Errorf)\b', line):
            continue
        for lit in re.findall(r'"((?:[^"\\]|\\.)*)"', line):
            printed.append((path, n, lit))

bad = []
for path, n, lit in printed:
    # "0trust <word>" — the word has to be a subcommand.
    for sub in re.findall(r'\b0trust ([a-z][a-z-]+)', lit):
        if sub in ("connect", "disconnect"):      # always present
            continue
        if sub not in subs:
            bad.append(f"{path.name}:{n}: advises `0trust {sub}`, "
                       f"which the dispatcher does not handle")
    # Any long flag named in advice has to be one we parse.
    for fl in re.findall(r'(--[a-z][a-z-]+)', lit):
        if fl in flags:
            continue
        # Flags belonging to other programs the advice legitimately names.
        if fl in ("--mode", "--domain", "--email", "--wallet", "--backup-key",
                  "--provision-token", "--obfs-port", "--admin-allow",
                  "--refresh-node-files", "--no-vpn", "--dry-run", "--check",
                  "--release", "--canary", "--support", "--help", "--version",
                  "--status", "--repo", "--pin", "--no-verify-key"):
            continue
        bad.append(f"{path.name}:{n}: advises `{fl}`, which no flag parser "
                   f"in main.go accepts")

if bad:
    print("Advice naming something that does not exist:\n", file=sys.stderr)
    for b in sorted(set(bad)):
        print("  " + b, file=sys.stderr)
    print("\nA correct diagnosis with an invalid command is worse than no "
          "advice: it reads as a fix. Add the flag, or change the message.",
          file=sys.stderr)
    sys.exit(1)

print(f"advice-resolves: {len(printed)} printed strings, "
      f"{len(subs)} subcommands and {len(flags)} flags, all resolve")
