#!/usr/bin/env python3
"""
Find `producer | head` pipelines in scripts that run under `set -o pipefail`.

head exits the moment it has its N lines. Anything still writing upstream then
takes SIGPIPE, the pipeline's exit status becomes non-zero, and pipefail
propagates it — so a script that merely *displays* something can fail. Whether
it fires depends on whether the producer had finished writing, which depends on
the machine: never on an idle laptop, reliably on a loaded CI runner. Two
separate CI failures in this repo have been this exact shape.

Safe forms, all of which this accepts:
    head -N file | ...            head reads the file itself; nothing upstream
    ... | { head -N; cat >/dev/null; }   the drain absorbs the rest
    ... | head -N || true         the status is discarded
    ... | head -N) || true        same, closing a command substitution
"""
import os, re, subprocess, sys

REPO = os.environ.get(
    "ZTV_REPO",
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def strip_comment(line: str) -> str:
    """Drop a trailing `#` comment, respecting quotes.

    Without this the checker flags its own prose: a comment explaining the
    rule contains the very shape the rule forbids, and a linter that cannot
    read past a `#` is one people switch off.
    """
    out, quote = [], None
    for i, ch in enumerate(line):
        if quote:
            out.append(ch)
            if ch == quote and (i == 0 or line[i - 1] != "\\"):
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            out.append(ch)
            continue
        if ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out)


files = subprocess.run(["git", "-C", REPO, "ls-files", "*.sh"],
                       capture_output=True, text=True).stdout.split()
bad = []
for rel in files:
    path = os.path.join(REPO, rel)
    try:
        src = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    if not re.search(r'^\s*set\s+-[a-z]*\s*-?o?\s*pipefail|^\s*set\s+-o\s+pipefail',
                     src, re.M):
        continue
    for n, raw in enumerate(src.split("\n"), 1):
        line = strip_comment(raw)
        for m in re.finditer(r'\|\s*head\b', line):
            after = line[m.end():]
            # A drain, or an explicitly discarded status, is fine.
            if re.match(r'[^|]*;\s*cat\s*>\s*/dev/null', after):
                continue
            if re.search(r'\|\|\s*true', after):
                continue
            bad.append(f"{rel}:{n}: {raw.strip()}")

if bad:
    print("pipelines that can die of SIGPIPE under `set -o pipefail`:")
    for b in bad:
        print("  " + b)
    print("\nUse `head -N file | ...`, `| { head -N; cat >/dev/null; }`,")
    print("`grep -m1`, or append `|| true` if the status genuinely does not matter.")
    sys.exit(1)
