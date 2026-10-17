#!/usr/bin/env bash
# ============================================================================
# 0trust validation battery
# ============================================================================
# The checks CLAUDE.md describes in prose, as one command. Green across all of
# them is the bar before considering a change done.
#
#   ./scripts/validate.sh              # everything
#   ./scripts/validate.sh go api       # only checks whose id contains these
#   ./scripts/validate.sh -l           # list check ids and exit
#
# Needs: go, python3 with the api deps importable (Claude Code on the web gets
# these from .claude/hooks/session-start.sh; elsewhere, source a venv built
# from api/requirements-dev.txt). dpkg-deb is optional — the .deb check skips
# without it.
#
# Out of reach here, by design: the Android APK needs the Android SDK/NDK and
# the MSI needs a Windows host with WiX. Their sources are checked as far as
# parsing goes.
#
# Exit code is the number of failed checks, so CI can gate on it.
# ============================================================================
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; DIM=$'\033[2m'; NC=$'\033[0m'
PASS=0; FAIL=0; SKIP=0
LIST_ONLY=0; FILTER=()

for arg in "$@"; do
    case "$arg" in
        -l|--list) LIST_ONLY=1 ;;
        -*) echo "unknown flag: $arg" >&2; exit 64 ;;
        *) FILTER+=("$arg") ;;
    esac
done

# check <id> <description> -- <command...>
# Exit 0 = pass, 77 = skip (prerequisite absent), anything else = fail.
check() {
    local id="$1" desc="$2"; shift 2
    [[ "$1" == "--" ]] && shift

    if [[ ${#FILTER[@]} -gt 0 ]]; then
        local matched=0 f
        for f in "${FILTER[@]}"; do [[ "$id" == *"$f"* ]] && matched=1; done
        [[ $matched -eq 1 ]] || return 0
    fi
    if [[ $LIST_ONLY -eq 1 ]]; then printf '  %-22s %s\n' "$id" "$desc"; return 0; fi

    local out rc
    out=$("$@" 2>&1); rc=$?
    case $rc in
        0)  printf '  %sPASS%s  %-22s %s\n' "$GRN" "$NC" "$id" "$desc"; PASS=$((PASS+1)) ;;
        77) printf '  %sSKIP%s  %-22s %s\n' "$YLW" "$NC" "$id" "$desc"; SKIP=$((SKIP+1)) ;;
        *)  printf '  %sFAIL%s  %-22s %s\n' "$RED" "$NC" "$id" "$desc"; FAIL=$((FAIL+1))
            # Show the lines that actually failed, then the tail for context.
            #
            # A plain tail was useless for the one check that most needs a
            # readable log: the emulation suite prints hundreds of lines, so
            # the last 20 were the final module's PASS list and the real
            # failure — hundreds of lines earlier — never appeared in CI at
            # all. Diagnosing it meant reproducing the whole runner locally.
            #
            # -A6 and 200 lines, not -A3 and 60. Three lines of context and a
            # 60-line cap turned out to be exactly not enough to diagnose a
            # failure that only happens in CI: the summary showed a check had
            # failed and cut off before the part that said why, so the only
            # way forward was to reconstruct the runner's environment locally
            # and hope the failure reproduced. It did not.
            local hits full
            full=$(mktemp)
            printf '%s\n' "$out" > "$full"
            hits=$(grep -E -A6 'FAIL|FAILED|Traceback|Error:' "$full" \
                   | { head -200; cat >/dev/null; }) || true
            if [[ -n "$hits" ]]; then
                sed 's/^/          /' <<<"$hits"
                printf '          %s---- end of failures (full output: %s) ----%s\n' \
                       "$DIM" "$full" "$NC"
            fi
            { tail -20 "$full" | sed 's/^/          /'; } ;;
    esac
}

PY=python3
$PY -c 'import fastapi' >/dev/null 2>&1 || PY="$REPO_DIR/.venv/bin/python"

# The files the repo actually owns: tracked, plus new ones that aren't
# gitignored. Asking git rather than globbing keeps a stray venv/, dist/ or
# node_modules out of the parse checks — .gitignore already names them, and
# third-party code failing our syntax checks would be noise, not signal.
VALIDATE_FILES="$(mktemp)"; export VALIDATE_FILES
trap 'rm -f "$VALIDATE_FILES"' EXIT
if git -C "$REPO_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    # --deduplicate, and drop entries git still tracks but that are gone from
    # the working tree: a deletion you have not staged yet is a normal state to
    # run this in, and "cannot open the file you just deleted" is not a finding.
    git -C "$REPO_DIR" ls-files --cached --others --exclude-standard \
        | while IFS= read -r f; do [ -e "$REPO_DIR/$f" ] && printf '%s\n' "$f"; done \
        > "$VALIDATE_FILES"
else
    # Not a checkout (an extracted tarball, say) — approximate it.
    find . -type f -not -path './.git/*' -not -path '*/site-packages/*' \
        -not -path '*venv/*' -not -path '*/dist/*' -not -path '*/out/*' \
        -not -path '*/node_modules/*' -not -path '*/__pycache__/*' \
        | sed 's|^\./||' > "$VALIDATE_FILES"
fi

# ----------------------------------------------------------------------------
# Go client
# ----------------------------------------------------------------------------
check go-vet "go vet across the client" -- \
    bash -c 'cd client && CGO_ENABLED=0 go vet ./...'

check go-test "go test ./..." -- \
    bash -c 'cd client && CGO_ENABLED=0 go test ./...'

check go-fmt "client is gofmt clean" -- bash -c '
    out=$(cd client && gofmt -l .)
    [ -z "$out" ] || { echo "needs gofmt:"; echo "$out"; exit 1; }'

check go-crosscompile "all six release targets build" -- bash -c '
    cd client
    for p in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 \
             windows/amd64 windows/arm64; do
        os=${p%/*}; arch=${p#*/}; ext=""
        [ "$os" = "windows" ] && ext=".exe"
        CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
            -ldflags "-s -w" -o "dist/0trust-$os-$arch$ext" ./cmd/0trust || exit 1
    done'

check deb-package ".deb builds for amd64 + arm64" -- bash -c '
    command -v dpkg-deb >/dev/null || exit 77
    # Self-contained: go-crosscompile normally leaves these behind, but a
    # filtered run (./scripts/validate.sh deb) starts from an empty dist/.
    if [ ! -f client/dist/0trust-linux-amd64 ] \
    || [ ! -f client/dist/0trust-linux-arm64 ]; then
        make -C client linux >/dev/null || exit 1
    fi
    ./installer/linux/deb/build.sh >/dev/null || exit 1
    [ "$(ls installer/linux/deb/out/*.deb 2>/dev/null | wc -l)" -eq 2 ]'

# ----------------------------------------------------------------------------
# Control plane
# ----------------------------------------------------------------------------
check py-parse "every .py parses" -- "$PY" -c '
import ast, os, sys
bad = []
for f in open(os.environ["VALIDATE_FILES"]).read().splitlines():
    if not f.endswith(".py"):
        continue
    try:
        ast.parse(open(f).read())
    except SyntaxError as e:
        bad.append(f"{f}: {e}")
if bad:
    print("\n".join(bad)); sys.exit(1)'

check api-smoke "control plane end-to-end" -- bash -c "
    \"$PY\" -c 'import fastapi' >/dev/null 2>&1 || exit 77
    \"$PY\" api/smoke_test.py"

# The only check here whose result can change without anyone touching the
# repository, and that is the point: a pin that was current when it was
# written becomes a CVE on somebody else's schedule, and nothing else in this
# battery would ever notice. fastapi==0.115.0 resolved starlette 0.38.6, which
# by the time anyone looked carried nine advisories.
#
# Audits api/requirements.txt — what actually reaches the control plane — not
# the dev extras. Skips rather than fails when pip-audit is missing or the
# advisory database is unreachable, so an offline machine reports "no opinion"
# instead of a false alarm. A FAIL here means a real advisory against a
# version we ship: read it, and bump the pin.
check deps-audit "runtime deps carry no known advisories" -- bash -c '
    command -v pip-audit >/dev/null 2>&1 || exit 77
    out=$(pip-audit -r api/requirements.txt --progress-spinner off 2>&1) || true
    case "$out" in
        *"No known vulnerabilities found"*) exit 0 ;;
        *"known vulnerabilit"*) echo "$out"; exit 1 ;;
        *) echo "advisory database unreachable"; exit 77 ;;
    esac'

# Boots the real stack — control plane, meshd, the compiled client — and
# drives it. Slower than the rest of the battery put together and worth it:
# every bug this suite was written for was invisible to a parse check.
check emulation "full-stack emulation suite" -- bash -c "
    \"$PY\" -c 'import fastapi' >/dev/null 2>&1 || exit 77
    command -v go >/dev/null || exit 77
    \"$PY\" tests/emulation/run.py"

# ----------------------------------------------------------------------------
# Scripts and markup
# ----------------------------------------------------------------------------
check sh-syntax "every .sh parses" -- bash -c '
    rc=0
    while IFS= read -r f; do
        case "$f" in *.sh) bash -n "$f" || rc=1 ;; esac
    done < "$VALIDATE_FILES"
    exit $rc'

# Confirms the pages tokenize; Python's HTMLParser is lenient about tag
# nesting, so this catches malformed markup, not every structural mistake.
check html-parse "web pages + GUI assets parse" -- "$PY" -c '
import html.parser, os, sys
class P(html.parser.HTMLParser): pass
bad = []
for f in open(os.environ["VALIDATE_FILES"]).read().splitlines():
    if not f.endswith(".html"):
        continue
    try:
        P().feed(open(f).read())
    except Exception as e:
        bad.append(f"{f}: {e}")
if bad:
    print("\n".join(bad)); sys.exit(1)'

check xml-parse "Android res, MSI source, SVGs parse" -- "$PY" -c '
import os, sys, xml.etree.ElementTree as ET
bad = []
for f in open(os.environ["VALIDATE_FILES"]).read().splitlines():
    if not f.endswith((".xml", ".wxs", ".svg")):
        continue
    try:
        ET.parse(f)
    except ET.ParseError as e:
        bad.append(f"{f}: {e}")
if bad:
    print("\n".join(bad)); sys.exit(1)'

check plist-parse "iOS plists and entitlements parse" -- "$PY" -c '
import os, plistlib, sys
bad = []
for f in open(os.environ["VALIDATE_FILES"]).read().splitlines():
    if not f.endswith((".plist", ".entitlements")):
        continue
    try:
        with open(f, "rb") as fh:
            plistlib.load(fh)
    except Exception as e:
        bad.append(f"{f}: {e}")
if bad:
    print("\n".join(bad)); sys.exit(1)'

# Not a compile: there is no swiftc here and SwiftUI/NetworkExtension have no
# Linux SDK. It checks delimiters, leftover placeholders and missing imports.
# The real gate is xcodegen + xcodebuild on a Mac; the script says so itself.
check swift-structure "Swift sources are structurally sound" -- \
    ./mobile/ios/syntax-check.sh

# Font.custom does not fail on an unresolvable PostScript name — it quietly
# substitutes the system font. So a rename in Theme.swift, a face missing from
# UIAppFonts, or a file whose internal name is not what it is called on disk
# all ship an app that builds, launches and connects and simply looks wrong.
# This is the only thing that would catch it before a human noticed.
check ios-fonts "bundled iOS faces are the ones the app asks for" -- \
    ./mobile/ios/fetch-fonts.sh --check

# The sitemap names URLs nginx has to route, and the structured data restates
# prices that live in api/main.py's PRICING. Both are generated for that
# reason; these two checks are what makes "generated" mean something rather
# than "generated once, in March".
check seo-sitemap "sitemap.xml covers the routed pages and is current" -- \
    ./scripts/gen-sitemap.py --check
check seo-jsonld "structured data matches the pages and the API's prices" -- \
    ./scripts/gen-seo.py --check

# The vendored third-party JS is served from our own domain, into every
# visitor's browser, and its integrity rested on a script nothing ran:
# vendor-third-party.sh had a working --check-only mode and no gate above it.
# A file edited in place, or a hash that drifted from the manifest, went
# unnoticed. --check-only makes no network request.
check vendor-integrity "vendored third-party JS matches its pinned hashes" -- \
    ./scripts/vendor-third-party.sh --check-only

# Secrets, in HISTORY and not just the tree.
#
# test_audit.py already refuses an extended key in the working tree, and that
# check was green for months over a history containing two of them: a key
# committed once and deleted in the next commit stays in the pack and is
# handed to everyone who clones. For an extended public key there is no
# recovery — it cannot be rotated, only outrun by moving the funds.
#
# The built-in pass has no dependencies so it cannot silently not run;
# gitleaks adds breadth when installed. Exposures already registered in
# scripts/secret-scan.known are reprinted as outstanding, not waved through.
check secret-scan "no new secrets in the tree or in git history" -- \
    ./scripts/secret-scan.sh

# Static analysis against this codebase's own documented bug classes, not a
# generic pack: semgrep.dev is unreachable from the build environment, and
# the local rules know things a generic pack does not — that a blocking call
# in an `async def` is an invariant here, that this product fails closed on
# TLS rather than open. Every rule is mutation-tested; tests/sast/ztv.yml
# says so and names the two ways the SQL rule was dead on arrival.
# Skips when semgrep is absent: the tool genuinely is not there. That is a
# different thing from the SKIP-as-a-pass this project has been bitten by,
# where the component WAS present and only our config was missing.
check sast "no async-blocking, unbound SQL, or fail-open TLS" -- bash -c '
    command -v semgrep >/dev/null 2>&1 || exit 77
    j=$(mktemp); trap "rm -f $j" EXIT
    semgrep --metrics=off --config tests/sast/ztv.yml --json -o "$j" \
            api proxy wireguard btcpay canary support >/dev/null 2>&1 || true
    # Report the findings, not semgrep is own run summary: a gate whose
    # failure output does not name the file and line is one the next person
    # re-runs by hand to find out what it meant.
    python3 - "$j" <<"PYEOF"
import json, sys
try:
    rows = json.load(open(sys.argv[1]))["results"]
except Exception as e:
    print("semgrep produced no parseable report:", e); sys.exit(1)
for r in rows:
    print("  %s:%s  [%s]" % (r["path"], r["start"]["line"],
                             r["check_id"].split(".")[-1]))
    print("      " + " ".join(r["extra"]["message"].split())[:140])
sys.exit(1 if rows else 0)
PYEOF
'

# The GUI's favicon is generated from the same geometry as the MSI icon and
# the .desktop SVG, then committed. A committed generated file drifts from its
# generator the moment someone edits one of them.
check gui-favicon "the GUI favicon matches its generator" -- \
    ./scripts/gen-favicon.py --check

check json-parse "every .json parses" -- "$PY" -c '
import json, os, sys
bad = []
for f in open(os.environ["VALIDATE_FILES"]).read().splitlines():
    if not f.endswith(".json"):
        continue
    try:
        json.load(open(f))
    except json.JSONDecodeError as e:
        bad.append(f"{f}: {e}")
if bad:
    print("\n".join(bad)); sys.exit(1)'

check yaml-parse "cloud-init node image parses" -- bash -c "
    \"$PY\" -c 'import yaml' >/dev/null 2>&1 || exit 77
    \"$PY\" -c '
import sys, yaml
f = \"wireguard/cloud-init-ephemeral.yaml\"
try:
    yaml.safe_load(open(f))
except yaml.YAMLError as e:
    print(f\"{f}: {e}\"); sys.exit(1)'"

# ----------------------------------------------------------------------------
# Invariants from CLAUDE.md's "recurring bug classes"
# ----------------------------------------------------------------------------
# scripts/audit-verify.sh is exempt: its list of Eyes-country codes is a
# denylist, so the stale codes belong there.
check regions-current "only zur/rey/buc appear as regions" -- bash -c '
    hits=$(xargs -r -a "$VALIDATE_FILES" \
             grep -nE "\b(ams|fra|lon|sto|nyc|sjc|sgp|tyo)-[0-9]+\b" || true)
    [ -z "$hits" ] || { echo "stale region codes:"; echo "$hits"; exit 1; }'

# `producer | head -N` under `set -o pipefail` fails whenever the producer is
# still writing when head exits — which depends on scheduling, so it passes on
# a quiet laptop and fails on a loaded CI runner. It has cost this repo two
# CI-only failures: an installer dry run that exited non-zero halfway through
# printing a config, and audit checks that would have reported a finding
# because the check itself died.
check pipefail-head "no pipeline can die of SIGPIPE under pipefail" -- \
    "$PY" "$REPO_DIR/tests/lint/no-sigpipe-head.py"

# Our API clients authenticate with X-Account-Token; the token IS the
# credential and there is no OAuth anywhere in this product. Scoped to
# client/ and mobile/ on purpose: api/payments.py legitimately sends
# `Authorization: Bearer` to Stripe and Square, which are somebody else's
# APIs and do use bearer tokens. Comments are stripped first — the iOS client
# and the Android client both explain this rule in prose at the top of the
# file, and a check that cannot tell code from commentary fails on its own
# documentation.
check auth-header "clients send X-Account-Token, never Bearer" -- "$PY" -c '
import os, re, sys
bad = []
for f in open(os.environ["VALIDATE_FILES"]).read().splitlines():
    if not f.startswith(("client/", "mobile/")):
        continue
    if not f.endswith((".go", ".kt", ".swift", ".js", ".java")):
        continue
    try:
        text = open(f, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    in_block = False
    for n, line in enumerate(text.splitlines(), 1):
        code = line
        if in_block:
            if "*/" in code:
                code, in_block = code.split("*/", 1)[1], False
            else:
                continue
        if "/*" in code:
            head, rest = code.split("/*", 1)
            if "*/" in rest:
                code = head + rest.split("*/", 1)[1]
            else:
                code, in_block = head, True
        code = code.split("//")[0]
        if re.search(r"\bBearer\b", code) or "Authorization" in code:
            bad.append(f"{f}:{n}:{line.strip()}")
if bad:
    print("\n".join(bad)); sys.exit(1)'

# ----------------------------------------------------------------------------
if [[ $LIST_ONLY -eq 1 ]]; then exit 0; fi

echo
printf '  %s%d passed%s, %s%d failed%s, %s%d skipped%s\n' \
    "$GRN" "$PASS" "$NC" "$RED" "$FAIL" "$NC" "$YLW" "$SKIP" "$NC"
[[ $FAIL -eq 0 ]] || printf '  %sre-run one check: ./scripts/validate.sh <id>%s\n' "$DIM" "$NC"
exit "$FAIL"
