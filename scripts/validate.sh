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
            sed 's/^/          /' <<<"$out" | tail -20 ;;
    esac
}

PY=python3
$PY -c 'import fastapi' >/dev/null 2>&1 || PY="$REPO_DIR/.venv/bin/python"

# ----------------------------------------------------------------------------
# Go client
# ----------------------------------------------------------------------------
check go-vet "go vet across the client" -- \
    bash -c 'cd client && CGO_ENABLED=0 go vet ./...'

check go-test "go test ./..." -- \
    bash -c 'cd client && CGO_ENABLED=0 go test ./...'

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
    ./installer/linux/deb/build.sh >/dev/null || exit 1
    [ "$(ls installer/linux/deb/out/*.deb 2>/dev/null | wc -l)" -eq 2 ]'

# ----------------------------------------------------------------------------
# Control plane
# ----------------------------------------------------------------------------
check py-parse "every .py parses" -- "$PY" -c '
import ast, glob, sys
bad = []
for f in glob.glob("**/*.py", recursive=True):
    try:
        ast.parse(open(f).read())
    except SyntaxError as e:
        bad.append(f"{f}: {e}")
if bad:
    print("\n".join(bad)); sys.exit(1)'

check api-smoke "control plane end-to-end" -- bash -c "
    \"$PY\" -c 'import fastapi' >/dev/null 2>&1 || exit 77
    \"$PY\" api/smoke_test.py"

# ----------------------------------------------------------------------------
# Scripts and markup
# ----------------------------------------------------------------------------
check sh-syntax "every .sh parses" -- bash -c '
    rc=0
    while IFS= read -r f; do bash -n "$f" || rc=1; done \
        < <(find . -name "*.sh" -not -path "./.git/*")
    exit $rc'

check html-parse "web pages + GUI assets parse" -- "$PY" -c '
import glob, html.parser
class P(html.parser.HTMLParser): pass
for f in glob.glob("web/*.html") + glob.glob("client/internal/gui/assets/*.html"):
    P().feed(open(f).read())'

check xml-parse "Android res, MSI source, SVGs parse" -- "$PY" -c '
import glob, xml.etree.ElementTree as ET
for f in (glob.glob("mobile/android/**/*.xml", recursive=True)
          + glob.glob("installer/**/*.wxs", recursive=True)
          + glob.glob("**/*.svg", recursive=True)):
    ET.parse(f)'

check yaml-parse "cloud-init node image parses" -- bash -c "
    \"$PY\" -c 'import yaml' >/dev/null 2>&1 || exit 77
    \"$PY\" -c 'import yaml; yaml.safe_load(open(\"wireguard/cloud-init-ephemeral.yaml\"))'"

# ----------------------------------------------------------------------------
# Invariants from CLAUDE.md's "recurring bug classes"
# ----------------------------------------------------------------------------
# scripts/audit-verify.sh is exempt: its list of Eyes-country codes is a
# denylist, so the stale codes belong there.
check regions-current "only zur/rey/buc appear as regions" -- bash -c '
    hits=$(grep -rnE "\b(ams|fra|lon|sto|nyc|sjc|sgp|tyo)-[0-9]+\b" \
             --exclude-dir=.git --exclude-dir=dist --exclude-dir=out . || true)
    [ -z "$hits" ] || { echo "stale region codes:"; echo "$hits"; exit 1; }'

check auth-header "clients send X-Account-Token, never Bearer" -- bash -c '
    hits=$(grep -rn "Authorization: Bearer" api client mobile || true)
    [ -z "$hits" ] || { echo "$hits"; exit 1; }'

# ----------------------------------------------------------------------------
if [[ $LIST_ONLY -eq 1 ]]; then exit 0; fi

echo
printf '  %s%d passed%s, %s%d failed%s, %s%d skipped%s\n' \
    "$GRN" "$PASS" "$NC" "$RED" "$FAIL" "$NC" "$YLW" "$SKIP" "$NC"
[[ $FAIL -eq 0 ]] || printf '  %sre-run one check: ./scripts/validate.sh <id>%s\n' "$DIM" "$NC"
exit "$FAIL"
