#!/usr/bin/env bash
#
# Pin the real PGP fingerprints and the operating jurisdiction across every
# file that publishes them.
#
# Four placeholders live in three files plus the verifier, and they are NOT
# all the same key:
#
#   release   scripts/verify-release.sh (EXPECTED_KEY), web/download.html,
#             web/.well-known/security.txt        — signs SHA256SUMS
#   canary    web/.well-known/security.txt        — signs the warrant canary
#   support   web/security-policy.html            — the key people ENCRYPT
#                                                    vulnerability reports to
#
# That last one matters: security-policy.html is the disclosure channel, not a
# download page. Publishing the release fingerprint there tells reporters to
# encrypt to a signing key, which has no encryption subkey and will simply
# fail for them.
#
# Nothing here invents a fingerprint. Each one must be 40 hex characters and,
# unless --no-verify-key is given, must be a key this machine actually holds —
# you cannot pin a key you do not have.
#
#   ./scripts/set-fingerprints.sh --check
#   ./scripts/set-fingerprints.sh --release ABCD…  --canary ABCD…  --support ABCD…
#   ./scripts/set-fingerprints.sh --jurisdiction "Switzerland"
#
set -euo pipefail
cd "$(dirname "$0")/.."

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; DIM=$'\033[2m'; NC=$'\033[0m'
die() { printf '%s[!] %s%s\n' "$RED" "$*" "$NC" >&2; exit 1; }
ok()  { printf '  %s✓%s %s\n' "$GRN" "$NC" "$*"; }
note(){ printf '  %s•%s %s\n' "$DIM" "$NC" "$*"; }

VERIFIER="scripts/verify-release.sh"
DOWNLOAD="web/download.html"
POLICY="web/security-policy.html"
SECTXT="web/.well-known/security.txt"

RELEASE="" CANARY="" SUPPORT="" JURIS="" CHECK=0 VERIFY_KEY=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release)        RELEASE="${2:?}"; shift 2 ;;
        --canary)         CANARY="${2:?}";  shift 2 ;;
        --support)        SUPPORT="${2:?}"; shift 2 ;;
        --jurisdiction)   JURIS="${2:?}";   shift 2 ;;
        --check)          CHECK=1; shift ;;
        --no-verify-key)  VERIFY_KEY=0; shift ;;
        -h|--help)        sed -n '2,30p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

# --- validation -------------------------------------------------------------

# A v4 OpenPGP fingerprint is 160 bits: 40 hex characters. Spaces are how gpg
# prints it, so accept and strip them.
normalise() {
    local raw="${1//[[:space:]]/}"
    raw="${raw#0x}"
    printf '%s' "${raw^^}"
}

validate() {
    local name="$1" fpr="$2"
    [[ ${#fpr} -eq 40 ]] \
        || die "$name fingerprint is ${#fpr} hex characters, not 40 — that is not a v4 OpenPGP fingerprint"
    [[ "$fpr" =~ ^[0-9A-F]{40}$ ]] \
        || die "$name fingerprint has non-hex characters in it"
    [[ "$fpr" != DEADBEEF* ]] \
        || die "$name fingerprint is still the placeholder. A realistic-looking fake is WORSE than DEADBEEF: it passes preflight and sends people to verify against a key that does not exist."
    if (( VERIFY_KEY )); then
        command -v gpg >/dev/null \
            || die "gpg is not installed, so the $name key cannot be confirmed. Re-run with --no-verify-key if you are certain."
        gpg --list-keys "$fpr" >/dev/null 2>&1 \
            || die "this machine does not hold a key with the $name fingerprint $fpr. Pinning a fingerprint you cannot produce a signature for is how a release becomes unverifiable. Use --no-verify-key only if you know why."
    fi
}

# gpg's own display: ten groups of four, wider gap in the middle.
pretty() {
    local f="$1" out="" i
    for (( i = 0; i < 40; i += 4 )); do
        out+="${f:i:4}"
        (( i == 16 )) && out+="  " || { (( i < 36 )) && out+=" "; }
    done
    printf '%s' "$out"
}

# --- state ------------------------------------------------------------------

report() {
    printf '%s0trust published identity%s\n\n' "$YLW" "$NC"
    local pinned
    # awk, not `sed | head -1`: under `set -o pipefail` a producer that
    # outlives head dies of SIGPIPE and takes the whole command with it.
    pinned=$(awk -F'"' '/^EXPECTED_KEY=/ { print $2; exit }' "$VERIFIER")
    if [[ "$pinned" == DEADBEEF* ]]; then
        printf '  %srelease%s      not pinned (%s)\n' "$RED" "$NC" "$VERIFIER"
    else
        printf '  %srelease%s      %s\n' "$GRN" "$NC" "$pinned"
    fi
    local f n
    for f in "$DOWNLOAD" "$POLICY" "$SECTXT"; do
        n=$(grep -c 'DEADBEEF' "$f" 2>/dev/null || true)
        if [[ "${n:-0}" -gt 0 ]]; then
            printf '  %s%-12s%s %s placeholder line(s) remain\n' "$RED" "$(basename "$f")" "$NC" "$n"
        else
            printf '  %s%-12s%s clean\n' "$GRN" "$(basename "$f")" "$NC"
        fi
    done
    local j
    j=$(awk '/^#[[:space:]]*Jurisdiction:/ {
              sub(/^#[[:space:]]*Jurisdiction:[[:space:]]*/, ""); print; exit }' "$SECTXT")
    if [[ -z "$j" || "$j" == "TO BE CONFIRMED" ]]; then
        printf '  %sjurisdiction%s TO BE CONFIRMED — terms.html §9 makes this the governing law\n' "$RED" "$NC"
    else
        printf '  %sjurisdiction%s %s\n' "$GRN" "$NC" "$j"
    fi
}

if (( CHECK )) || [[ -z "$RELEASE$CANARY$SUPPORT$JURIS" ]]; then
    report
    (( CHECK )) && exit 0
    printf '\n%sNothing to do. Pass --release/--canary/--support/--jurisdiction.%s\n' "$DIM" "$NC"
    exit 0
fi

# Rewrite in place only after every value has been checked, so a bad argument
# never leaves the tree half-updated.
[[ -n "$RELEASE" ]] && { RELEASE=$(normalise "$RELEASE"); validate release "$RELEASE"; }
[[ -n "$CANARY"  ]] && { CANARY=$(normalise "$CANARY");   validate canary  "$CANARY"; }
[[ -n "$SUPPORT" ]] && { SUPPORT=$(normalise "$SUPPORT"); validate support "$SUPPORT"; }

sub() {  # file, python-expression-safe replacement
    local file="$1" py="$2"
    RE_FILE="$file" RE_PY="$py" python3 - "$file" <<'PY'
import os, sys, io
path = sys.argv[1]
src = open(path, encoding="utf-8").read()
exec(os.environ["RE_PY"])          # defines `out`
if out != src:
    tmp = path + ".tmp"
    with io.open(tmp, "w", encoding="utf-8") as fh:
        fh.write(out)
    os.replace(tmp, path)          # atomic
    print("changed")
PY
}

if [[ -n "$RELEASE" ]]; then
    P=$(pretty "$RELEASE")
    RELEASE="$RELEASE" python3 - "$VERIFIER" <<'PY'
import os, re, sys
p = sys.argv[1]; s = open(p).read()
s2 = re.sub(r'^EXPECTED_KEY=".*"$', 'EXPECTED_KEY="%s"' % os.environ["RELEASE"],
            s, count=1, flags=re.M)
open(p, "w").write(s2)
PY
    ok "release key pinned in $VERIFIER"

    FPR="$P" python3 - "$DOWNLOAD" <<'PY'
import os, re, sys
p = sys.argv[1]; s = open(p).read(); f = os.environ["FPR"]
short = f.split()[0] + f.split()[1]
s = s.replace("DEADBEEF DEADBEEF DEADBEEF DEADBEEF DEADBEEF DEADBEEF", f)
s = s.replace("DEADBEEF...REPLACE-ME", short + "...")
open(p, "w").write(s)
PY
    ok "release fingerprint published on $DOWNLOAD"

    FPR="$P" python3 - "$SECTXT" <<'PY'
import os, re, sys
p = sys.argv[1]; s = open(p).read()
s = re.sub(r'(# Release signing key[^\n]*\n#\s+)DEADBEEF(?: DEADBEEF)*',
           lambda m: m.group(1) + os.environ["FPR"], s, count=1)
open(p, "w").write(s)
PY
    ok "release fingerprint recorded in $SECTXT"

    # The header carries a BEFORE LAUNCH instruction naming DEADBEEF. Left
    # alone it outlives its own completion: the operator does exactly what it
    # says, and web-no-placeholder-fpr still fails forever because the gate
    # greps this file for the word. Retire the instruction once it has been
    # carried out, keeping the half that is still true — the file wants
    # signing after the fingerprints go in.
    python3 - "$SECTXT" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p, encoding="utf-8").read()
s = re.sub(
    r"# BEFORE LAUNCH, replace both DEADBEEF fingerprints and the entity line, then\n# sign this file:\n",
    "# The fingerprints and the entity line below are set. Sign this file so\n"
    "# they cannot be edited in transit:\n",
    s, count=1)
open(p, "w", encoding="utf-8").write(s)
PY
fi

if [[ -n "$CANARY" ]]; then
    FPR="$(pretty "$CANARY")" python3 - "$SECTXT" <<'PY'
import os, re, sys
p = sys.argv[1]; s = open(p).read()
s = re.sub(r'(# Warrant canary signing key[^\n]*\n#\s+)DEADBEEF(?: DEADBEEF)*',
           lambda m: m.group(1) + os.environ["FPR"], s, count=1)
open(p, "w").write(s)
PY
    ok "canary fingerprint recorded in $SECTXT"
fi

if [[ -n "$SUPPORT" ]]; then
    FPR="$(pretty "$SUPPORT")" python3 - "$POLICY" <<'PY'
import os, sys
p = sys.argv[1]; s = open(p).read()
s = s.replace("DEADBEEF DEADBEEF DEADBEEF DEADBEEF DEADBEEF DEADBEEF",
              os.environ["FPR"])
open(p, "w").write(s)
PY
    ok "support (disclosure) fingerprint published on $POLICY"
fi

if [[ -n "$JURIS" ]]; then
    JUR="$JURIS" python3 - "$SECTXT" <<'PY'
import os, re, sys
p = sys.argv[1]; s = open(p).read()
s = re.sub(r'^(#\s+Jurisdiction:\s*).*$', lambda m: m.group(1) + os.environ["JUR"],
           s, count=1, flags=re.M)
open(p, "w").write(s)
PY
    ok "jurisdiction set to \"$JURIS\" in $SECTXT"
    note "terms.html §9 defers the governing law to this line — have a lawyer read it."
fi

printf '\n'
report
printf '\n%sNext: re-sign security.txt with the release key, then ./scripts/preflight.sh%s\n' "$DIM" "$NC"
