#!/usr/bin/env bash
# ============================================================================
# 0trust warrant canary generator
# ============================================================================
# Run weekly. Generates a fresh canary from the template, fills in proof-of-
# freshness headlines and a Bitcoin block hash, prompts you to PGP-sign it,
# and stages it for deployment.
#
# Designed to be run interactively by a human — the signing key MUST be
# operated by a person, never automated, or the canary loses its meaning.
#
# Usage:
#   sudo ./canary/scripts/generate.sh
#
# Required env:
#   CANARY_SIGNER_NAME    "Your Name"
#   CANARY_SIGNER_KEY     PGP key fingerprint to sign with
#   CANARY_WEB_ROOT       defaults to /var/www/0trust
# ============================================================================
set -euo pipefail

CANARY_SIGNER_NAME="${CANARY_SIGNER_NAME:?Set CANARY_SIGNER_NAME=\"Your Name\"}"
CANARY_SIGNER_KEY="${CANARY_SIGNER_KEY:?Set CANARY_SIGNER_KEY=<your PGP fingerprint>}"
CANARY_WEB_ROOT="${CANARY_WEB_ROOT:-/var/www/0trust}"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$REPO_DIR/templates/canary.txt"

log() { printf '\033[1;33m[+] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;31m[!] %s\033[0m\n' "$*" >&2; }

[[ -f "$TEMPLATE" ]] || { warn "template missing at $TEMPLATE"; exit 1; }

# ----------------------------------------------------------------------------
log "Computing dates"
# ----------------------------------------------------------------------------
NOW_UTC=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
WEEK_NUMBER=$(date -u +"%G-W%V")
WEEK_START=$(date -u -d "monday this week" +"%Y-%m-%d" 2>/dev/null \
             || date -u +"%Y-%m-%d")   # macOS date doesn't take -d "monday"
WEEK_END=$(date -u -d "$WEEK_START +6 days" +"%Y-%m-%d" 2>/dev/null \
             || date -u -v+6d -j -f "%Y-%m-%d" "$WEEK_START" +"%Y-%m-%d")
NEXT_DEADLINE=$(date -u -d "$WEEK_END +7 days" +"%Y-%m-%d" 2>/dev/null \
             || date -u -v+13d -j -f "%Y-%m-%d" "$WEEK_START" +"%Y-%m-%d")

# ----------------------------------------------------------------------------
log "Fetching proof-of-freshness data"
# ----------------------------------------------------------------------------

# Bitcoin block height + hash from blockchain.info (no auth required, public API)
# `|| true` on every step, deliberately. The script runs under `set -euo
# pipefail`, so an unreachable blockchain.info made the grep pipeline fail and
# killed the script outright — the "enter it manually" fallback written
# directly below could never be reached. The one job of this block is to
# degrade to asking a human.
# CANARY_BLOCK_HEIGHT / CANARY_BLOCK_HASH short-circuit the fetch entirely,
# for an operator scripting this or reading the block from somewhere they
# trust more. CANARY_BLOCK_URL repoints the lookup.
BLOCK_URL="${CANARY_BLOCK_URL:-https://blockchain.info/latestblock}"
if [[ -n "${CANARY_BLOCK_HEIGHT:-}" && -n "${CANARY_BLOCK_HASH:-}" ]]; then
    BLOCK_INFO='{}'
else
    BLOCK_INFO=$(curl -fsS --max-time 20 "$BLOCK_URL" 2>/dev/null || echo '{}')
fi
BLOCK_HEIGHT="${CANARY_BLOCK_HEIGHT:-$(echo "$BLOCK_INFO" \
               | grep -om1 -E '"height":[0-9]+' | grep -oE '[0-9]+' || true)}"
BLOCK_HASH="${CANARY_BLOCK_HASH:-$(echo "$BLOCK_INFO" \
             | grep -om1 -E '"hash":"[a-f0-9]+"' \
             | sed 's/.*"\([a-f0-9]*\)"/\1/' || true)}"

if [[ -z "$BLOCK_HEIGHT" || -z "$BLOCK_HASH" ]]; then
    warn "Could not fetch Bitcoin block info — please enter manually."
    warn "Latest block: https://mempool.space/  (height and hash)"
    read -r -p "Block height: " BLOCK_HEIGHT
    read -r -p "Block hash: " BLOCK_HASH
fi
[[ -n "$BLOCK_HEIGHT" && -n "$BLOCK_HASH" ]] \
    || { warn "a canary with no block reference proves nothing about when it was signed"; exit 1; }

# News headlines — you MUST review and verify these are real, current
echo ""
log "Provide 4 current-news headlines (paste any URL, then enter)"
echo "These prove this document could not have been signed before today."
echo "Pick ones likely to remain referenceable (BBC, Reuters, AP). Trim each to ~80 chars."
echo ""
HEADLINES=()
for i in 1 2 3 4; do
    # -r, because a pasted headline is literal text: without it read eats
    # backslashes, so "asks $1bn \ industry" silently loses a character from
    # a document whose whole value is being exactly what was signed.
    read -r -p "Headline #$i: " line
    HEADLINES+=("$line")
done

# ----------------------------------------------------------------------------
log "Rendering canary"
# ----------------------------------------------------------------------------
WORK_DIR="$REPO_DIR/build"
mkdir -p "$WORK_DIR" "$REPO_DIR/archive"

CANARY_FILE="$WORK_DIR/canary.txt"
cp "$TEMPLATE" "$CANARY_FILE"

# Substitute all the placeholders — literally.
#
# These were `sed "s|PLACEHOLDER|$value|"`, which treats the replacement as a
# sed expression. A headline is operator-pasted text: "Reuters | Something
# happened" ends the expression early and sed errors out, and an "&" anywhere
# in it silently expands to the whole matched text. Getting the canary subtly
# wrong is worse than failing to produce one, so replace literally.
subst() {   # subst <placeholder> <literal replacement>
    local ph="$1" rep="$2"
    ph="$ph" rep="$rep" awk '
        {
            out = ""; line = $0
            while ((i = index(line, ENVIRON["ph"])) > 0) {
                out  = out substr(line, 1, i - 1) ENVIRON["rep"]
                line = substr(line, i + length(ENVIRON["ph"]))
            }
            print out line
        }' "$CANARY_FILE" > "$CANARY_FILE.tmp"
    mv "$CANARY_FILE.tmp" "$CANARY_FILE"
}

subst "WEEK_NUMBER"              "$WEEK_NUMBER"
subst "YYYY-MM-DD to YYYY-MM-DD" "$WEEK_START to $WEEK_END"
subst "NEXT_DEADLINE"            "$NEXT_DEADLINE"
subst "ISSUED_AT"                "$NOW_UTC"
subst "SIGNER_NAME"              "$CANARY_SIGNER_NAME"
subst "BLOCK_HEIGHT"             "$BLOCK_HEIGHT"
subst "BLOCK_HASH"               "$BLOCK_HASH"
subst "HEADLINE_1"               "${HEADLINES[0]}"
subst "HEADLINE_2"               "${HEADLINES[1]}"
subst "HEADLINE_3"               "${HEADLINES[2]}"
subst "HEADLINE_4"               "${HEADLINES[3]}"
subst "KEY_FINGERPRINT"          "$CANARY_SIGNER_KEY"

# Nothing may go out with a placeholder still in it.
if leftover=$(grep -nE 'HEADLINE_[0-9]|BLOCK_HEIGHT|BLOCK_HASH|WEEK_NUMBER|NEXT_DEADLINE|ISSUED_AT|SIGNER_NAME|KEY_FINGERPRINT' "$CANARY_FILE"); then
    warn "unsubstituted placeholders remain:"
    printf '%s\n' "$leftover" >&2
    exit 1
fi

# ----------------------------------------------------------------------------
log "Review before signing"
# ----------------------------------------------------------------------------
cat "$CANARY_FILE"
echo ""
read -r -p "Sign this canary now? [y/N] " ans
[[ "$ans" =~ ^[Yy]$ ]] || { warn "aborted by operator"; exit 1; }

# ----------------------------------------------------------------------------
log "Signing with PGP key $CANARY_SIGNER_KEY"
# ----------------------------------------------------------------------------
# Detached signature so the .txt remains human-readable
rm -f "$CANARY_FILE.sig"
gpg --local-user "$CANARY_SIGNER_KEY" \
    --output "$CANARY_FILE.sig" \
    --detach-sign --armor \
    "$CANARY_FILE"

# Verify our own signature before deploying
gpg --verify "$CANARY_FILE.sig" "$CANARY_FILE"

# ----------------------------------------------------------------------------
log "Archiving and staging for deploy"
# ----------------------------------------------------------------------------
cp "$CANARY_FILE"     "$REPO_DIR/archive/canary-$WEEK_NUMBER.txt"
cp "$CANARY_FILE.sig" "$REPO_DIR/archive/canary-$WEEK_NUMBER.txt.sig"

# Export public key for inclusion on the site
PUBKEY_FILE="$WORK_DIR/pubkey.asc"
gpg --armor --export "$CANARY_SIGNER_KEY" > "$PUBKEY_FILE"

if [[ -d "$CANARY_WEB_ROOT" ]]; then
    install -m 0644 "$CANARY_FILE"     "$CANARY_WEB_ROOT/canary.txt"
    install -m 0644 "$CANARY_FILE.sig" "$CANARY_WEB_ROOT/canary.txt.sig"
    install -m 0644 "$PUBKEY_FILE"     "$CANARY_WEB_ROOT/pubkey.asc"
    mkdir -p "$CANARY_WEB_ROOT/canary/archive"
    cp "$REPO_DIR/archive/canary-$WEEK_NUMBER".* "$CANARY_WEB_ROOT/canary/archive/"
    log "Deployed to $CANARY_WEB_ROOT"
else
    warn "$CANARY_WEB_ROOT doesn't exist; canary is staged in $WORK_DIR but NOT deployed."
    log "Files ready:"
    ls -la "$WORK_DIR"
fi

cat <<EOF

  Canary published for week $WEEK_NUMBER.
  Next signing deadline: $NEXT_DEADLINE

  Verify publicly:
    curl https://0trustvpn.com/canary.txt
    curl https://0trustvpn.com/canary.txt.sig
    curl https://0trustvpn.com/pubkey.asc
    gpg --import pubkey.asc
    gpg --verify canary.txt.sig canary.txt

EOF
