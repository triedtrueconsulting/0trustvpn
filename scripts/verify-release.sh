#!/usr/bin/env bash
# ============================================================================
# 0trust release verifier
# ============================================================================
# Verifies that a downloaded 0trust client binary matches a PGP-signed
# checksums file. Designed for users to run BEFORE running the binary.
#
# Usage:
#   ./verify-release.sh                          # verify ./0trust-*
#   ./verify-release.sh /path/to/binary          # verify a specific file
#   ./verify-release.sh --release-dir ./0.1.0    # verify a full release dir
#
# What it checks:
#   1. SHA256SUMS exists and matches the binary's sha256
#   2. SHA256SUMS.asc is a valid PGP signature on SHA256SUMS
#   3. The signing key matches the expected release key fingerprint
#
# What it does NOT do:
#   - Confirm the operator is who you think they are. Trust is established
#     by you having verified the operator's PGP key out-of-band (e.g. via
#     keys.openpgp.org, the project's .well-known/security.txt, or in-person).
#
# Pinned expected fingerprint — UPDATE this when the project rolls keys:
EXPECTED_KEY="DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
# ============================================================================
set -euo pipefail

GRN=$'\033[1;32m'; RED=$'\033[1;31m'; YLW=$'\033[1;33m'; NC=$'\033[0m'
ok()   { printf "${GRN}[✓]${NC} %s\n" "$*"; }
warn() { printf "${YLW}[!]${NC} %s\n" "$*" >&2; }
fail() { printf "${RED}[✗]${NC} %s\n" "$*" >&2; exit 1; }

# ----------------------------------------------------------------------------
# Parse args
# ----------------------------------------------------------------------------
RELEASE_DIR="."
TARGET=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --release-dir) RELEASE_DIR="$2"; shift 2 ;;
        --help|-h)
            sed -n '3,/^# =\+$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) TARGET="$1"; shift ;;
    esac
done

[[ -d "$RELEASE_DIR" ]] || fail "release dir not found: $RELEASE_DIR"
cd "$RELEASE_DIR"

# ----------------------------------------------------------------------------
# Required files present?
# ----------------------------------------------------------------------------
[[ -f SHA256SUMS     ]] || fail "SHA256SUMS missing from $(pwd)"
[[ -f SHA256SUMS.asc ]] || fail "SHA256SUMS.asc missing — release is unsigned"

# ----------------------------------------------------------------------------
# Verify the PGP signature
# ----------------------------------------------------------------------------
command -v gpg >/dev/null || fail "gpg not installed.  Install with: apt-get install -y gnupg"

# Can we check the signature at all, or is the signing key simply absent?
#
# This used to ask `gpg --list-keys "$EXPECTED_KEY"`, which is a different
# question: EXPECTED_KEY is a DEADBEEF placeholder until the operator pins a
# real fingerprint, so the answer was always "no" and the script always stopped
# to prompt — including when the key WAS in the keyring and verification would
# have succeeded. Piped or run from a script, `read` got EOF and it failed
# outright. Ask whether the signature verifies instead.
if ! gpg --verify SHA256SUMS.asc SHA256SUMS >/dev/null 2>&1; then
    if [[ -f pubkey.asc ]]; then
        warn "Signing key not in your keyring."
        warn "pubkey.asc is here — fingerprint:"
        gpg --with-fingerprint --show-keys pubkey.asc 2>&1 | grep -E "(uid|fingerprint|sub)"
        echo ""
        warn "Before importing, verify this fingerprint matches the one published at:"
        warn "  https://0trustvpn.com/.well-known/security.txt"
        warn "  (and ideally one out-of-band source — Twitter, Mastodon, etc.)"
        echo ""
        # Importing a key is a trust decision and it is the customer's to make.
        # With no terminal there is nobody to make it, so say what to run rather
        # than reading EOF and calling that a "no".
        if [[ "${ASSUME_YES:-}" == "1" ]]; then
            warn "ASSUME_YES=1 — importing without asking"
            gpg --import pubkey.asc
        elif [[ -t 0 ]]; then
            read -r -p "Import this key? [y/N] " ans
            [[ "$ans" =~ ^[Yy]$ ]] || fail "aborted — import the key manually then re-run"
            gpg --import pubkey.asc
        else
            fail "no terminal to confirm the import on. Check the fingerprint above, then:
    gpg --import pubkey.asc && $0 ${*:-}
  or re-run with ASSUME_YES=1 if you have already verified it."
        fi
    fi
fi

# Now verify
output=$(gpg --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS 2>&1) || \
    fail "signature verification FAILED — release is tampered or signed by wrong key"

# Pull the actual signing key fingerprint out of gpg's output
signer=$(echo "$output" | grep -oE 'GOODSIG [A-F0-9]+' | head -1 | awk '{print $2}')
signer_full=$(echo "$output" | grep -oE 'VALIDSIG [A-F0-9]+' | head -1 | awk '{print $2}')

ok "PGP signature valid (key: $signer_full)"

# Check it's the EXPECTED key
if [[ "$EXPECTED_KEY" != "DEADBEEF"* ]]; then
    # Compare last 40 chars (full fingerprint) — accept partial matches if pinned shorter
    if [[ "${signer_full: -${#EXPECTED_KEY}}" != "$EXPECTED_KEY" ]]; then
        fail "signed by UNEXPECTED key

  Expected: $EXPECTED_KEY
  Got:      $signer_full

  Either the release was signed by the wrong key, or this verify script
  is pinning a stale fingerprint. Check https://0trustvpn.com/.well-known/security.txt."
    fi
    ok "key fingerprint matches expected: $EXPECTED_KEY"
else
    warn "EXPECTED_KEY placeholder still in this script — verify ${signer_full} out-of-band"
fi

# ----------------------------------------------------------------------------
# Verify SHA256 of the actual binary(ies)
# ----------------------------------------------------------------------------
if [[ -n "$TARGET" ]]; then
    # Just one binary
    [[ -f "$TARGET" ]] || fail "binary not found: $TARGET"
    expected=$(grep " $(basename "$TARGET")\$" SHA256SUMS | awk '{print $1}')
    [[ -n "$expected" ]] || fail "$(basename "$TARGET") not listed in SHA256SUMS"

    got=$(sha256sum "$TARGET" | awk '{print $1}')
    if [[ "$got" == "$expected" ]]; then
        ok "$(basename "$TARGET")  $expected"
    else
        fail "checksum MISMATCH:
  expected: $expected
  got:      $got
DO NOT RUN this binary — it differs from what the operator signed."
    fi
else
    # Whole release
    if ! sha256sum -c SHA256SUMS --strict --quiet 2>/dev/null; then
        # Fall through to verbose to show the failing file
        sha256sum -c SHA256SUMS
        fail "one or more files don't match SHA256SUMS"
    fi
    ok "all $(grep -c . SHA256SUMS) files match SHA256SUMS"
fi

echo ""
ok "VERIFIED.  Safe to run."
