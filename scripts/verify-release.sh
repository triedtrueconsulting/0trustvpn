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
signer=$(echo "$output" | grep -om1 -E 'GOODSIG [A-F0-9]+' | awk '{print $2}')
signer_full=$(echo "$output" | grep -om1 -E 'VALIDSIG [A-F0-9]+' | awk '{print $2}')

ok "PGP signature valid (key: $signer_full)"

# Check it's the EXPECTED key
if [[ "$EXPECTED_KEY" != "DEADBEEF"* ]]; then
    # A full 40-character fingerprint, not a key id. Short ids are forgeable:
    # a matching 32-bit id takes seconds to grind and a 64-bit one is within
    # reach, so comparing a suffix of whatever length happens to be pinned
    # means the strength of this check is whatever the person editing this
    # line felt like typing. There is one right length.
    if [[ ! "$EXPECTED_KEY" =~ ^[A-Fa-f0-9]{40}$ ]]; then
        fail "EXPECTED_KEY in this script is not a 40-character fingerprint.
  A short key id can be forged; only the full fingerprint identifies a key.
  Get it from https://0trustvpn.com/.well-known/security.txt."
    fi
    if [[ "${signer_full^^}" != "${EXPECTED_KEY^^}" ]]; then
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
    # Whatever is actually here.
    #
    # This was `sha256sum -c SHA256SUMS`, which checks every file the list
    # names — and a customer downloads ONE binary, for their own platform.
    # So the documented default ("verify ./0trust-*") reported
    # "one or more files don't match SHA256SUMS" on an ordinary, untampered
    # download, five missing files being the only reason. That message reads
    # as tampering. A verifier that cries wolf on the normal case is a
    # verifier people stop running, which costs more than it ever protected.
    #
    # Absent and altered are different findings and are reported differently.
    checked=0; missing=0
    while read -r want name; do
        [[ -n "$want" && -n "$name" ]] || continue
        name=${name#\*}                      # sha256sum's binary-mode marker
        if [[ ! -f "$name" ]]; then
            missing=$((missing + 1)); continue
        fi
        got=$(sha256sum "$name" | awk '{print $1}')
        if [[ "$got" != "$want" ]]; then
            fail "checksum MISMATCH for $name
  expected: $want
  got:      $got
DO NOT RUN this file — it differs from what the operator signed."
        fi
        checked=$((checked + 1))
    done < SHA256SUMS

    if [[ $checked -eq 0 ]]; then
        fail "none of the $missing files in SHA256SUMS are in $(pwd).
  Download the binary you want into this directory and run this again."
    fi
    ok "$checked file(s) match SHA256SUMS"
    if [[ $missing -gt 0 ]]; then
        # Said plainly, and not as a warning: not downloading the other five
        # platforms is the normal thing to do.
        printf '    %s\n' "($missing other file(s) in SHA256SUMS are not in this directory — \
that is expected if you downloaded one platform's binary)"
    fi
fi

echo ""
# The identity check is check 3 of the three this script says it performs.
# When EXPECTED_KEY is still the placeholder it cannot run — and this script
# printed the same unconditional "VERIFIED. Safe to run." either way, which
# is a check that did not happen being reported as one that passed. The
# signature being valid says the file was not altered after signing; it says
# nothing about who signed it.
if [[ "$EXPECTED_KEY" == "DEADBEEF"* ]]; then
    warn "NOT FULLY VERIFIED."
    warn "The checksums match and the signature is valid, but this script has"
    warn "no fingerprint pinned, so it cannot tell you the signer is 0trust."
    warn "Compare ${signer_full} against:"
    warn "  https://0trustvpn.com/.well-known/security.txt"
    warn "  and one source that is not that website."
    exit 2
fi
ok "VERIFIED.  Safe to run."
