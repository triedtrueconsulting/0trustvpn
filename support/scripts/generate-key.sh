#!/usr/bin/env bash
# ============================================================================
# Generate the 0trust support PGP key
# ============================================================================
# Creates an ed25519 keypair for the support address, exports the public key,
# and computes the Web Key Directory (WKD) hash so you know exactly where to
# publish the public key on your web server.
#
# Run on a hardened workstation, NOT the control plane host.
#
# Usage:
#   ./support/scripts/generate-key.sh
#
# Env:
#   SUPPORT_EMAIL    default: 0trustvpn@proton.me
#   KEY_NAME         default: "0trust support"
#   KEY_LIFETIME     default: 2y  (use --expert mode in gpg to override)
# ============================================================================
set -euo pipefail

log()  { printf '\033[1;33m[+] %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m[✓] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[!] %s\033[0m\n' "$*" >&2; exit 1; }

SUPPORT_EMAIL="${SUPPORT_EMAIL:-0trustvpn@proton.me}"
KEY_NAME="${KEY_NAME:-0trust support}"

command -v gpg >/dev/null || die "install gpg: apt-get install gnupg"
command -v zbase32 >/dev/null || \
    log "  (no zbase32 in PATH; we'll compute the WKD hash with Python)"

OUT_DIR="${OUT_DIR:-$(pwd)/support-key-output}"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# ----------------------------------------------------------------------------
log "Generating ed25519 keypair for $SUPPORT_EMAIL"
# ----------------------------------------------------------------------------
# Batch mode so it's non-interactive (we don't set a passphrase — the
# encrypted mail provider's storage encryption protects it. If you'd rather
# have a passphrase here, run interactively: `gpg --full-generate-key`)
cat > batch.txt <<EOF
%no-protection
Key-Type: EDDSA
Key-Curve: ed25519
Key-Usage: sign cert
Subkey-Type: ECDH
Subkey-Curve: cv25519
Subkey-Usage: encrypt
Name-Real: $KEY_NAME
Name-Email: $SUPPORT_EMAIL
Expire-Date: 2y
%commit
EOF

gpg --batch --gen-key batch.txt 2>&1 | tail -10
rm batch.txt

# Find the fingerprint of the freshly-created key
FINGERPRINT=$(gpg --list-keys --with-colons "$SUPPORT_EMAIL" \
              | awk -F: '/^fpr/{print $10; exit}')
[[ -n "$FINGERPRINT" ]] || die "could not find newly-created key"
ok "fingerprint: $FINGERPRINT"

# ----------------------------------------------------------------------------
log "Exporting public key"
# ----------------------------------------------------------------------------
gpg --armor --export "$FINGERPRINT" > pubkey.asc
ok "pubkey.asc written"

# Binary export for WKD
gpg --export "$FINGERPRINT" > pubkey.bin

# ----------------------------------------------------------------------------
log "Computing Web Key Directory (WKD) location"
# ----------------------------------------------------------------------------
# WKD uses zbase32(sha1(local-part-lowercase)) as the filename.
local_part="${SUPPORT_EMAIL%@*}"
domain="${SUPPORT_EMAIL##*@}"
local_part_lc=$(echo -n "$local_part" | tr '[:upper:]' '[:lower:]')

if command -v zbase32 >/dev/null; then
    wkd_hash=$(echo -n "$local_part_lc" | sha1sum | cut -d' ' -f1 \
                 | xxd -r -p | zbase32)
else
    # Pure-python fallback for zbase32
    wkd_hash=$(python3 -c "
import hashlib, sys
local = sys.argv[1]
sha = hashlib.sha1(local.encode()).digest()
alphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769'
# Pack into 5-bit groups
bits = ''.join(f'{b:08b}' for b in sha)
out = ''
for i in range(0, len(bits), 5):
    chunk = bits[i:i+5].ljust(5, '0')
    out += alphabet[int(chunk, 2)]
print(out)
" "$local_part_lc")
fi

ok "WKD hash: $wkd_hash"

# Stage the WKD layout for easy copy-to-web-root
mkdir -p "wkd/.well-known/openpgpkey/$domain/hu"
cp pubkey.bin "wkd/.well-known/openpgpkey/$domain/hu/$wkd_hash"
touch "wkd/.well-known/openpgpkey/$domain/policy"

# ----------------------------------------------------------------------------
log "Generating security.txt"
# ----------------------------------------------------------------------------
expiry=$(date -u -d '+1 year' +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null \
          || date -u -v+1y +"%Y-%m-%dT%H:%M:%SZ")
cat > security.txt <<EOF
# RFC 9116 security.txt for 0trust VPN
Contact: mailto:${CONTACT_EMAIL:-0trustvpn@proton.me}
Encryption: https://$domain/.well-known/openpgpkey/hu/$wkd_hash
Encryption: https://keys.openpgp.org/vks/v1/by-fingerprint/$FINGERPRINT
Preferred-Languages: en
Canonical: https://$domain/.well-known/security.txt
Policy: https://$domain/security-policy
Expires: $expiry
EOF
ok "security.txt drafted (review before publishing)"

# ----------------------------------------------------------------------------
cat <<EOF

================================================================
  Support key generated.

  Files in $OUT_DIR/:
    pubkey.asc          ASCII-armored public key (publish this)
    pubkey.bin          Binary public key (used for WKD)
    wkd/                Drop into your web root as-is
    security.txt        RFC 9116 metadata; serve at /.well-known/security.txt

  Fingerprint:
    $FINGERPRINT

  Next:
    1. Upload pubkey.asc to keys.openpgp.org:
         gpg --keyserver hkps://keys.openpgp.org --send-keys $FINGERPRINT
       Then verify the email link they send.

    2. Deploy WKD to your web root:
         rsync -a wkd/ root@your-web-host:/var/www/0trust/

    3. Install security.txt at:
         /var/www/0trust/.well-known/security.txt

    4. Configure your mail provider (ProtonMail/Tuta) to use this
       key for 0trustvpn@proton.me. Both providers support uploading
       a custom key under domain settings.

    5. UPDATE the EXPECTED_KEY constant in scripts/verify-release.sh
       if this is your release-signing key too (you may want a
       separate key for releases — common practice).

  KEEP THE PRIVATE KEY SAFE:
    Export it for backup with: gpg --export-secret-keys $FINGERPRINT > secret.asc
    Encrypt that file before storing anywhere off your air-gapped workstation.
================================================================
EOF
