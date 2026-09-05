#!/usr/bin/env bash
# ============================================================================
# 0trust key generation
# ============================================================================
# Creates the four keys the product needs, prints the exact edits to make, and
# refuses to do any of it somewhere it should not be done.
#
#   release   PGP  signs SHA256SUMS on every download
#   canary    PGP  signs the weekly warrant canary
#   support   PGP  published via WKD so people can report things encrypted
#   backup    age  encrypts the database backups
#
#   ./scripts/generate-keys.sh              # all four
#   ./scripts/generate-keys.sh release      # just one
#
# ---------------------------------------------------------------------------
# RUN THIS ON YOUR OWN MACHINE. NOT ON THE SERVER, AND NOT IN CI.
#
# Three of these keys are the product's root of trust and the fourth can
# decrypt every customer record you hold. A signing key on an internet-facing
# box is a signing key an intruder can use to sign a malicious release that
# every customer's verify-release.sh will happily accept. The server never
# needs any private key here: it needs the age PUBLIC key for backups, and
# nothing else.
#
# The script checks for the obvious wrong places and stops. It cannot check
# for all of them — that part is on you.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME="${KEY_OWNER_NAME:-0trust INC.}"
EMAIL="${KEY_OWNER_EMAIL:-0trustvpn@proton.me}"
OUT="${KEY_OUT_DIR:-$HOME/.0trust-keys}"

GRN=$'\033[0;32m'; RED=$'\033[0;31m'; YLW=$'\033[1;33m'
DIM=$'\033[2m'; BLD=$'\033[1m'; NC=$'\033[0m'
log()  { printf '%s[+] %s%s\n' "$YLW" "$*" "$NC"; }
ok()   { printf '%s[✓] %s%s\n' "$GRN" "$*" "$NC"; }
die()  { printf '%s[!] %s%s\n' "$RED" "$*" "$NC" >&2; exit 1; }

WANT=("$@")
(( ${#WANT[@]} )) || WANT=(release canary support backup)

# --- Refuse the obviously wrong machine -------------------------------------
[[ -z "${CI:-}${GITHUB_ACTIONS:-}" ]] \
    || die "this is CI. Generate these on a machine you control."
[[ ! -d /etc/0trust ]] \
    || die "/etc/0trust exists, so this looks like the server. Generate these
    on your own machine and copy ONLY the public halves here."
[[ ! -f /.dockerenv ]] \
    || printf '%s[!] running in a container — make sure %s survives it%s\n' \
              "$YLW" "$OUT" "$NC" >&2

command -v gpg >/dev/null || die "gpg not installed"
mkdir -p "$OUT"; chmod 700 "$OUT"

printf '\n%sKeys go in %s%s — back that directory up before you do anything\n' \
       "$BLD" "$OUT" "$NC"
printf '%selse. Losing the release key means every future release is signed by\n' "$DIM"
printf 'a key your customers have never seen, and they are told to reject those.%s\n\n' "$NC"

# gpg wants an interactive agent for the passphrase. That is deliberate: an
# unprotected release key is a file anyone who reaches your disk can sign with.
gen_pgp() {   # gen_pgp <slot> <comment>
    local slot="$1" comment="$2" uid="$NAME ($comment) <$EMAIL>"
    if gpg --list-secret-keys "$uid" >/dev/null 2>&1; then
        ok "$slot key already exists — leaving it alone"
    else
        log "generating the $slot key ($comment)"
        printf '%s    you will be asked for a passphrase. Use one.%s\n' "$DIM" "$NC"
        gpg --quick-generate-key "$uid" ed25519 sign 3y
    fi
    local fpr
    fpr="$(gpg --list-keys --with-colons "$uid" | awk -F: '/^fpr/{print $10; exit}')"
    printf '%s' "$fpr" > "$OUT/$slot.fpr"
    gpg --armor --export "$fpr" > "$OUT/$slot.pub.asc"
    ok "$slot  $fpr"
}

for slot in "${WANT[@]}"; do
    case "$slot" in
        release) gen_pgp release "release signing" ;;
        canary)  gen_pgp canary  "warrant canary"  ;;
        support) gen_pgp support "support"         ;;
        backup)
            command -v age-keygen >/dev/null || die "age not installed (apt install age)"
            if [[ -s "$OUT/backup-age.key" ]]; then
                ok "age backup key already exists — leaving it alone"
            else
                log "generating the age backup key"
                age-keygen -o "$OUT/backup-age.key" 2>/dev/null
                chmod 600 "$OUT/backup-age.key"
            fi
            grep -m1 -o 'age1[0-9a-z]*' "$OUT/backup-age.key" > "$OUT/backup-age.pub"
            ok "backup  $(cat "$OUT/backup-age.pub")"
            ;;
        *) die "unknown key: $slot (release|canary|support|backup)" ;;
    esac
done

# --- What to do with them ---------------------------------------------------
rel="$(cat "$OUT/release.fpr" 2>/dev/null || echo '<release-fpr>')"
can="$(cat "$OUT/canary.fpr"  2>/dev/null || echo '<canary-fpr>')"
sup="$(cat "$OUT/support.fpr" 2>/dev/null || echo '<support-fpr>')"
agp="$(cat "$OUT/backup-age.pub" 2>/dev/null || echo '<age1...>')"

cat <<EOF

$BLD────────────────────────────────────────────────────────────────$NC
$BLD  Now make these edits. scripts/preflight.sh checks every one.$NC
$BLD────────────────────────────────────────────────────────────────$NC

${BLD}1. Pin the release key in the verifier${NC}
   scripts/verify-release.sh
     EXPECTED_KEY="$rel"

${BLD}2. Publish the fingerprints — one command, each key in its own place${NC}
   ./scripts/set-fingerprints.sh \\
       --release $rel \\
       --canary  $can \\
       --support $sup

   ${DIM}Do not hand-edit these. The three keys are NOT interchangeable:${NC}
   ${DIM}  release  → verify-release.sh, download.html, security.txt${NC}
   ${DIM}  canary   → security.txt${NC}
   ${DIM}  support  → security-policy.html, which is the key people ENCRYPT${NC}
   ${DIM}             vulnerability reports to. Publishing the release key${NC}
   ${DIM}             there tells reporters to encrypt to a signing key that${NC}
   ${DIM}             has no encryption subkey, and they simply cannot.${NC}
   ${DIM}The script refuses a malformed fingerprint, refuses the DEADBEEF${NC}
   ${DIM}placeholder, and refuses any key this machine does not actually hold.${NC}

${BLD}3. Give the server the age PUBLIC key — never the private one${NC}
   on the server:
     echo '$agp' | sudo tee /etc/0trust/backup-recipients.txt
   keep $OUT/backup-age.key OFF the server; it is what restores backups.

${BLD}4. Sign security.txt once the fingerprints are in${NC}
   gpg --clearsign --local-user $rel web/.well-known/security.txt
   mv web/.well-known/security.txt.asc web/.well-known/security.txt

${BLD}5. Publish the support key for WKD${NC}
   support/scripts/generate-key.sh, or place $OUT/support.pub.asc
   under web/.well-known/openpgpkey/hu/ using the WKD hash of the localpart.

${BLD}6. Then cut a release${NC}
   RELEASE_SIGNER_KEY=$rel ./scripts/release.sh 0.1.0

$RED  Back up $OUT now, offline, before you touch anything else.$NC
$DIM  Three of those keys cannot be re-issued without telling every customer
  the old ones are dead, and the fourth is the only thing that can read your
  backups.$NC

EOF
