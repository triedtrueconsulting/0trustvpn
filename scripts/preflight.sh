#!/usr/bin/env bash
# ============================================================================
# 0trust launch preflight
# ============================================================================
# Answers one question: is this deployment ready to take a paying customer?
#
# Everything the code can do to itself is checked by ./scripts/validate.sh and
# tests/emulation. This checks the things a green build cannot: whether the
# operator has actually replaced the placeholders, generated the keys, pointed
# the wallet somewhere they control, and stood the services up. A repository
# that builds is not a business that can take money.
#
#   ./scripts/preflight.sh            # check this checkout + this host
#   ./scripts/preflight.sh --repo     # only the checks that need no host
#
# Exit code is the number of blockers. WARN items do not block launch but are
# worth a decision.
#
# Every FAIL below is an operator action. None of them can be done for you:
# they need private keys, a card, a legal review, or a machine.
# ============================================================================
set -uo pipefail

REPO_ONLY=0
[[ "${1:-}" == "--repo" ]] && REPO_ONLY=1

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[1;33m'
DIM=$'\033[2m'; BLD=$'\033[1m'; NC=$'\033[0m'
BLOCK=0; WARNED=0; OK=0

section() { printf '\n%s━━━ %s ━━━%s\n' "$YLW" "$*" "$NC"; }

# gate <id> <what it means> <fix>  — reads the verdict from stdin: "ok", "warn"
# or a failure message.
gate() {
    local id="$1" desc="$2" fix="$3" verdict
    verdict="$(cat)"
    printf '  %-26s %-44s ' "$id" "$desc"
    case "$verdict" in
        ok)   printf '%sREADY%s\n' "$GRN" "$NC"; ((OK++)) ;;
        warn) printf '%sWARN%s\n'  "$YLW" "$NC"; ((WARNED++)) ;;
        *)    printf '%sBLOCKED%s\n' "$RED" "$NC"
              printf '      %s%s%s\n' "$DIM" "$verdict" "$NC"
              printf '      %sfix:%s %s\n' "$BLD" "$NC" "$fix"
              ((BLOCK++)) ;;
    esac
}

cat <<HDR
================================================================
  0trust launch preflight
  Repo:    $REPO_DIR
  Host:    $(hostname)
  Time:    $(date -u +%FT%TZ)
================================================================
HDR

# ---------------------------------------------------------------------------
section "SIGNING KEYS AND FINGERPRINTS"
# ---------------------------------------------------------------------------
# A download page that tells people to verify against a fingerprint nobody
# owns is worse than one that says nothing: it teaches the habit and then
# breaks it.

gate release-key-pinned "verify-release.sh pins a real fingerprint" \
     "generate the release key, then replace EXPECTED_KEY in scripts/verify-release.sh" <<EOF
$(grep -q '^EXPECTED_KEY="DEADBEEF' scripts/verify-release.sh \
  && echo "EXPECTED_KEY is still the DEADBEEF placeholder" || echo ok)
EOF

gate web-no-placeholder-fpr "no DEADBEEF fingerprint on the site" \
     "replace the fingerprints in web/download.html and web/security-policy.html" <<EOF
$(files=$(grep -rl 'DEADBEEF' web/*.html web/.well-known/security.txt 2>/dev/null | tr '\n' ' ')
  [[ -n "$files" ]] && echo "placeholder fingerprint in: $files" || echo ok)
EOF

gate support-key-published "a support PGP key is published for WKD" \
     "support/scripts/generate-key.sh, then publish under /.well-known/openpgpkey/" <<EOF
$([[ -s web/.well-known/openpgpkey/hu/* ]] 2>/dev/null && echo ok || echo warn)
EOF

# ---------------------------------------------------------------------------
section "MONEY"
# ---------------------------------------------------------------------------

ENVFILE="${ZTV_ENV_FILE:-/etc/0trust/api.env}"
provider="$(grep -hoP '^ZTV_PAYMENT_PROVIDER=\K.*' "$ENVFILE" 2>/dev/null | tail -1)"
provider="${provider:-watch}"
printf '  %sprovider: %s%s\n' "$DIM" "$provider" "$NC"

case "$provider" in
  watch)
    gate wallet-xpub "WALLET_BTC derives real receive addresses" \
         "put your own account xpub/zpub in $ENVFILE — never a private key — then confirm the first address with scripts/check-wallet.sh" <<EOF
$(w="$(grep -hoP '^WALLET_BTC=\K.*' "$ENVFILE" 2>/dev/null | tail -1)"
  if [[ -z "$w" ]]; then echo "WALLET_BTC is empty — paid signup cannot issue an address"
  elif [[ "$w" == *prv* ]]; then echo "that looks like a PRIVATE key. Use the extended PUBLIC key."
  # Derive from it rather than checking the prefix: a typo'"'"'d key still starts
  # with zpub, and the failure it causes has no symptom — invoices simply
  # never settle while every health check stays green.
  elif ./scripts/check-wallet.sh --count 1 "$w" >/dev/null 2>&1; then echo ok
  else echo "WALLET_BTC does not derive — run scripts/check-wallet.sh to see why"; fi)
EOF
    ;;
  btcpay)
    gate btcpay-configured "BTCPay URL, store and key are set" \
         "run btcpay/scripts/configure.sh and copy the values into $ENVFILE" <<EOF
$(u="$(grep -hoP '^BTCPAY_URL=\K.*' "$ENVFILE" 2>/dev/null | tail -1)"
  k="$(grep -hoP '^BTCPAY_API_KEY=\K.*' "$ENVFILE" 2>/dev/null | tail -1)"
  if [[ -z "$k" ]]; then echo "BTCPAY_API_KEY is empty"
  elif [[ "$u" == *example.com* ]]; then echo "BTCPAY_URL still points at example.com"
  else echo ok; fi)
EOF
    ;;
  stripe|square)
    gate card-provider-disclosed "the site says cards mean an identity" \
         "cards put a real name behind every payment; privacy.html must say so" <<EOF
$(grep -qi 'card' web/privacy.html && echo ok \
  || echo "privacy.html does not mention card payments at all")
EOF
    ;;
esac

# ---------------------------------------------------------------------------
section "BACKUPS AND RECOVERY"
# ---------------------------------------------------------------------------
# Tokens are stored hashed. Without a restorable backup, losing the host loses
# every account permanently, with no way to reissue.

gate backup-recipients "an age recipient is configured" \
     "age-keygen, then put the PUBLIC key in /etc/0trust/backup-recipients.txt" <<EOF
$(f="${ZTV_AGE_RECIPIENTS:-/etc/0trust/backup-recipients.txt}"
  if [[ $REPO_ONLY -eq 1 ]]; then echo ok
  elif [[ ! -s "$f" ]]; then echo "no recipients at $f — scripts/backup.sh will refuse to run"
  elif grep -q 'AGE-SECRET-KEY' "$f"; then echo "that is a SECRET key. Recipients take the public one."
  else echo ok; fi)
EOF

gate backup-taken "at least one encrypted backup exists" \
     "run scripts/backup.sh once by hand, then enable 0trust-backup.timer" <<EOF
$(d="${ZTV_BACKUP_DIR:-/var/lib/0trust/backups}"
  if [[ $REPO_ONLY -eq 1 ]]; then echo ok
  elif compgen -G "$d/daily/*.age" >/dev/null; then echo ok
  else echo "nothing in $d/daily — an unrestorable service is one host failure from over"; fi)
EOF

gate backup-offsite "backups leave the machine" \
     "set ZTV_OFFSITE to an rclone remote; a backup on the same disk is not one" <<EOF
$(grep -q '^ZTV_OFFSITE=.\+' "${ZTV_BACKUP_ENV:-/etc/0trust/backup.env}" 2>/dev/null \
  && echo ok || echo warn)
EOF

# ---------------------------------------------------------------------------
section "THE PROMISE"
# ---------------------------------------------------------------------------

gate canary-signed "a warrant canary has been published" \
     "canary/scripts/generate.sh — the site links it; an absent one is a bad signal" <<EOF
$(c="${CANARY_PATH:-/var/www/0trust/canary.txt}"
  if [[ $REPO_ONLY -eq 1 ]]; then echo warn
  elif [[ -f "$c" ]]; then bash canary/scripts/check.sh >/dev/null 2>&1 \
       && echo ok || echo "the canary at $c is stale — re-sign it"
  else echo "no canary at $c, and privacy.html points customers at one"; fi)
EOF

# terms.html §9 does not name the entity itself: it says the governing law is
# that of wherever the entity is established and points at security.txt for
# the name. So that is where to look — matching "operating entity" in the
# terms just matches the sentence doing the deferring.
gate legal-entity-named "the operating entity is named" \
     "name the entity in web/.well-known/security.txt" <<EOF
$(f=web/.well-known/security.txt
  if [[ ! -f "$f" ]]; then echo "no security.txt, and terms.html §9 points at it for the entity"
  elif ! grep -qE '^#?\s*Entity:\s*\S' "$f"; then echo "no Entity: line"
  elif grep -qE '^#?\s*Entity:.*(NOT YET|TBD|TO BE)' "$f"; then echo "the Entity line is still a placeholder"
  else echo ok; fi)
EOF

# Separate from the name on purpose: terms.html §9 makes the entity's
# jurisdiction the governing law of the contract, so a named company with no
# stated jurisdiction leaves the terms pointing at nothing.
gate legal-jurisdiction "and its jurisdiction is stated" \
     "add the country (and US state, if applicable) to the Jurisdiction line in security.txt; see docs/AUDIT.md §2.6" <<EOF
$(f=web/.well-known/security.txt
  if [[ ! -f "$f" ]]; then echo "no security.txt"
  elif grep -qE '^#?\s*Jurisdiction:.*(NOT YET|TBD|TO BE CONFIRMED)' "$f"; then
       echo "Jurisdiction is still TO BE CONFIRMED — terms.html §9 defers the governing law to it"
  elif grep -qE '^#?\s*Jurisdiction:\s*\S' "$f"; then echo ok
  else echo "no Jurisdiction: line"; fi)
EOF

gate security-txt-valid "security.txt exists and has not expired" \
     "web/.well-known/security.txt — RFC 9116 requires a future Expires; re-issue annually" <<EOF
$(f=web/.well-known/security.txt
  if [[ ! -f "$f" ]]; then echo "seven pages and verify-release.sh link this file"
  else exp=$(grep -m1 '^Expires:' "$f" | sed 's/^Expires:[[:space:]]*//')
       if [[ -z "$exp" ]]; then echo "no Expires field — the file is invalid per RFC 9116"
       elif [[ $(date -u -d "$exp" +%s 2>/dev/null || echo 0) -le $(date -u +%s) ]]; then
            echo "Expires $exp has passed — researchers' tooling treats it as invalid"
       else echo ok; fi
  fi)
EOF

gate security-txt-signed "security.txt is PGP-signed" \
     "gpg --clearsign it once the keys exist; it is what pins the release fingerprint" <<EOF
$(grep -q 'BEGIN PGP SIGNED MESSAGE' web/.well-known/security.txt 2>/dev/null \
  && echo ok || echo warn)
EOF

gate audit-clean "scripts/audit-verify.sh reports no failures" \
     "run it and resolve each FAIL; it is what a third-party auditor will run" <<EOF
$(if [[ $REPO_ONLY -eq 1 ]]; then echo ok
  else out="$(bash scripts/audit-verify.sh 2>/dev/null)"
       n="$(sed -n 's/.*FAIL:[^0-9]*\([0-9]\+\).*/\1/p' <<<"$out" | tail -1)"
       [[ "${n:-1}" == "0" ]] && echo ok || echo "${n:-?} check(s) failing"; fi)
EOF

# ---------------------------------------------------------------------------
section "BUILD AND RELEASE"
# ---------------------------------------------------------------------------

gate validate-green "./scripts/validate.sh passes" \
     "run it; every check is a thing the product claims about itself" <<EOF
$(if [[ -n "${ZTV_SKIP_VALIDATE:-}" ]]; then echo warn
  else bash scripts/validate.sh >/dev/null 2>&1 && echo ok \
       || echo "validate.sh is failing — fix that before anything here"; fi)
EOF

gate installers-signed "the release carries signed installers" \
     "build the MSI on Windows and the APK in Android Studio, then scripts/release.sh" <<EOF
$(v="$(grep -oE '/releases/([0-9.]+)/' web/download.html | head -1 | tr -d '/' | sed 's/releases//')"
  d="releases/$v"
  if [[ ! -d "$d" ]]; then echo "no $d/ yet — nothing has been released"
  elif [[ ! -f "$d/SHA256SUMS.asc" ]]; then echo "$d is unsigned"
  else echo ok; fi)
EOF

# ---------------------------------------------------------------------------
section "SERVICES"
# ---------------------------------------------------------------------------

if [[ $REPO_ONLY -eq 1 ]]; then
    printf '  %s(skipped: --repo)%s\n' "$DIM" "$NC"
else
    for unit in 0trust-api 0trust-sweep.timer 0trust-backup.timer; do
        gate "${unit%%.*}-running" "$unit is enabled" \
             "systemctl enable --now $unit" <<EOF
$(systemctl is-enabled "$unit" >/dev/null 2>&1 && echo ok \
  || echo "$unit is not enabled")
EOF
    done
fi

# ---------------------------------------------------------------------------
printf '\n================================================================\n'
if (( BLOCK == 0 )); then
    printf '  %sREADY TO LAUNCH%s — %d checks passed, %d warning(s)\n' \
           "$GRN" "$NC" "$OK" "$WARNED"
else
    printf '  %sNOT READY%s — %d blocker(s), %d passed, %d warning(s)\n' \
           "$RED" "$NC" "$BLOCK" "$OK" "$WARNED"
    printf '\n  Every blocker above needs a person: a key, a card, a lawyer or a\n'
    printf '  machine. None of them are code, and none of them can be skipped by\n'
    printf '  a green test run.\n'
fi
printf '================================================================\n'
exit "$BLOCK"
