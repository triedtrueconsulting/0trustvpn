#!/usr/bin/env bash
# ============================================================================
# 0trust control plane backup
# ============================================================================
# Backs up the SQLite database that holds account hashes, devices, invoices,
# and mesh-node state. Without this, a host loss = loss of all customer
# accounts with no way to recover (tokens are hashed; we can't recover them).
#
# Strategy:
#   1. sqlite3 .backup → an online consistent snapshot (vs naive cp which
#      can copy a half-written WAL)
#   2. age-encrypt to the operator's backup recipient key
#   3. Push to an off-host destination
#   4. Local rotation: keep 7 daily + 4 weekly + 12 monthly
#
# Run from cron daily.  Tested with sqlite3 3.40+ and age 1.0+.
# ============================================================================
set -euo pipefail

log()  { printf '\033[1;33m[+] %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m[✓] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[!] %s\033[0m\n' "$*" >&2; exit 1; }

# ----- Config -----
DB_PATH="${ZTV_DB_PATH:-/var/lib/0trust/0trust.db}"
# The database is not enough to bring the service back. docs/DR.md step 6
# says "restore api.env" and told the operator to keep an encrypted copy
# off-host themselves — a manual step, forever, on the one path where manual
# steps fail. Nothing backed it up and nothing checked that anybody had.
#
# What is lost without it: NODE_API_PSK, so nodes cannot authenticate;
# BTCPAY_WEBHOOK_SECRET, so payment deliveries stop verifying and nothing is
# credited; ZTV_TRIAL_SECRET, so every outstanding trial challenge fails. A
# restore from backup came back as a control plane that could not take money
# or talk to its own mesh.
ENV_PATH="${ZTV_ENV_PATH:-/etc/0trust/api.env}"
BACKUP_DIR="${ZTV_BACKUP_DIR:-/var/lib/0trust/backups}"
AGE_RECIPIENT_FILE="${ZTV_AGE_RECIPIENTS:-/etc/0trust/backup-recipients.txt}"
OFFSITE_RCLONE_REMOTE="${ZTV_OFFSITE:-}"   # e.g. "b2:0trust-backups"

command -v sqlite3 >/dev/null || die "sqlite3 not installed"
command -v age >/dev/null     || die "age not installed (apt-get install age)"
[[ -f "$DB_PATH" ]]           || die "db missing: $DB_PATH"
[[ -f "$AGE_RECIPIENT_FILE" ]] || die "age recipients file missing: $AGE_RECIPIENT_FILE"

mkdir -p "$BACKUP_DIR"/{daily,weekly,monthly}

# ----- Snapshot + encrypt -----
ts=$(date -u +%Y%m%dT%H%M%SZ)
snapshot="$BACKUP_DIR/.snap-$ts.db"
final="$BACKUP_DIR/daily/0trust-${ts}.db.age"

# The snapshot is a full, unencrypted copy of every account, device and
# invoice. If anything below fails — a bad recipients file, a full disk, age
# missing — `set -e` walks out of the script and the plain copy stays on disk
# until somebody notices. It is the exact finding scripts/audit-verify.sh looks
# for, produced by the backup job itself. Shred it on the way out, always.
cleanup_snapshot() {
    [[ -e "$snapshot" ]] && shred -u "$snapshot" 2>/dev/null
    return 0
}
trap cleanup_snapshot EXIT

log "Snapshotting db (online)"
sqlite3 "$DB_PATH" ".backup '$snapshot'"

log "Encrypting to recipients in $AGE_RECIPIENT_FILE"
age -R "$AGE_RECIPIENT_FILE" -o "$final" "$snapshot"
cleanup_snapshot              # the cleartext snapshot dies right here
ok "$final ($(du -h "$final" | cut -f1))"

# The environment file, alongside it and encrypted to the same recipients.
# Never copied in the clear: age reads it and writes only the ciphertext, so
# the secrets exist unencrypted only where they already did.
if [[ -f "$ENV_PATH" ]]; then
    env_final="$BACKUP_DIR/daily/0trust-env-${ts}.env.age"
    age -R "$AGE_RECIPIENT_FILE" -o "$env_final" "$ENV_PATH"
    chmod 600 "$env_final"
    ok "$env_final"
else
    # Loud, not silent. A backup set that restores a database into a control
    # plane with no credentials is a restore that does not work, and finding
    # that out during the outage is the whole failure this guards against.
    log "  WARNING: $ENV_PATH not found — the backup has the database and"
    log "  NOT the node PSK, the webhook secret or the trial secret. A"
    log "  restore from it will not take payments. Set ZTV_ENV_PATH if the"
    log "  file lives elsewhere."
fi

# ----- Promote to weekly / monthly -----
dow=$(date -u +%u)            # 1=Mon ... 7=Sun
dom=$(date -u +%d)
# Both artifacts move together. A weekly database without the weekly
# environment beside it restores into the same broken state.
promote() {   # promote <dir>
    cp "$final" "$BACKUP_DIR/$1/$(basename "$final")"
    [[ -n "${env_final:-}" && -f "$env_final" ]] \
        && cp "$env_final" "$BACKUP_DIR/$1/$(basename "$env_final")"
    log "Promoted to $1"
}
if [[ "$dow" == "7" ]]; then promote weekly; fi
if [[ "$dom" == "01" ]]; then promote monthly; fi

# ----- Rotation -----
# Rotate each ARTIFACT TYPE separately, not the directory as a whole.
#
# This counted files, and each run now writes two of them — the database and
# the environment file. Counting files would have quietly halved every
# retention window the moment the second artifact appeared: seven daily files
# is three and a half days, not seven. The kind of regression that shows up
# as "the backup I wanted is gone" and never as an error.
keep_newest() {
    local dir="$1" pattern="$2" count="$3"
    # `|| true` is load-bearing under this file's `set -euo pipefail`: a
    # glob that matches nothing makes ls exit 2, pipefail propagates that
    # through the pipeline, and set -e ends the script — so the very first
    # run, with an empty weekly directory, aborted after writing the backup
    # and before the off-site push. The old version listed the directory
    # rather than a pattern, which always matched. Same shape as the
    # `find | head` SIGPIPE in mobile/ios/build.sh: a pipeline that fails on
    # the ordinary case rather than an exceptional one.
    # shellcheck disable=SC2012  # names are ours, not user input
    { ls -1t "$dir"/$pattern 2>/dev/null || true; } | tail -n +$((count + 1)) \
    | while read -r old; do
        rm -f "$old"
        log "  pruned $old"
    done
}
for spec in "daily 7" "weekly 4" "monthly 12"; do
    set -- $spec
    keep_newest "$BACKUP_DIR/$1" "0trust-2*.db.age"    "$2"
    keep_newest "$BACKUP_DIR/$1" "0trust-env-*.env.age" "$2"
done

# ----- Off-host push -----
if [[ -n "$OFFSITE_RCLONE_REMOTE" ]]; then
    if command -v rclone >/dev/null; then
        log "Pushing to off-site: $OFFSITE_RCLONE_REMOTE"
        rclone copy "$final" "$OFFSITE_RCLONE_REMOTE/" --quiet
        [[ -n "${env_final:-}" && -f "$env_final" ]] \
            && rclone copy "$env_final" "$OFFSITE_RCLONE_REMOTE/" --quiet
        ok "off-site push done"
    else
        log "  rclone not installed; install + configure for off-site push"
    fi
fi

ok "Backup complete at $ts"
