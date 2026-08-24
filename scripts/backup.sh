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

# ----- Promote to weekly / monthly -----
dow=$(date -u +%u)            # 1=Mon ... 7=Sun
dom=$(date -u +%d)
if [[ "$dow" == "7" ]]; then
    cp "$final" "$BACKUP_DIR/weekly/$(basename "$final")"
    log "Promoted to weekly"
fi
if [[ "$dom" == "01" ]]; then
    cp "$final" "$BACKUP_DIR/monthly/$(basename "$final")"
    log "Promoted to monthly"
fi

# ----- Rotation -----
keep_newest() {
    local dir="$1" count="$2"
    ls -1t "$dir" 2>/dev/null | tail -n +$((count + 1)) | while read -r old; do
        rm -f "$dir/$old"
        log "  pruned $dir/$old"
    done
}
keep_newest "$BACKUP_DIR/daily"   7
keep_newest "$BACKUP_DIR/weekly"  4
keep_newest "$BACKUP_DIR/monthly" 12

# ----- Off-host push -----
if [[ -n "$OFFSITE_RCLONE_REMOTE" ]]; then
    if command -v rclone >/dev/null; then
        log "Pushing to off-site: $OFFSITE_RCLONE_REMOTE"
        rclone copy "$final" "$OFFSITE_RCLONE_REMOTE/" --quiet
        ok "off-site push done"
    else
        log "  rclone not installed; install + configure for off-site push"
    fi
fi

ok "Backup complete at $ts"
