#!/usr/bin/env bash
# ============================================================================
# 0trust BTCPay backup
# ============================================================================
# What this backs up:
#   - BTCPay's PostgreSQL DB    (store config, invoice history, webhook secrets)
#   - BTCPay's nginx + LE certs (so we can restore on a new box)
#   - Monero wallet file(s)     (THE CRITICAL ONE — contains spend key)
#   - The "0trust" specific env block we wrote out during configure
#
# What this does NOT back up:
#   - The Bitcoin node's blockchain data (it'll just re-sync; ~1 day with fastsync)
#   - The Monero node's blockchain data (~3 days re-sync, but no funds lost)
#   - The Bitcoin xpub (operator keeps this in cold storage themselves)
#
# Output: an age-encrypted .tar.gz dropped at $BACKUP_DIR/btcpay-YYYY-MM-DD.tar.gz.age
# The encryption key is the operator's age public key — pass via BACKUP_AGE_RECIPIENT.
#
# Required env:
#   BACKUP_AGE_RECIPIENT   age public key (age1...) — encrypt backups to this
#
# Optional:
#   BACKUP_DIR             default /var/backups/0trust
#   BTCPAY_DIR             default /root/btcpayserver-docker
#   RETAIN_DAYS            keep this many days of backups locally; default 30
#
# Recommended cadence: daily via systemd timer; ship encrypted tarballs to a
# separate host (Wasabi/Hetzner Storage Box) with rclone.
# ============================================================================
set -euo pipefail

log()  { printf '\033[1;33m[+] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[!] %s\033[0m\n' "$*" >&2; exit 1; }

[[ -n "${BACKUP_AGE_RECIPIENT:-}" ]] || die "set BACKUP_AGE_RECIPIENT=age1..."
command -v age >/dev/null  || die "install age:  apt-get install -y age"
command -v docker >/dev/null || die "docker not found"

BACKUP_DIR="${BACKUP_DIR:-/var/backups/0trust}"
BTCPAY_DIR="${BTCPAY_DIR:-/root/btcpayserver-docker}"
RETAIN_DAYS="${RETAIN_DAYS:-30}"

mkdir -p "$BACKUP_DIR"
ts=$(date +%Y-%m-%d-%H%M%S)
work=$(mktemp -d /tmp/btcpay-backup.XXXXXX)
trap 'rm -rf "$work"' EXIT

# ----------------------------------------------------------------------------
log "Dumping PostgreSQL"
# ----------------------------------------------------------------------------
# BTCPay's deployment names the postgres container `postgres_1` or similar.
# Find it by service label rather than hard-coding.
PG_CONTAINER=$(docker ps --format '{{.Names}}' | grep -E 'postgres' | head -1)
[[ -n "$PG_CONTAINER" ]] || die "could not find postgres container"

docker exec -t "$PG_CONTAINER" pg_dumpall -U postgres > "$work/postgres.sql"

# ----------------------------------------------------------------------------
log "Archiving BTCPay config + LE certs"
# ----------------------------------------------------------------------------
# BTCPay stores its config under /var/lib/docker/volumes/generated_*_datadir
# but the canonical source is the btcpay-docker tree's .env file + Generated/.
mkdir -p "$work/btcpay-config"
cp "$BTCPAY_DIR/.env"            "$work/btcpay-config/env" 2>/dev/null || true
cp -r "$BTCPAY_DIR/Generated"    "$work/btcpay-config/" 2>/dev/null || true

# Let's Encrypt — letsencrypt volume
LE_VOLUME=$(docker volume ls -q | grep -E 'letsencrypt' | head -1)
if [[ -n "$LE_VOLUME" ]]; then
    docker run --rm \
        -v "$LE_VOLUME:/data:ro" \
        -v "$work:/backup" \
        alpine \
        tar -czf /backup/letsencrypt.tar.gz -C /data . 2>/dev/null
fi

# ----------------------------------------------------------------------------
log "Backing up Monero wallet (THIS HAS SPEND KEYS)"
# ----------------------------------------------------------------------------
# The Monero plugin keeps wallet files under the monerod_data volume at
# /home/monero/wallets. Spend key + view key live there. Without this file,
# funds in the hot wallet are gone forever.
XMR_VOLUME=$(docker volume ls -q | grep -E '(monero|wallet)' | head -1)
if [[ -n "$XMR_VOLUME" ]]; then
    docker run --rm \
        -v "$XMR_VOLUME:/data:ro" \
        -v "$work:/backup" \
        alpine \
        tar -czf /backup/monero-wallet.tar.gz \
            -C /data \
            --exclude='lmdb' \
            --exclude='blockchain*' \
            . 2>/dev/null || log "  (no XMR wallet volume found)"
else
    log "  (no Monero wallet volume found — XMR not enabled?)"
fi

# ----------------------------------------------------------------------------
log "Bundling + encrypting"
# ----------------------------------------------------------------------------
out="$BACKUP_DIR/btcpay-$ts.tar.gz.age"

tar -C "$work" -czf - . \
    | age -r "$BACKUP_AGE_RECIPIENT" -o "$out"

chmod 600 "$out"
sz=$(du -h "$out" | awk '{print $1}')
log "Wrote $out  ($sz)"

# ----------------------------------------------------------------------------
log "Pruning backups older than $RETAIN_DAYS days"
# ----------------------------------------------------------------------------
find "$BACKUP_DIR" -name 'btcpay-*.tar.gz.age' -mtime "+$RETAIN_DAYS" -delete

cat <<EOF

  Backup complete: $out
  Decryption (on a host with the age secret key):
    age -d -i ~/.age/key.txt < $out | tar -xz

  IMPORTANT: ship this file off-host. A backup that lives only on the
  BTCPay box is no backup at all. Recommended:
    rclone copy "$out" remote:backups/btcpay/
EOF
