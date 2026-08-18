#!/usr/bin/env bash
# ============================================================================
# 0trust BTCPay Server bootstrap — LITE variant
# ============================================================================
# Same control-plane integration as bootstrap.sh, but much smaller:
#
#   - Bitcoin: pruned to ~10GB via opt-save-storage-xs + bitcoin-fastsync.
#              Still runs locally because NBXplorer can't talk to a remote
#              node — but at $5/mo VPS scale rather than $40/mo dedicated.
#   - Monero:  NO local monerod. Only monero-wallet-rpc, pointed at a
#              public remote daemon. ~150GB → ~500MB.
#
# Tradeoffs vs the full bootstrap.sh:
#   ✓  ~15GB disk instead of 200GB
#   ✓  4GB RAM instead of 8GB
#   ✓  Ready in 2-3 hours instead of 1-3 days
#   ✓  Monthly cost ~$5-10 instead of $30-50
#   ✗  Monero remote-node operator sees that SOMEONE queries your subaddresses.
#      They can't see balances or link payments to customer identities
#      (Monero is private by design), but they see the timing of your polls.
#      Mitigate by configuring multiple remote nodes (env var supports a list)
#      and rotating between them.
#   ✗  If the remote Monero node goes down, XMR payments break until it's
#      back or you swap to another. The wallet is still safe — only checking
#      is impacted. Daemon failover is built into the override (see below).
#
# Run on a fresh Ubuntu 24.04 box with DNS pointing at it.
#
# Required env:
#   BTCPAY_HOST            FQDN, e.g. pay.0trustvpn.com
#   LETSENCRYPT_EMAIL      Bounce address for cert expiry notifications
#
# Optional env:
#   NBITCOIN_NETWORK       mainnet (default) | testnet | regtest
#   MONERO_REMOTE_DAEMON   Public daemon to use; default rotates trusted ones
#   BTCPAY_DOCKER_REF      Branch of btcpayserver-docker (default: master)
# ============================================================================
set -euo pipefail

log()  { printf '\033[1;33m[+] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;31m[!] %s\033[0m\n' "$*" >&2; }
die()  { warn "$*"; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"
[[ -n "${BTCPAY_HOST:-}" ]]       || die "set BTCPAY_HOST=pay.your-domain.tld"
[[ -n "${LETSENCRYPT_EMAIL:-}" ]] || die "set LETSENCRYPT_EMAIL=0trustvpn@proton.me"

NBITCOIN_NETWORK="${NBITCOIN_NETWORK:-mainnet}"
BTCPAY_DOCKER_REF="${BTCPAY_DOCKER_REF:-master}"

# Default Monero remote daemon — these are widely-trusted community nodes.
# Operator should pick one, verify it's reachable, and consider rotating.
# Format: host:port (no protocol).
MONERO_REMOTE_DAEMON="${MONERO_REMOTE_DAEMON:-node.monerodevs.org:18089}"

# DNS sanity check
log "Checking DNS for $BTCPAY_HOST"
public_ip=$(curl -fsS4 https://api.ipify.org)
resolved_ip=$(getent ahostsv4 "$BTCPAY_HOST" | awk 'NR==1{print $1}')
if [[ -z "$resolved_ip" ]]; then
    die "$BTCPAY_HOST has no A record — fix DNS first"
fi
if [[ "$resolved_ip" != "$public_ip" ]]; then
    warn "$BTCPAY_HOST resolves to $resolved_ip, this host is $public_ip"
    warn "Continuing in 10s — Ctrl-C to abort"
    sleep 10
fi

# Verify the chosen Monero daemon is actually responsive BEFORE we lock it in
log "Probing remote Monero daemon $MONERO_REMOTE_DAEMON"
mxhost=${MONERO_REMOTE_DAEMON%:*}
mxport=${MONERO_REMOTE_DAEMON##*:}
if ! curl -fsS -m 5 -X POST "http://$mxhost:$mxport/json_rpc" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' \
    | grep -q '"status":"OK"'; then
    warn "Remote Monero daemon at $MONERO_REMOTE_DAEMON didn't respond cleanly."
    warn "Continuing anyway — verify in BTCPay UI after install."
fi

# ----------------------------------------------------------------------------
log "Installing OS prerequisites"
# ----------------------------------------------------------------------------
apt-get update -qq
apt-get install -y -qq \
    git curl jq ca-certificates fail2ban ufw \
    apparmor-utils unattended-upgrades

# ----------------------------------------------------------------------------
log "Tightening the firewall"
# ----------------------------------------------------------------------------
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP (Lets Encrypt + redirect)'
ufw allow 443/tcp comment 'BTCPay HTTPS'
ufw --force enable

# ----------------------------------------------------------------------------
log "Cloning btcpayserver-docker"
# ----------------------------------------------------------------------------
BTCPAY_DIR="${BTCPAY_DIR:-/root/btcpayserver-docker}"
if [[ ! -d "$BTCPAY_DIR" ]]; then
    git clone https://github.com/btcpayserver/btcpayserver-docker "$BTCPAY_DIR"
fi
cd "$BTCPAY_DIR"
git fetch origin
git checkout "$BTCPAY_DOCKER_REF"
git pull --ff-only origin "$BTCPAY_DOCKER_REF" || true

# ----------------------------------------------------------------------------
log "Composing BTCPay fragments (LITE profile)"
# ----------------------------------------------------------------------------
# bitcoin-fastsync       : seed Bitcoin from snapshot (~2h sync vs days)
# opt-save-storage-xs    : aggressively prune Bitcoin to ~5-15GB
# NO opt-add-monero      : we'll add monero-wallet-rpc via our own override
fragments="bitcoin-fastsync;opt-save-storage-xs"

export BTCPAY_HOST
export LETSENCRYPT_EMAIL
export NBITCOIN_NETWORK
export BTCPAYGEN_CRYPTO1=btc
export BTCPAYGEN_ADDITIONAL_FRAGMENTS="$fragments"
export BTCPAYGEN_REVERSEPROXY=nginx
export BTCPAY_DISABLE_REGISTRATION=true

# ----------------------------------------------------------------------------
log "Running BTCPay installer"
# ----------------------------------------------------------------------------
./btcpay-setup.sh -i

# ----------------------------------------------------------------------------
log "Adding Monero remote-daemon override"
# ----------------------------------------------------------------------------
# BTCPay's setup writes its compose to Generated/. We drop a sidecar override
# that adds monero-wallet-rpc pointed at the remote daemon. The official
# BTCPay setup script honors docker-compose.override.yml files.

OVERRIDE_DIR="$BTCPAY_DIR/Generated"
OVERRIDE_FILE="$OVERRIDE_DIR/docker-compose.override.yml"

# Source the override template from this repo
TEMPLATE_FILE="${BASH_SOURCE%/*}/../docker/monero-remote.override.yml"
if [[ ! -f "$TEMPLATE_FILE" ]]; then
    # Fall back to /opt/0trust if running from a different cwd
    TEMPLATE_FILE="/opt/0trust/btcpay/docker/monero-remote.override.yml"
fi
[[ -f "$TEMPLATE_FILE" ]] || die "monero-remote.override.yml not found"

# Substitute the daemon address
sed "s|__MONERO_REMOTE_DAEMON__|$MONERO_REMOTE_DAEMON|g" "$TEMPLATE_FILE" \
    > "$OVERRIDE_FILE"
chmod 0644 "$OVERRIDE_FILE"

log "Restarting BTCPay to pick up Monero override"
cd "$BTCPAY_DIR"
docker compose -f Generated/docker-compose.generated.yml \
               -f "$OVERRIDE_FILE" up -d

# ----------------------------------------------------------------------------
log "System hardening"
# ----------------------------------------------------------------------------
cat > /etc/fail2ban/jail.d/sshd.local <<'F2B'
[sshd]
enabled = true
maxretry = 5
findtime = 600
bantime = 86400
F2B
systemctl restart fail2ban

dpkg-reconfigure -plow unattended-upgrades || true

mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/0trust-btcpay.conf <<'JOU'
[Journal]
SystemMaxUse=500M
SystemMaxFileSize=50M
MaxRetentionSec=14day
JOU
systemctl restart systemd-journald

# ----------------------------------------------------------------------------
log "Waiting for BTCPay to come up"
# ----------------------------------------------------------------------------
deadline=$(( $(date +%s) + 180 ))
while (( $(date +%s) < deadline )); do
    if curl -fsS -m 5 "https://$BTCPAY_HOST/api/v1/health" >/dev/null 2>&1; then
        log "BTCPay is up at https://$BTCPAY_HOST/"
        break
    fi
    sleep 5
done

cat <<EOF

================================================================
  BTCPay LITE deployed.

  Web UI:                 https://$BTCPAY_HOST/
  Bitcoin storage budget: ~10GB pruned
  Monero remote daemon:   $MONERO_REMOTE_DAEMON

  NEXT STEPS (manual, do these now):

  1. Browse to https://$BTCPAY_HOST/Account/Register — first
     account becomes admin. Use a strong password manager.

  2. Verify Bitcoin sync progress (should hit 100% in ~2 hours):
       sudo $BTCPAY_DIR/bitcoin-cli.sh getblockchaininfo \\
           | jq '{blocks, headers, verification_progress}'

  3. Verify the Monero wallet RPC can talk to the remote daemon:
       docker logs --tail 20 \$(docker ps -qf name=monero-wallet-rpc)
     Should show "Connected to <daemon>" lines. If you see
     "Unable to connect", swap to a different node:
       MONERO_REMOTE_DAEMON=xmr-node.cakewallet.com:18081 \\
           ./btcpay/scripts/bootstrap-lite.sh

  4. Configure the store, BTC xpub, and webhook:
       ./btcpay/scripts/configure.sh

  5. Run the smoke test:
       ./btcpay/scripts/test-integration.sh

  TRUSTED MONERO NODES (rotate between these):
    node.monerodevs.org:18089   (default, donation-supported)
    xmr-node.cakewallet.com:18081  (Cake Wallet team)
    nodex.monerujo.io:18081     (Monerujo team)
    node.community.rino.io:18081 (Rino wallet team)
================================================================
EOF
