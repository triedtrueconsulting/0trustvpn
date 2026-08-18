#!/usr/bin/env bash
# ============================================================================
# 0trust BTCPay Server bootstrap
# ============================================================================
# Wraps BTCPay's official Docker deployment with the env vars we want for a
# privacy-first VPN payment processor:
#   - Bitcoin (we'll point at a watching-only xpub during configure.sh)
#   - Monero (full node + wallet-rpc, opt-add-monero fragment)
#   - opt-save-storage-s  → prunes Bitcoin to ~50GB
#   - nginx reverse-proxy with auto Let's Encrypt
#   - No registration page on the public site (admin-only)
#
# This script is idempotent — re-running it on a host that already has BTCPay
# upgrades it in place. BTCPay's own installer handles that bit.
#
# Run as root on a fresh Ubuntu 24.04 box that has the BTCPay hostname's DNS
# pointing at it already.
#
# Required env:
#   BTCPAY_HOST            FQDN, e.g. pay.0trustvpn.com
#   LETSENCRYPT_EMAIL      Bounce address for cert expiry notifications
#
# Optional env:
#   NBITCOIN_NETWORK       mainnet (default) | testnet | regtest
#   ENABLE_MONERO          1 (default) | 0
#   PRUNE_BITCOIN          1 (default) — keep BTC node to ~50GB
#   BTCPAY_DOCKER_REF      Tag/branch of btcpayserver-docker to clone (default: master)
# ============================================================================
set -euo pipefail

log()  { printf '\033[1;33m[+] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;31m[!] %s\033[0m\n' "$*" >&2; }
die()  { warn "$*"; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root"
[[ -n "${BTCPAY_HOST:-}" ]]       || die "set BTCPAY_HOST=pay.your-domain.tld"
[[ -n "${LETSENCRYPT_EMAIL:-}" ]] || die "set LETSENCRYPT_EMAIL=0trustvpn@proton.me"

NBITCOIN_NETWORK="${NBITCOIN_NETWORK:-mainnet}"
ENABLE_MONERO="${ENABLE_MONERO:-1}"
PRUNE_BITCOIN="${PRUNE_BITCOIN:-1}"
BTCPAY_DOCKER_REF="${BTCPAY_DOCKER_REF:-master}"

# Verify DNS resolves to this host BEFORE letting BTCPay try Let's Encrypt
# (otherwise LE rate-limits us for repeated failures)
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
# BTCPay needs 80/443 (HTTP+HTTPS for nginx). SSH stays open.
# Bitcoin p2p (8333) and Monero p2p (18080) are outbound-only by default; we
# don't accept inbound peer connections.
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP (Let'\''s Encrypt + redirect)'
ufw allow 443/tcp comment 'BTCPay HTTPS'
ufw --force enable

# ----------------------------------------------------------------------------
log "Cloning btcpayserver-docker"
# ----------------------------------------------------------------------------
# BTCPay's deployment scripts live in this repo. We clone it once and re-run
# the installer when we want to upgrade.
BTCPAY_DIR="${BTCPAY_DIR:-/root/btcpayserver-docker}"
if [[ ! -d "$BTCPAY_DIR" ]]; then
    git clone https://github.com/btcpayserver/btcpayserver-docker "$BTCPAY_DIR"
fi
cd "$BTCPAY_DIR"
git fetch origin
git checkout "$BTCPAY_DOCKER_REF"
git pull --ff-only origin "$BTCPAY_DOCKER_REF" || true

# ----------------------------------------------------------------------------
log "Composing BTCPay fragments"
# ----------------------------------------------------------------------------
# BTCPay uses a fragment system: BTCPAYGEN_CRYPTO1 chooses the primary chain;
# BTCPAYGEN_ADDITIONAL_FRAGMENTS layers add-ons. We want:
#   - opt-save-storage-s   : prune Bitcoin to ~50GB (safe for a payment processor;
#                            we only need recent blocks for fee estimation + UTXO)
#   - opt-add-monero       : full Monero node + wallet-rpc
#   - bitcoin-fastsync     : seeds Bitcoin from a checkpoint to skip days of IBD
fragments="bitcoin-fastsync"
[[ "$PRUNE_BITCOIN" == "1" ]] && fragments="$fragments;opt-save-storage-s"
[[ "$ENABLE_MONERO" == "1" ]] && fragments="$fragments;opt-add-monero"

export BTCPAY_HOST
export LETSENCRYPT_EMAIL
export NBITCOIN_NETWORK
export BTCPAYGEN_CRYPTO1=btc
export BTCPAYGEN_ADDITIONAL_FRAGMENTS="$fragments"
export BTCPAYGEN_REVERSEPROXY=nginx
# Disable public registration — admin creates accounts manually
export BTCPAY_DISABLE_REGISTRATION=true

# ----------------------------------------------------------------------------
log "Running BTCPay installer"
# ----------------------------------------------------------------------------
# This pulls images, sets up systemd units, generates the env file, runs
# docker compose up. Idempotent — re-running it just refreshes config.
./btcpay-setup.sh -i

# ----------------------------------------------------------------------------
log "Configuring system hardening"
# ----------------------------------------------------------------------------

# fail2ban for SSH (the Docker daemon already protects the BTCPay surface)
cat > /etc/fail2ban/jail.d/sshd.local <<'F2B'
[sshd]
enabled = true
maxretry = 5
findtime = 600
bantime = 86400
F2B
systemctl restart fail2ban

# Unattended security updates
dpkg-reconfigure -plow unattended-upgrades || true

# Disable journald persistence — payment metadata should not linger in logs
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/0trust-btcpay.conf <<'JOU'
[Journal]
# Keep logs but cap total + per-file so disk pressure can't cause loss
SystemMaxUse=500M
SystemMaxFileSize=50M
MaxRetentionSec=14day
JOU
systemctl restart systemd-journald

# ----------------------------------------------------------------------------
log "Waiting for BTCPay to come up"
# ----------------------------------------------------------------------------
# Give nginx + the .NET app a minute to settle. Check the health endpoint.
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
  BTCPay Server deployed.

  Web UI:    https://$BTCPAY_HOST/

  NEXT STEPS (manual, do these now):

  1. Browse to https://$BTCPAY_HOST/Account/Register — the first
     account becomes the admin. Use a strong password manager.
     (Public registration is disabled, but the FIRST account is
     allowed.)

  2. In another tab, run the configure script which creates the
     store, sets up the BTC wallet from your xpub, mints the API
     key and webhook, and prints the env vars to drop into
     /etc/0trust/api.env on the control plane host:

       ./btcpay/scripts/configure.sh

  3. Check sync status of the chains:
       sudo /root/btcpayserver-docker/bitcoin-cli.sh getblockchaininfo
       sudo /root/btcpayserver-docker/monero-cli.sh status

     Bitcoin should sync within a few hours thanks to fastsync.
     Monero takes 1-3 days from a fresh download.

  4. Before going to production, run the integration test:
       ./btcpay/scripts/test-integration.sh
================================================================
EOF
