#!/usr/bin/env bash
# ============================================================================
# 0trust mesh node bootstrap (Ubuntu 24.04)
# ============================================================================
# Run on each WireGuard mesh node (entry/exit point).
# This box should be SEPARATE from the control plane box.
#
# This is the MANUAL path: it sets a node up with a fixed id and the shared
# node PSK, and leaves you to insert the row on the control plane yourself.
# For a node that registers itself — and that can rejoin on its own after a
# reboot, which this one cannot — use:
#
#   sudo ./scripts/install.sh --mode node --control-url https://<cp> \
#        --region zur --provision-token <minted on the control plane>
#
# Usage:
#   sudo CONTROL_URL=https://api.0trustvpn.com \
#        NODE_API_PSK=<from /etc/0trust/api.env on control plane> \
#        NODE_ID=zur-01 \
#        REGION=zur \
#        ./bootstrap-node.sh
# ============================================================================
set -euo pipefail

CONTROL_URL="${CONTROL_URL:?Set CONTROL_URL=https://api.your-domain}"
NODE_API_PSK="${NODE_API_PSK:?Set NODE_API_PSK (from control plane api.env)}"
NODE_ID="${NODE_ID:?Set NODE_ID=zur-01}"
REGION="${REGION:?Set REGION=zur (zur|rey|buc)}"
NODE_ROLE="${NODE_ROLE:-both}"   # entry | exit | both
WG_PORT="${WG_PORT:-51820}"
MESH_GATEWAY="${MESH_GATEWAY:-10.64.0.1/10}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$NODE_ROLE" in
    entry|exit|both) ;;
    *) echo "NODE_ROLE must be entry|exit|both, got: $NODE_ROLE" >&2; exit 1 ;;
esac

log() { printf '\033[1;33m[+] %s\033[0m\n' "$*"; }

# The rules below (sysctl, NAT, egress filter, resolver) are shared with
# scripts/install.sh --mode test, so a single-VPS test deployment behaves the
# same way a real node does. Changing one and not the other is how a test box
# stops predicting production.
# shellcheck source=scripts/node-runtime.sh
source "$REPO_DIR/scripts/node-runtime.sh"

if [[ $EUID -ne 0 ]]; then echo "must be root" >&2; exit 1; fi

# ----------------------------------------------------------------------------
log "Installing WireGuard + tooling"
# ----------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools python3 ufw nftables iptables dnsmasq

# ----------------------------------------------------------------------------
log "Enabling IP forwarding (exit node functionality)"
# ----------------------------------------------------------------------------
ztv_sysctl_conf > /etc/sysctl.d/99-0trust.conf
sysctl -p /etc/sysctl.d/99-0trust.conf > /dev/null

# ----------------------------------------------------------------------------
log "Generating WireGuard keypair"
# ----------------------------------------------------------------------------
umask 077
mkdir -p /etc/wireguard /etc/0trust
if [[ ! -f /etc/wireguard/wg0.key ]]; then
    wg genkey | tee /etc/wireguard/wg0.key | wg pubkey > /etc/wireguard/wg0.pub
fi
chmod 600 /etc/wireguard/wg0.key
chmod 644 /etc/wireguard/wg0.pub
PUBKEY=$(cat /etc/wireguard/wg0.pub)
PUBLIC_IP=$(curl -fsS https://api.ipify.org)

# ----------------------------------------------------------------------------
log "Installing mesh syncer"
# ----------------------------------------------------------------------------
cp "$REPO_DIR/wireguard/0trust-meshd.py" /usr/local/bin/0trust-meshd
chmod +x /usr/local/bin/0trust-meshd

ztv_meshd_env "$CONTROL_URL" "$NODE_API_PSK" "$NODE_ID" "$NODE_ROLE" \
              wg0 "$WG_PORT" "$MESH_GATEWAY" ztv_forward \
              > /etc/0trust/meshd.env
chmod 600 /etc/0trust/meshd.env

cp "$REPO_DIR/systemd/0trust-meshd.service" /etc/systemd/system/0trust-meshd.service

# The NAT and egress rules below are kernel state, and nothing on a stock
# Ubuntu box replays them at boot — /etc/nftables.conf does not include
# /etc/nftables.d. Without this unit the node came back from a reboot doing no
# masquerading at all: customer traffic entered the tunnel and died silently,
# while meshd went on heartbeating over its own outbound HTTPS and the control
# plane kept routing customers here.
install -d /usr/local/lib/0trust
install -m 0644 "$REPO_DIR/scripts/node-runtime.sh" /usr/local/lib/0trust/node-runtime.sh
install -m 0755 "$REPO_DIR/scripts/node-runtime-apply.sh" \
        /usr/local/lib/0trust/node-runtime-apply.sh
cp "$REPO_DIR/systemd/0trust-node-runtime.service" \
   /etc/systemd/system/0trust-node-runtime.service

systemctl daemon-reload
systemctl enable 0trust-node-runtime.service >/dev/null 2>&1 || true
systemctl enable --now 0trust-meshd.service

# ----------------------------------------------------------------------------
log "Configuring NAT for exit node"
# ----------------------------------------------------------------------------
PRIMARY_IF=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
mkdir -p /etc/nftables.d
ztv_nat_ruleset "$PRIMARY_IF" | nft -f -
nft list table inet ztv_nat > /etc/nftables.d/0trust.nft

# ----------------------------------------------------------------------------
log "Abuse-mitigation egress filter (exit nodes)"
# ----------------------------------------------------------------------------
ztv_egress_ruleset | nft -f -
nft list table inet ztv_egress >> /etc/nftables.d/0trust.nft

# ----------------------------------------------------------------------------
log "Mesh resolver"
# ----------------------------------------------------------------------------
# Clients are handed DNS = the mesh gateway. Until this existed nothing was
# listening there, so a customer connected successfully and then could not
# resolve a single name — a tunnel that looks broken to everyone using it.
MESH_GW="${MESH_GATEWAY%%/*}"
mkdir -p /etc/dnsmasq.d
ztv_dnsmasq_conf "$MESH_GW" > /etc/dnsmasq.d/0trust.conf
systemctl enable dnsmasq >/dev/null 2>&1 || true
# dnsmasq cannot bind the gateway address until meshd has brought wg0 up, so
# a restart here may fail on a first run; the unit retries and meshd is
# already starting. Not fatal either way.
systemctl restart dnsmasq >/dev/null 2>&1 || \
    log "dnsmasq will bind $MESH_GW once wg0 is up"

# ----------------------------------------------------------------------------
log "Firewall (UFW)"
# ----------------------------------------------------------------------------
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'ssh'
ufw allow "$WG_PORT/udp" comment 'wireguard'
ufw allow in on wg0
# Note there is deliberately no `ufw allow 53`: the resolver binds the mesh
# gateway only. An open resolver on a public address is an amplification
# vector and an abuse report waiting to happen.
# Multi-hop entry-port range — UDP packets coming in here are immediately
# DNATed to an exit node by nftables (no socket on this host listens here)
if [[ "$NODE_ROLE" == "entry" || "$NODE_ROLE" == "both" ]]; then
    ufw allow 52000:59999/udp comment '0trust multi-hop'
fi
ufw --force enable

# ----------------------------------------------------------------------------
log "Done."
# ----------------------------------------------------------------------------
cat <<EOF

  Mesh node $NODE_ID ($REGION, role=$NODE_ROLE) is up.

  Register this node in the control plane DB:

    ssh <control-plane>
    sudo sqlite3 /var/lib/0trust/0trust.db <<SQL
      INSERT INTO mesh_nodes
        (id, hostname, pubkey, endpoint, region, role, public_ip)
      VALUES (
        '$NODE_ID',
        '$(hostname -f)',
        '$PUBKEY',
        '$PUBLIC_IP:$WG_PORT',
        '$REGION',
        '$NODE_ROLE',
        '$PUBLIC_IP'
      );
SQL

  Pubkey:          $PUBKEY
  Public endpoint: $PUBLIC_IP:$WG_PORT
  Role:            $NODE_ROLE

  Service: systemctl status 0trust-meshd
  Logs:    journalctl -u 0trust-meshd -f

EOF
