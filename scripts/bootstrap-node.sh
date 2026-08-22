#!/usr/bin/env bash
# ============================================================================
# 0trust mesh node bootstrap (Ubuntu 24.04)
# ============================================================================
# Run on each WireGuard mesh node (entry/exit point).
# This box should be SEPARATE from the control plane box.
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
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$NODE_ROLE" in
    entry|exit|both) ;;
    *) echo "NODE_ROLE must be entry|exit|both, got: $NODE_ROLE" >&2; exit 1 ;;
esac

log() { printf '\033[1;33m[+] %s\033[0m\n' "$*"; }

if [[ $EUID -ne 0 ]]; then echo "must be root" >&2; exit 1; fi

# ----------------------------------------------------------------------------
log "Installing WireGuard + tooling"
# ----------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard wireguard-tools python3 ufw nftables iptables

# ----------------------------------------------------------------------------
log "Enabling IP forwarding (exit node functionality)"
# ----------------------------------------------------------------------------
cat > /etc/sysctl.d/99-0trust.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
# Drop source-routed packets, ignore ICMP redirects
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
# Reverse path filter
net.ipv4.conf.all.rp_filter=1
# Anti-spoofing
net.ipv4.conf.all.log_martians=1
EOF
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

cat > /etc/0trust/meshd.env <<EOF
CONTROL_URL=$CONTROL_URL
NODE_API_PSK=$NODE_API_PSK
NODE_ID=$NODE_ID
NODE_ROLE=$NODE_ROLE
WG_IFACE=wg0
WG_PRIVKEY=/etc/wireguard/wg0.key
WG_PORT=$WG_PORT
MESH_GATEWAY=10.64.0.1/10
POLL_INTERVAL=30
EOF
chmod 600 /etc/0trust/meshd.env

cp "$REPO_DIR/systemd/0trust-meshd.service" /etc/systemd/system/0trust-meshd.service
systemctl daemon-reload
systemctl enable --now 0trust-meshd.service

# ----------------------------------------------------------------------------
log "Configuring NAT for exit node"
# ----------------------------------------------------------------------------
PRIMARY_IF=$(ip -o -4 route show to default | awk '{print $5}' | head -n1)
# Table names are ztv_*, not 0trust_*: an nftables identifier cannot start
# with a digit. nft parses the leading 0 as a number and rejects the file
# ("syntax error, unexpected number"), and quoting does not help. Both tables
# here failed to load, which meant the exit node had no masquerade rule and
# — worse — the abuse-mitigation egress filter below was never in force.
nft -f - <<EOF
table inet ztv_nat {
    chain postrouting {
        type nat hook postrouting priority 100;
        oifname "$PRIMARY_IF" ip saddr 10.64.0.0/10 masquerade
    }
}
EOF
# persist
mkdir -p /etc/nftables.d
nft list table inet ztv_nat > /etc/nftables.d/0trust.nft

# ----------------------------------------------------------------------------
log "Abuse-mitigation egress filter (exit nodes)"
# ----------------------------------------------------------------------------
# These ship by default on every node so abuse complaints (the #1 cause of
# losing a VPS) are pre-empted. See docs/ABUSE.md for the rationale.
#   - Block outbound SMTP: stops the node being used to send spam, which
#     otherwise poisons the IP's reputation and gets it blocklisted.
#   - Block forwarding into private/link-local ranges: prevents a customer
#     from using the VPN to pivot into RFC1918 networks (the provider's
#     internal infra, other tenants, etc).
#   - Rate-limit new outbound connections: blunts port-scanning / connection
#     storms without affecting normal browsing.
CLIENT_NET="10.64.0.0/10"
nft -f - <<EOF
table inet ztv_egress {
    chain forward {
        type filter hook forward priority 0; policy accept;

        # Only police traffic originating from VPN clients
        ip saddr != $CLIENT_NET accept

        # Block outbound mail submission (anti-spam)
        tcp dport { 25, 465, 587 } drop

        # Block pivoting into private / link-local / CGNAT ranges
        ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } drop
        ip6 daddr { fc00::/7, fe80::/10 } drop

        # Throttle connection storms (scan mitigation)
        ct state new limit rate over 80/second drop
    }
}
EOF
nft list table inet ztv_egress >> /etc/nftables.d/0trust.nft

# ----------------------------------------------------------------------------
log "Firewall (UFW)"
# ----------------------------------------------------------------------------
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'ssh'
ufw allow "$WG_PORT/udp" comment 'wireguard'
ufw allow in on wg0
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
