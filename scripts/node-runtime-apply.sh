#!/usr/bin/env bash
# ============================================================================
# 0trust node runtime — apply the kernel state a reboot forgets
# ============================================================================
# NAT, the abuse egress filter and the mesh resolver. All three are configured
# once at install time and then live in the kernel or in a daemon, and nothing
# on a stock Ubuntu box replays them at boot: /etc/nftables.conf does not
# include /etc/nftables.d, so an exit node came back from a reboot doing no
# masquerading at all. Customer traffic entered the tunnel and went nowhere,
# while meshd's heartbeat — an outbound HTTPS call that does not care — kept
# reporting the node healthy.
#
# Run by 0trust-node-enroll on a RAM-only node, and by
# 0trust-node-runtime.service on a persistent one. Idempotent: nft replaces
# whole tables, and the dnsmasq config is rewritten from the same inputs.
# ============================================================================
set -euo pipefail

LIBDIR="${ZTV_LIBDIR:-/usr/local/lib/0trust}"
MESH_GATEWAY="${ZTV_MESH_GATEWAY:-10.64.0.1/10}"

log() { printf '[runtime] %s\n' "$*"; }

# shellcheck source=node-runtime.sh
if [[ -r "$LIBDIR/node-runtime.sh" ]]; then
    source "$LIBDIR/node-runtime.sh"
else
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/node-runtime.sh"
fi

PRIMARY_IF="$(ip -o -4 route show to default | awk '{print $5}' | head -n1)"
if [[ -n "$PRIMARY_IF" ]]; then
    mkdir -p /etc/nftables.d
    ztv_nat_ruleset "$PRIMARY_IF" | nft -f -
    ztv_egress_ruleset | nft -f -
    { nft list table inet ztv_nat; nft list table inet ztv_egress; } \
        > /etc/nftables.d/0trust.nft 2>/dev/null || true
    log "nftables: NAT via $PRIMARY_IF, egress filter applied"
else
    log "WARNING: no default route found; NAT not applied"
fi

# Clients are handed DNS = the mesh gateway, so something has to answer there.
# bind-interfaces, and never on the public address: an open resolver is a
# DNS-amplification abuse report waiting to happen.
mkdir -p /etc/dnsmasq.d
ztv_dnsmasq_conf "${MESH_GATEWAY%%/*}" > /etc/dnsmasq.d/0trust.conf
systemctl enable dnsmasq >/dev/null 2>&1 || true
# dnsmasq cannot bind the gateway address until meshd has created wg0, and on
# a fresh boot meshd starts after this. Its own restarts pick it up.
systemctl restart dnsmasq >/dev/null 2>&1 \
    || log "dnsmasq will bind ${MESH_GATEWAY%%/*} once wg0 is up"
