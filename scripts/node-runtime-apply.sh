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

# See node-enroll.sh: empty in production, a scratch prefix under test.
ROOT="${ZTV_ROOT:-}"
LIBDIR="${ZTV_LIBDIR:-/usr/local/lib/0trust}"
MESH_GATEWAY="${ZTV_MESH_GATEWAY:-10.64.0.1/10}"
NFT_DIR="${ZTV_NFT_DIR:-$ROOT/etc/nftables.d}"
DNSMASQ_DIR="${ZTV_DNSMASQ_DIR:-$ROOT/etc/dnsmasq.d}"
STUBBY_DIR="${ZTV_STUBBY_DIR:-$ROOT/etc/stubby}"

log() { printf '[runtime] %s\n' "$*"; }

# shellcheck source=node-runtime.sh
if [[ -r "$LIBDIR/node-runtime.sh" ]]; then
    source "$LIBDIR/node-runtime.sh"
else
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/node-runtime.sh"
fi

PRIMARY_IF="$(ip -o -4 route show to default | awk 'NR==1{print $5}')"
if [[ -n "$PRIMARY_IF" ]]; then
    mkdir -p "$NFT_DIR"
    ztv_nat_ruleset "$PRIMARY_IF" | nft -f -
    ztv_egress_ruleset | nft -f -
    { nft list table inet ztv_nat; nft list table inet ztv_egress; } \
        > "$NFT_DIR/0trust.nft" 2>/dev/null || true
    log "nftables: NAT via $PRIMARY_IF, egress filter applied"
else
    log "WARNING: no default route found; NAT not applied"
fi

# The DNS-over-TLS stub dnsmasq forwards to. Started first: dnsmasq below
# points at it, and a dnsmasq that comes up before its only upstream answers
# is a tunnel whose first few lookups fail.
if [[ "${ZTV_DNS_ENCRYPTED:-1}" == "1" ]]; then
    if command -v stubby >/dev/null; then
        mkdir -p "$STUBBY_DIR"
        ztv_stubby_conf > "$STUBBY_DIR/stubby.yml"
        systemctl enable stubby >/dev/null 2>&1 || true
        if systemctl restart stubby >/dev/null 2>&1; then
            log "upstream DNS: DNS-over-TLS via ${ZTV_DNS_TLS_UPSTREAM%% *}"
        else
            log "WARNING: stubby did not start — journalctl -u stubby."
            log "         dnsmasq has no upstream, so DNS will fail rather"
            log "         than resolve in clear. Set ZTV_DNS_ENCRYPTED=0 to"
            log "         accept cleartext upstream DNS instead."
        fi
    else
        log "WARNING: ZTV_DNS_ENCRYPTED=1 but stubby is not installed."
        log "         apt install stubby, or set ZTV_DNS_ENCRYPTED=0 and"
        log "         understand that upstream DNS then crosses the internet"
        log "         in clear. web/privacy.html 4d describes the intent."
    fi
fi

# Clients are handed DNS = the mesh gateway, so something has to answer there.
# bind-interfaces, and never on the public address: an open resolver is a
# DNS-amplification abuse report waiting to happen.
mkdir -p "$DNSMASQ_DIR"
ztv_dnsmasq_conf "${MESH_GATEWAY%%/*}" > "$DNSMASQ_DIR/0trust.conf"
systemctl enable dnsmasq >/dev/null 2>&1 || true
# dnsmasq cannot bind the gateway address until meshd has created wg0, and on
# a fresh boot meshd starts after this. Its own restarts pick it up.
systemctl restart dnsmasq >/dev/null 2>&1 \
    || log "dnsmasq will bind ${MESH_GATEWAY%%/*} once wg0 is up"
