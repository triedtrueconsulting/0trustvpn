#!/usr/bin/env bash
# ============================================================================
# 0trust node enrolment — runs on every boot, before meshd
# ============================================================================
# A mesh node's disk is tmpfs. That is the point: web/privacy.html and
# docs/AUDIT.md §5.3 tell customers the WireGuard private key never touches
# persistent storage, and the only way to keep that true is for the key to be
# generated fresh in RAM each time the box starts.
#
# The consequence is this script. After a reboot the node has no key, no node
# id and no PSK, so something has to register it again before meshd has
# anything to run on. It:
#
#   1. generates a fresh WireGuard keypair (in tmpfs)
#   2. works out this box's public address, and whether v6 egress works
#   3. calls the control plane to register — as a NEW node the first time, and
#      as the SAME node id on every boot after that
#   4. writes meshd's environment
#   5. reapplies NAT, the abuse egress filter and the mesh resolver, none of
#      which survive a reboot on their own
#
# It reads /etc/0trust-node.env, written by `install.sh --mode node` — the one
# 0trust file deliberately left on real disk, because without it step 3 needs
# a human with a fresh token every time the machine restarts.
#
# Exit codes matter here: systemd orders meshd after this unit, so failing
# loudly is better than leaving meshd to start against a half-written env.
# ============================================================================
set -euo pipefail

# ZTV_ROOT prefixes every system path this writes. Empty in production, which
# is the only value a node ever uses. It exists so the whole script can be run
# end to end against a scratch directory — the alternative was a test that
# needed real root to write /etc, which meant the enrolment path went
# unexercised on exactly the unprivileged CI that was supposed to be checking
# it.
ROOT="${ZTV_ROOT:-}"
ENVFILE="${ZTV_NODE_ENV:-$ROOT/etc/0trust-node.env}"
LIBDIR="${ZTV_LIBDIR:-/usr/local/lib/0trust}"
WG_DIR="${ZTV_WG_DIR:-$ROOT/etc/wireguard}"
CONF_DIR="${ZTV_CONF_DIR:-$ROOT/etc/0trust}"
STATE_DIR="${ZTV_STATE_DIR:-$ROOT/var/0trust}"
WG_IFACE="${ZTV_WG_IFACE:-wg0}"
MESH_GATEWAY="${ZTV_MESH_GATEWAY:-10.64.0.1/10}"

log() { printf '[enroll] %s\n' "$*"; }
die() { printf '[enroll] %s\n' "$*" >&2; exit 1; }

[[ -r "$ENVFILE" ]] || die "$ENVFILE is missing — run install.sh --mode node"
# shellcheck disable=SC1090
set -a; source "$ENVFILE"; set +a

: "${CONTROL_URL:?CONTROL_URL not set in $ENVFILE}"
: "${REGION:?REGION not set in $ENVFILE}"
: "${ZTV_PROVISION_TOKEN:?ZTV_PROVISION_TOKEN not set in $ENVFILE}"
NODE_ROLE="${NODE_ROLE:-both}"
WG_PORT="${WG_PORT:-51820}"
CONTROL_URL="${CONTROL_URL%/}"

umask 077
mkdir -p "$WG_DIR" "$CONF_DIR" "$STATE_DIR"

# --- 1. a key that has never existed before ---------------------------------
# Unconditionally regenerated. If /etc/wireguard is somehow NOT tmpfs, this is
# also what stops yesterday's key living on: it is overwritten every boot.
wg genkey > "$WG_DIR/$WG_IFACE.key"
wg pubkey < "$WG_DIR/$WG_IFACE.key" > "$WG_DIR/$WG_IFACE.pub"
chmod 600 "$WG_DIR/$WG_IFACE.key"
PUBKEY="$(cat "$WG_DIR/$WG_IFACE.pub")"

if [[ -z "$ROOT" ]] \
   && ! grep -qE "[[:space:]]/etc/wireguard[[:space:]]+tmpfs" /proc/mounts; then
    log "WARNING: /etc/wireguard is not tmpfs — the private key is on disk,"
    log "         which contradicts what the site tells customers."
fi

# --- 2. where we are --------------------------------------------------------
# Three services, because the node cannot register at all if this fails, and
# any one of them can be down or blocked by a provider. ZTV_IP_URLS overrides
# the list — for an operator who would rather not ask a third party, or who
# knows their address and can point this at something of their own.
: "${ZTV_IP_URLS:=https://api.ipify.org https://ifconfig.co/ip https://icanhazip.com}"
PUBLIC_IP="${ZTV_PUBLIC_IP:-}"
if [[ -z "$PUBLIC_IP" ]]; then
    for u in $ZTV_IP_URLS; do
        if candidate="$(curl -4 -fsS --max-time 10 "$u" 2>/dev/null | tr -d '[:space:]')" \
           && [[ "$candidate" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
            PUBLIC_IP="$candidate"; break
        fi
    done
fi
[[ -n "$PUBLIC_IP" ]] || die "could not determine this box's public IPv4"

# Whether v6 actually leaves this machine, not whether an address exists. A
# provider that hands out a v6 address and routes nothing is common, and
# claiming v6 we cannot carry is how traffic leaks around the tunnel. The
# heartbeat re-reports this every 30s, so a provider enabling or withdrawing
# v6 later corrects itself without anyone editing a database.
: "${ZTV_IP6_PROBE_URL:=https://api6.ipify.org}"
HAS_V6="${ZTV_NODE_IPV6:-}"
if [[ -z "$HAS_V6" ]]; then
    if curl -6 -fsS --max-time 8 "$ZTV_IP6_PROBE_URL" >/dev/null 2>&1; then
        HAS_V6=true
    else
        HAS_V6=false
    fi
fi

# --- 3. register ------------------------------------------------------------
REQ="$(printf '{"pubkey":"%s","public_ip":"%s","region":"%s","role":"%s","ipv6":%s,"wg_port":%s}' \
       "$PUBKEY" "$PUBLIC_IP" "$REGION" "$NODE_ROLE" "$HAS_V6" "$WG_PORT")"

RESP="$(curl -fsS --max-time 30 -X POST \
        -H 'Content-Type: application/json' \
        -H "X-Provision-Token: $ZTV_PROVISION_TOKEN" \
        -d "$REQ" "$CONTROL_URL/api/v1/node/provision")" || {
    # The body of a 4xx says which of the several ways this can go wrong it
    # was — expired, revoked, bound elsewhere, region mismatch — and without
    # it the operator gets "curl exited 22" and nothing else.
    BODY="$(curl -sS --max-time 30 -X POST \
            -H 'Content-Type: application/json' \
            -H "X-Provision-Token: $ZTV_PROVISION_TOKEN" \
            -d "$REQ" "$CONTROL_URL/api/v1/node/provision" 2>&1 || true)"
    die "control plane refused this node: ${BODY:0:300}"
}

read -r NODE_ID NODE_PSK REJOINED <<<"$(printf '%s' "$RESP" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d["node_id"], d["node_psk"], "rejoined" if d.get("rejoined") else "joined")
')" || die "could not parse the control plane response"
[[ -n "$NODE_ID" && -n "$NODE_PSK" ]] || die "control plane returned no node id"

if [[ "$REJOINED" == "rejoined" ]]; then
    log "rejoined the mesh as $NODE_ID (fresh key after reboot)"
else
    log "joined the mesh as $NODE_ID"
fi

# --- 4. meshd's environment -------------------------------------------------
# shellcheck source=node-runtime.sh
source "$LIBDIR/node-runtime.sh"
ztv_meshd_env "$CONTROL_URL" "$NODE_PSK" "$NODE_ID" "$NODE_ROLE" \
              "$WG_IFACE" "$WG_PORT" "$MESH_GATEWAY" ztv_forward \
              > "$CONF_DIR/meshd.env"
chmod 600 "$CONF_DIR/meshd.env"

# Not a secret: the id and address this box is known by, for the installer and
# for anyone reading the box later. The PSK stays out of it.
cat > "$STATE_DIR/enrol.state" <<STATE
NODE_ID=$NODE_ID
PUBLIC_IP=$PUBLIC_IP
WG_PORT=$WG_PORT
REGION=$REGION
NODE_ROLE=$NODE_ROLE
IPV6=$HAS_V6
ENROLLED_AT=$(date -u +%FT%TZ)
STATE
chmod 644 "$STATE_DIR/enrol.state"

# --- 5. the runtime a reboot would otherwise lose ---------------------------
# NAT, the abuse egress filter and the mesh resolver, in one place shared with
# the persistent-node path so the two cannot drift.
ZTV_ROOT="$ROOT" ZTV_LIBDIR="$LIBDIR" ZTV_MESH_GATEWAY="$MESH_GATEWAY" \
    "${ZTV_RUNTIME_APPLY:-$LIBDIR/node-runtime-apply.sh}"

log "ready — meshd starts next"
