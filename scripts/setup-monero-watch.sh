#!/usr/bin/env bash
# ============================================================================
# 0trust — Monero payments without a Monero node
# ============================================================================
# Stands up `monero-wallet-rpc` as a VIEW-ONLY wallet against a PUBLIC remote
# node, which is what lets this deployment take XMR with no blockchain on disk
# and no ability to spend.
#
# Why a wallet and not an explorer, since every other coin here uses one:
# Monero publishes neither the recipient nor the amount. No explorer can
# answer "was this address paid" — that is the point of the coin. Detecting a
# payment needs the private VIEW key and a scan of every block's outputs, and
# the thing that does that is a wallet.
#
#   ./scripts/setup-monero-watch.sh --address 4... --view-key <secret view key>
#   ./scripts/setup-monero-watch.sh --restore-height 3100000 ...
#
# ---------------------------------------------------------------------------
# WHAT YOU ARE HANDING THIS BOX
#
# The private VIEW key. It can see every payment into the wallet, forever, and
# it cannot move any of them. The SPEND key stays with you and must never be
# typed here — a wallet holding one on an internet-facing machine is a wallet
# an intruder can empty.
#
# Get the view key from your own wallet:  seed → "Keys" → Secret view key.
# In monero-wallet-cli:  `viewkey`  (the SECRET one, not the public one).
# ---------------------------------------------------------------------------
set -euo pipefail

ADDRESS="" VIEW_KEY="" RESTORE_HEIGHT="" WALLET_NAME="0trust-watch"
RPC_PORT="18083"
# A public remote node. The wallet asks it for blocks; it never sees your
# keys, and it cannot tell which outputs are yours — but it does learn that
# this IP is scanning, so point it somewhere you are comfortable with.
DAEMON="${MONERO_DAEMON:-https://xmr-node.cakewallet.com:18081}"
WALLET_DIR="${MONERO_WALLET_DIR:-/var/lib/0trust/monero}"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --address) ADDRESS="${2:-}"; shift 2 ;;
        --view-key) VIEW_KEY="${2:-}"; shift 2 ;;
        --restore-height) RESTORE_HEIGHT="${2:-}"; shift 2 ;;
        --daemon) DAEMON="${2:-}"; shift 2 ;;
        --wallet-dir) WALLET_DIR="${2:-}"; shift 2 ;;
        --port) RPC_PORT="${2:-}"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) sed -n '2,32p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 64 ;;
    esac
done

RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[1;33m'; DIM=$'\033[2m'; NC=$'\033[0m'
log() { printf '%s[+] %s%s\n' "$YLW" "$*" "$NC"; }
ok()  { printf '%s[✓] %s%s\n' "$GRN" "$*" "$NC"; }
die() { printf '%s[!] %s%s\n' "$RED" "$*" "$NC" >&2; exit 1; }

[[ -n "$ADDRESS" ]]  || die "--address is your Monero primary address (starts with 4)"
[[ -n "$VIEW_KEY" ]] || die "--view-key is the SECRET view key. Never the spend key."
[[ "$ADDRESS" =~ ^4[0-9A-Za-z]{94}$ ]] \
    || die "--address does not look like a Monero primary address (4…, 95 chars)"
[[ "$VIEW_KEY" =~ ^[0-9a-f]{64}$ ]] \
    || die "--view-key should be 64 hex characters"

# A spend key is also 64 hex, so shape cannot tell them apart. Say it out loud
# instead: this is the one mistake here that loses money rather than breaking
# a feature.
cat <<EOF

${YLW}Before continuing, be certain that is the SECRET VIEW key.${NC}
${DIM}A spend key looks identical — 64 hex characters — and nothing here can
tell them apart. A view key on this box lets it watch payments. A spend key
on this box lets whoever takes this box spend them.${NC}

EOF
read -r -p "Type 'view' to confirm: " CONFIRM
[[ "$CONFIRM" == "view" ]] || die "aborted"

if ! command -v monero-wallet-rpc >/dev/null; then
    # Under --dry-run this is worth reporting rather than dying on: the whole
    # point of a dry run is to find out what a real run would need.
    [[ $DRY_RUN -eq 1 ]] && printf '%s[!] monero-wallet-rpc is not installed here%s\n' "$YLW" "$NC"
    [[ $DRY_RUN -eq 1 ]] || die "monero-wallet-rpc not installed.
    It is in the official CLI bundle from getmonero.org/downloads — the
    'monero-wallet-rpc' binary only; you do not need monerod, which is the
    node. Unpack it somewhere on PATH."
fi

if [[ -z "$RESTORE_HEIGHT" ]]; then
    cat <<EOF
${YLW}No --restore-height given.${NC}
${DIM}The wallet will scan from the beginning of the chain, which takes hours
and is almost never what you want. Pass the block height around when this
wallet was created; a height slightly too low costs time, too high misses
payments.${NC}
EOF
    read -r -p "Continue scanning from height 0? [y/N] " GO
    [[ "$GO" == "y" ]] || die "aborted — re-run with --restore-height"
    RESTORE_HEIGHT=0
fi

if [[ $DRY_RUN -eq 1 ]]; then
    ok "would create a view-only wallet in $WALLET_DIR from $ADDRESS"
    ok "would run monero-wallet-rpc on 127.0.0.1:$RPC_PORT against $DAEMON"
    exit 0
fi

install -d -m 0700 "$WALLET_DIR"

if [[ -f "$WALLET_DIR/$WALLET_NAME" ]]; then
    ok "wallet already exists at $WALLET_DIR/$WALLET_NAME — leaving it alone"
else
    log "Creating the view-only wallet"
    # generate-from-json is the non-interactive path. The file holds the view
    # key, so it is written 600 and removed immediately afterwards.
    SPEC="$(mktemp)"; chmod 600 "$SPEC"
    trap 'shred -u "$SPEC" 2>/dev/null || rm -f "$SPEC"' EXIT
    cat > "$SPEC" <<JSON
{
  "version": 1,
  "filename": "$WALLET_DIR/$WALLET_NAME",
  "scan_from_height": $RESTORE_HEIGHT,
  "password": "",
  "viewkey": "$VIEW_KEY",
  "address": "$ADDRESS"
}
JSON
    monero-wallet-rpc --generate-from-json "$SPEC" \
        --rpc-bind-port "$RPC_PORT" --rpc-bind-ip 127.0.0.1 \
        --disable-rpc-login --daemon-address "$DAEMON" \
        --log-level 0 --detach --non-interactive 2>&1 | tail -3 || true
    sleep 3
    ok "wallet created (view-only, scanning from height $RESTORE_HEIGHT)"
fi

log "Installing the service"
cat > /etc/systemd/system/0trust-monero.service <<UNIT
[Unit]
Description=0trust Monero view-only wallet (payments)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# --disable-rpc-login is safe ONLY because the socket is bound to loopback.
# If you ever move this off 127.0.0.1, add --rpc-login and set
# MONERO_RPC_USER / MONERO_RPC_PASSWORD in the dashboard.
ExecStart=/usr/bin/env monero-wallet-rpc \\
    --wallet-file $WALLET_DIR/$WALLET_NAME --password "" \\
    --rpc-bind-ip 127.0.0.1 --rpc-bind-port $RPC_PORT \\
    --disable-rpc-login --daemon-address $DAEMON \\
    --trusted-daemon --non-interactive --log-level 0
Restart=on-failure
RestartSec=15s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$WALLET_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now 0trust-monero.service
ok "0trust-monero.service running on 127.0.0.1:$RPC_PORT"

cat <<EOF

${GRN}  Monero is ready to configure.${NC}

  In the dashboard, under Settings -> Monero:
    MONERO_WALLET_RPC = http://127.0.0.1:$RPC_PORT/json_rpc

  XMR appears at checkout as soon as that is set, and not before — a coin
  with no wallet behind it is never offered.

  ${DIM}Check it is scanning:
    journalctl -u 0trust-monero -f
  The wallet must reach the chain tip before it can see a payment. Until it
  does, the dashboard's payment health shows the height it has reached.${NC}

  ${YLW}This box holds a view key and no spend key.${NC} ${DIM}Verify that:
    the dashboard's payment health says so, and refuses to call itself
    healthy if it ever finds a spend key here.${NC}

EOF
