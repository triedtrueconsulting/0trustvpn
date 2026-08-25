#!/usr/bin/env bash
# ============================================================================
# 0trust wallet check
# ============================================================================
# Derives the first few receive addresses from the configured extended PUBLIC
# key and shows them, so you can confirm against your wallet BEFORE a customer
# pays into one.
#
# This is the failure CLAUDE.md singles out as the worst in the system: a
# typo'd or wrong-account xpub sends every customer payment to addresses the
# operator cannot spend, silently, with every health check green. There is no
# error to notice. The only defence is a human comparing the first address here
# against the first address their wallet shows.
#
#   ./scripts/check-wallet.sh                        # read /etc/0trust/api.env
#   ./scripts/check-wallet.sh zpub6q...              # check a key before use
#   ./scripts/check-wallet.sh --count 5 zpub6q...
#
# Nothing here contacts the network, and nothing here can spend: the derivation
# is local and an extended public key cannot sign.
# ============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COUNT=3
KEY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --count) COUNT="${2:-3}"; shift 2 ;;
        --env)   ENVFILE="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,22p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) KEY="$1"; shift ;;
    esac
done

ENVFILE="${ENVFILE:-${ZTV_ENV_FILE:-/etc/0trust/api.env}}"

if [[ -z "$KEY" ]]; then
    [[ -r "$ENVFILE" ]] || {
        echo "no key given and $ENVFILE is not readable" >&2
        echo "usage: $0 <xpub|ypub|zpub>" >&2
        exit 64
    }
    KEY="$(grep -hoP '^WALLET_BTC=\K.*' "$ENVFILE" | tail -1)"
    [[ -n "$KEY" ]] || { echo "WALLET_BTC is empty in $ENVFILE" >&2; exit 1; }
fi

PY="${ZTV_PYTHON:-python3}"
[[ -x "$REPO_DIR/.venv/bin/python" ]] && PY="$REPO_DIR/.venv/bin/python"

KEY="$KEY" COUNT="$COUNT" "$PY" - "$REPO_DIR" <<'PYEOF'
import os, sys
sys.path.insert(0, os.path.join(sys.argv[1], "api"))
import chainwatch

key = os.environ["KEY"].strip()
count = int(os.environ["COUNT"])

# An extended PRIVATE key here would mean the operator has put spending
# authority on an internet-facing box. chainwatch refuses it; say why.
if key[1:4] == "prv" or key.startswith(("xprv", "yprv", "zprv")):
    print("REFUSED: that is an extended PRIVATE key.", file=sys.stderr)
    print("  Nothing in 0trust ever needs one. Use the PUBLIC half (xpub/ypub/zpub).",
          file=sys.stderr)
    print("  If this key has been pasted into a server config, treat it as "
          "compromised and move the funds.", file=sys.stderr)
    sys.exit(2)

try:
    addrs = [chainwatch.receive_address(key, i) for i in range(count)]
except Exception as e:
    print(f"REFUSED: {type(e).__name__}: {e}", file=sys.stderr)
    print("  The key did not parse. A wrong key does not fail at runtime — it "
          "quietly issues addresses you cannot spend.", file=sys.stderr)
    sys.exit(1)

kind = {"x": "BIP44 legacy (1…)", "y": "BIP49 wrapped segwit (3…)",
        "z": "BIP84 native segwit (bc1…)"}.get(key[0], "unknown")
print(f"key   {key[:20]}…{key[-6:]}")
print(f"type  {kind}")
print(f"path  m/0/i  (external chain, one address per invoice)")
print()
for i, a in enumerate(addrs):
    print(f"  {i}  {a}")
print()
print("Compare the FIRST address against the next receive address your wallet")
print("shows. If they differ, this is the wrong key or the wrong account, and")
print("every payment will go somewhere you cannot spend from.")
PYEOF
