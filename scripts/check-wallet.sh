#!/usr/bin/env bash
# ============================================================================
# 0trust wallet check
# ============================================================================
# Derives the first few receive addresses from the configured extended PUBLIC
# key and shows them, so you can confirm against your wallet BEFORE a customer
# pays into one — and checks the key against the identity recorded in
# scripts/wallet.pin.
#
# This is the failure CLAUDE.md singles out as the worst in the system: a
# typo'd or wrong-account xpub sends every customer payment to addresses the
# operator cannot spend, silently, with every health check green. There is no
# error to notice. Two defences, and you want both: the pin catches a key that
# is not the one this deployment was set up with, and a human comparing the
# first address below against their wallet catches the case where the pin
# itself was recorded from the wrong key.
#
#   ./scripts/check-wallet.sh                        # read /etc/0trust/api.env
#   ./scripts/check-wallet.sh zpub6q...              # check a key before use
#   ./scripts/check-wallet.sh --count 5 zpub6q...
#   ./scripts/check-wallet.sh --pin zpub6q...        # record a NEW wallet
#   ./scripts/check-wallet.sh --no-pin zpub6q...     # derive only, no compare
#
# Nothing here contacts the network, and nothing here can spend: the derivation
# is local and an extended public key cannot sign.
#
# Exit: 0 ok · 1 the key does not parse · 2 it is a private key
#       3 it is not the pinned wallet · 64 usage
# ============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COUNT=3
KEY=""
PIN_MODE="compare"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --count) COUNT="${2:-3}"; shift 2 ;;
        --env)   ENVFILE="${2:-}"; shift 2 ;;
        --pin)      PIN_MODE="record"; shift ;;
        --no-pin)   PIN_MODE="skip";   shift ;;
        --pin-file) PINFILE="${2:-}";  shift 2 ;;
        -h|--help) sed -n '2,29p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) KEY="$1"; shift ;;
    esac
done

ENVFILE="${ENVFILE:-${ZTV_ENV_FILE:-/etc/0trust/api.env}}"
PINFILE="${PINFILE:-${ZTV_WALLET_PIN_FILE:-$REPO_DIR/scripts/wallet.pin}}"

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

KEY="$KEY" COUNT="$COUNT" PINFILE="$PINFILE" PIN_MODE="$PIN_MODE" \
    "$PY" - "$REPO_DIR" <<'PYEOF'
import hashlib, os, re, sys
sys.path.insert(0, os.path.join(sys.argv[1], "api"))
import chainwatch

key = os.environ["KEY"].strip()
count = int(os.environ["COUNT"])
pinfile = os.environ["PINFILE"]
pin_mode = os.environ["PIN_MODE"]

# An extended PRIVATE key here would mean the operator has put spending
# authority on an internet-facing box. chainwatch refuses it; say why.
if key[1:4] == "prv" or key.startswith(("xprv", "yprv", "zprv")):
    print("REFUSED: that is an extended PRIVATE key.", file=sys.stderr)
    print("  Nothing in 0trust ever needs one. Use the PUBLIC half (xpub/ypub/zpub).",
          file=sys.stderr)
    print("  If this key has been pasted into a server config, treat it as "
          "compromised and move the funds.", file=sys.stderr)
    sys.exit(2)

reused = not chainwatch.looks_like_xpub(key)
if reused:
    # payments.WatchOnlyProvider accepts a bare address and reuses it, so this
    # is a real configuration and must not read as a broken one — but it is
    # the worse one, and the operator should hear that here too.
    if not re.fullmatch(r'(bc1[02-9ac-hj-np-z]{11,71}|[13][1-9A-HJ-NP-Za-km-z]{25,34})',
                        key):
        print("REFUSED: that is neither an extended public key nor a Bitcoin "
              "address.", file=sys.stderr)
        print("  A wrong key does not fail at runtime — it quietly issues "
              "addresses you cannot spend.", file=sys.stderr)
        sys.exit(1)
    addrs = [key]
else:
    try:
        addrs = [chainwatch.receive_address(key, i) for i in range(count)]
    except Exception as e:
        print(f"REFUSED: {type(e).__name__}: {e}", file=sys.stderr)
        print("  The key did not parse. A wrong key does not fail at runtime — "
              "it quietly issues addresses you cannot spend.", file=sys.stderr)
        sys.exit(1)

kind = {"x": "BIP44 legacy (1…)", "y": "BIP49 wrapped segwit (3…)",
        "z": "BIP84 native segwit (bc1…)"}.get(key[0], "unknown")
print(f"key   {key[:20]}…{key[-6:]}")
if reused:
    print("type  a single address, reused for every invoice")
    print("path  none — there is nothing to derive")
else:
    print(f"type  {kind}")
    print(f"path  m/0/i  (external chain, one address per invoice)")
print()
for i, a in enumerate(addrs):
    print(f"  {i}  {a}")
print()

if reused:
    print("This is ONE address for every customer. Two people owing the same")
    print("amount become impossible to tell apart, and the whole payment")
    print("history is public and linked. An account xpub fixes both.")
    print()

print("Compare the FIRST address against the next receive address your wallet")
print("shows. If they differ, this is the wrong key or the wrong account, and")
print("every payment will go somewhere you cannot spend from.")

# --- identity pin -----------------------------------------------------------
# The digest, never the key: a SHA-256 gives up nothing about the wallet, and
# an xpub in a repository gives up its whole history to everyone with read
# access, forever.
digest = hashlib.sha256(key.encode()).hexdigest()


def read_pin(path):
    try:
        with open(path) as fh:
            for line in fh:
                m = re.match(r'\s*sha256:\s*([0-9a-fA-F]{64})\s*$', line)
                if m:
                    return m.group(1).lower()
    except FileNotFoundError:
        return None
    return None


if pin_mode == "record":
    body = ""
    if os.path.exists(pinfile):
        body = "".join(l for l in open(pinfile)
                       if not re.match(r'\s*sha256:', l))
    else:
        body = ("# 0trust receiving wallet — identity pin.\n"
                "# The SHA-256 of the extended PUBLIC key that receives "
                "customer payments;\n# never the key itself.\n")
    with open(pinfile, "w") as fh:
        fh.write(body.rstrip("\n") + f"\nsha256:{digest}\n")
    print()
    print(f"PINNED: {pinfile} now records this wallet.")
    print("  Commit it. Every install and preflight from here on refuses a key")
    print("  that is not this one.")
    sys.exit(0)

if pin_mode == "skip":
    sys.exit(0)

pinned = read_pin(pinfile)
print()
if pinned is None:
    print(f"note  no wallet pinned in {pinfile} — nothing to compare against.")
    print("      ./scripts/check-wallet.sh --pin <key>  records this one.")
elif pinned == digest:
    print("PINNED WALLET: this is the key this deployment was set up with.")
else:
    print()
    print("MISMATCH: this is NOT the wallet recorded in", pinfile, file=sys.stderr)
    print(f"  expected sha256 {pinned}", file=sys.stderr)
    print(f"  this key        {digest}", file=sys.stderr)
    print("  Either the key was mistyped or truncated, or it is a different"
          " account.", file=sys.stderr)
    print("  Both send customer money to addresses you cannot spend, with no"
          " error anywhere.", file=sys.stderr)
    print("  If the new wallet is deliberate: ./scripts/check-wallet.sh --pin"
          " <key>", file=sys.stderr)
    sys.exit(3)
PYEOF
