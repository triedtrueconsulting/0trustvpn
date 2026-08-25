#!/usr/bin/env bash
# ============================================================================
# 0trust BTCPay store configuration
# ============================================================================
# Run AFTER bootstrap.sh and AFTER you've registered an admin account at
# https://$BTCPAY_HOST/Account/Register
#
# What this does (all idempotent — safe to re-run):
#   1. Authenticates as the admin you just created
#   2. Creates (or finds) a store called "0trust VPN"
#   3. Configures Bitcoin to use your watching-only xpub
#   4. Enables Monero (uses BTCPay's internal wallet — XMR has no xpub concept)
#   5. Creates a webhook pointing at the 0trust control plane
#   6. Mints a scoped API key with exactly the permissions the control plane needs
#   7. Prints the four env values to drop into /etc/0trust/api.env
#
# Run on the BTCPay host itself, or anywhere with curl + jq that can reach the
# BTCPay HTTPS endpoint.
#
# Required env:
#   BTCPAY_HOST            FQDN of the BTCPay box (e.g. pay.0trustvpn.com)
#   BTCPAY_ADMIN_EMAIL     Email you registered the admin account with
#   BTCPAY_ADMIN_PASSWORD  That account's password
#   BTC_XPUB               The Bitcoin xpub/ypub/zpub from your cold wallet
#   CONTROL_HOST           FQDN of the 0trust control plane (e.g. 0trustvpn.com)
#
# Optional:
#   STORE_NAME             default "0trust VPN"
#   BTC_DERIVATION_SCHEME  default infers from xpub prefix (zpub→native segwit)
# ============================================================================
set -euo pipefail

log()  { printf '\033[1;33m[+] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;31m[!] %s\033[0m\n' "$*" >&2; }
die()  { warn "$*"; exit 1; }

for v in BTCPAY_HOST BTCPAY_ADMIN_EMAIL BTCPAY_ADMIN_PASSWORD BTC_XPUB CONTROL_HOST; do
    [[ -n "${!v:-}" ]] || die "set $v=..."
done
command -v jq >/dev/null || die "install jq first"

STORE_NAME="${STORE_NAME:-0trust VPN}"
BASE="https://$BTCPAY_HOST"

# ----------------------------------------------------------------------------
# Step 1 — Mint a session API key using basic-auth, then forget the password
# ----------------------------------------------------------------------------
# Greenfield supports HTTP basic auth on /api/v1/api-keys to bootstrap. We use
# that exactly once to mint a SHORT-LIVED admin-scoped key, then use that key
# for everything else so the password never leaves our memory.
log "Bootstrapping admin API key"
basic_b64=$(printf '%s:%s' "$BTCPAY_ADMIN_EMAIL" "$BTCPAY_ADMIN_PASSWORD" | base64 -w0)

# Note: the unrestricted scope is required for store creation. We delete this
# key at the end of the script.
admin_key_resp=$(curl -fsS -X POST "$BASE/api/v1/api-keys" \
    -H "Authorization: Basic $basic_b64" \
    -H "Content-Type: application/json" \
    -d '{
        "label": "0trust-configure-temp",
        "permissions": ["unrestricted"]
    }')
ADMIN_KEY=$(echo "$admin_key_resp" | jq -r .apiKey)
ADMIN_KEY_ID=$(echo "$admin_key_resp" | jq -r .id)
[[ -n "$ADMIN_KEY" && "$ADMIN_KEY" != "null" ]] || die "admin key creation failed: $admin_key_resp"
unset BTCPAY_ADMIN_PASSWORD basic_b64

# Helper for authenticated calls
api() {
    local method="$1" path="$2" body="${3:-}"
    if [[ -n "$body" ]]; then
        curl -fsS -X "$method" "$BASE$path" \
            -H "Authorization: token $ADMIN_KEY" \
            -H "Content-Type: application/json" \
            -d "$body"
    else
        curl -fsS -X "$method" "$BASE$path" \
            -H "Authorization: token $ADMIN_KEY"
    fi
}

cleanup() {
    if [[ -n "${ADMIN_KEY_ID:-}" ]]; then
        log "Revoking temporary admin key"
        api DELETE "/api/v1/api-keys/$ADMIN_KEY_ID" >/dev/null || true
    fi
}
trap cleanup EXIT

# ----------------------------------------------------------------------------
# Step 2 — Find or create the store
# ----------------------------------------------------------------------------
log "Finding or creating store '$STORE_NAME'"
existing=$(api GET "/api/v1/stores" | jq -r --arg n "$STORE_NAME" '.[] | select(.name == $n) | .id' | head -1)
if [[ -n "$existing" ]]; then
    STORE_ID="$existing"
    log "Using existing store $STORE_ID"
else
    create_resp=$(api POST "/api/v1/stores" "$(jq -nc \
        --arg name "$STORE_NAME" \
        --arg url "https://$CONTROL_HOST" \
        '{
            name: $name,
            website: $url,
            defaultCurrency: "USD",
            invoiceExpiration: 900,
            monitoringExpiration: 86400,
            speedPolicy: "MediumSpeed",
            networkFeeMode: "MultiplePaymentsOnly",
            anyoneCanCreateInvoice: false,
            requiresRefundEmail: false
        }')")
    STORE_ID=$(echo "$create_resp" | jq -r .id)
    log "Created store $STORE_ID"
fi

# ----------------------------------------------------------------------------
# Step 3 — Configure Bitcoin: watching-only via xpub
# ----------------------------------------------------------------------------
# Derivation scheme format depends on the xpub prefix:
#   xpub.../44'/0'/0'  → legacy P2PKH        → "<xpub>-[legacy]"
#   ypub.../49'/0'/0'  → wrapped segwit      → "<xpub>"
#   zpub.../84'/0'/0'  → native segwit       → "<xpub>"  (default)
log "Configuring Bitcoin payment method"
prefix=${BTC_XPUB:0:4}
case "$prefix" in
    xpub|tpub)  DERIVATION="${BTC_XPUB}-[legacy]" ;;
    ypub|upub)  DERIVATION="$BTC_XPUB" ;;
    zpub|vpub)  DERIVATION="$BTC_XPUB" ;;
    *)          die "Unrecognized xpub prefix '$prefix' (expected xpub/ypub/zpub)" ;;
esac

# The wallet this deployment is meant to pay into is recorded by digest in
# scripts/wallet.pin. Check it here too: BTCPay will happily accept any valid
# derivation scheme, issue addresses from it forever, and mark invoices paid —
# into somebody else's wallet, with nothing to notice.
CHECK_WALLET="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/scripts/check-wallet.sh"
if [[ -x "$CHECK_WALLET" ]]; then
    rc=0; "$CHECK_WALLET" --count 1 "$BTC_XPUB" >/dev/null 2>&1 || rc=$?
    if [[ $rc -eq 3 && -z "${ALLOW_UNPINNED_WALLET:-}" ]]; then
        die "BTC_XPUB is not the wallet pinned in scripts/wallet.pin.
    Run ./scripts/check-wallet.sh '$prefix…' to see both digests. If this
    wallet is deliberate, re-pin it (--pin) or set ALLOW_UNPINNED_WALLET=1."
    fi
else
    warn "scripts/check-wallet.sh not found — BTC_XPUB unverified"
fi

api PUT "/api/v1/stores/$STORE_ID/payment-methods/BTC-CHAIN" "$(jq -nc \
    --arg deriv "$DERIVATION" \
    '{
        enabled: true,
        config: { derivationScheme: $deriv }
    }')" >/dev/null

# Verify the wallet is watching-only (no private key on the BTCPay host)
btc_method=$(api GET "/api/v1/stores/$STORE_ID/payment-methods/BTC-CHAIN" || echo '{}')
log "  BTC payment method: $(echo "$btc_method" | jq -r .enabled) (watching-only)"

# ----------------------------------------------------------------------------
# Step 4 — Configure Monero
# ----------------------------------------------------------------------------
# Monero doesn't have xpub-style watching keys with the same UX as Bitcoin.
# (Technically it has view keys, but BTCPay's Monero plugin operates a hot
# wallet via monero-wallet-rpc. The wallet's seed and spend key live on the
# BTCPay host. Operator MUST sweep funds regularly.)
#
# The BTCPay Monero plugin auto-generates a wallet on first run. Here we
# enable the payment method; the wallet itself already exists if you ran
# bootstrap.sh with ENABLE_MONERO=1.
log "Configuring Monero payment method"
xmr_resp=$(api GET "/api/v1/stores/$STORE_ID/payment-methods" \
    | jq -r '.[] | select(.paymentMethodId | startswith("XMR-")) | .paymentMethodId' \
    | head -1)
if [[ -n "$xmr_resp" ]]; then
    api PUT "/api/v1/stores/$STORE_ID/payment-methods/$xmr_resp" '{"enabled": true}' >/dev/null
    log "  XMR payment method enabled (hot wallet on BTCPay host — sweep regularly)"
else
    warn "  XMR payment method not available — did bootstrap.sh run with ENABLE_MONERO=1?"
    warn "  Continuing without Monero. You can enable it later from the BTCPay UI."
fi

# ----------------------------------------------------------------------------
# Step 5 — Webhook
# ----------------------------------------------------------------------------
log "Configuring webhook to 0trust control plane"
WEBHOOK_URL="https://$CONTROL_HOST/api/v1/payment/webhook"

# Generate a 256-bit HMAC secret. This is what the control plane will use to
# verify webhook authenticity.
WEBHOOK_SECRET=$(openssl rand -hex 32)

# Remove any old 0trust webhook so this is idempotent
api GET "/api/v1/stores/$STORE_ID/webhooks" \
    | jq -r --arg url "$WEBHOOK_URL" '.[] | select(.url == $url) | .id' \
    | while read -r old; do
        [[ -n "$old" ]] && api DELETE "/api/v1/stores/$STORE_ID/webhooks/$old" >/dev/null
    done

# Subscribe only to events the control plane cares about. Don't send PaymentSettled
# noise — the 0trust API tracks the invoice lifecycle on InvoiceSettled / Invalid.
api POST "/api/v1/stores/$STORE_ID/webhooks" "$(jq -nc \
    --arg url "$WEBHOOK_URL" \
    --arg secret "$WEBHOOK_SECRET" \
    '{
        url: $url,
        secret: $secret,
        enabled: true,
        automaticRedelivery: true,
        authorizedEvents: {
            everything: false,
            specificEvents: [
                "InvoiceSettled",
                "InvoiceInvalid",
                "InvoiceExpired"
            ]
        }
    }')" >/dev/null

# ----------------------------------------------------------------------------
# Step 6 — Production API key (least-privilege, store-scoped)
# ----------------------------------------------------------------------------
log "Minting production API key for the control plane"
PROD_KEY_RESP=$(api POST "/api/v1/api-keys" "$(jq -nc \
    --arg storeId "$STORE_ID" \
    '{
        label: "0trust-control-plane",
        permissions: [
            ("btcpay.store.canviewinvoices:" + $storeId),
            ("btcpay.store.cancreateinvoice:" + $storeId),
            ("btcpay.store.canviewstoresettings:" + $storeId)
        ]
    }')")
PROD_KEY=$(echo "$PROD_KEY_RESP" | jq -r .apiKey)
[[ -n "$PROD_KEY" && "$PROD_KEY" != "null" ]] || die "prod key creation failed"

# ----------------------------------------------------------------------------
# Step 7 — Output the env block
# ----------------------------------------------------------------------------
ENV_FILE="/tmp/0trust-btcpay.env"
cat > "$ENV_FILE" <<EOF
# Drop these four lines into /etc/0trust/api.env on the control plane host,
# then: sudo systemctl restart 0trust-api
BTCPAY_URL=$BASE
BTCPAY_STORE_ID=$STORE_ID
BTCPAY_API_KEY=$PROD_KEY
BTCPAY_WEBHOOK_SECRET=$WEBHOOK_SECRET
EOF
chmod 600 "$ENV_FILE"

cat <<EOF

================================================================
  BTCPay store configured.

  Env file written to: $ENV_FILE  (mode 0600)

  Contents:
$(sed 's/^/    /' "$ENV_FILE")

  Next:
    1. Copy $ENV_FILE to the control plane host:
         scp $ENV_FILE root@$CONTROL_HOST:/etc/0trust/api.env.btcpay
    2. On the control plane host, merge into /etc/0trust/api.env:
         cat /etc/0trust/api.env.btcpay >> /etc/0trust/api.env
         systemctl restart 0trust-api
    3. Verify the integration end-to-end:
         ./btcpay/scripts/test-integration.sh
================================================================
EOF
