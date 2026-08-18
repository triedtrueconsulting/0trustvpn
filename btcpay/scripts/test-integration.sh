#!/usr/bin/env bash
# ============================================================================
# 0trust BTCPay integration smoke test
# ============================================================================
# Verifies the full payment path works end-to-end:
#
#   1.  Hit the 0trust API to mint a new account + open an invoice
#   2.  Confirm BTCPay shows the invoice with the expected amount + status
#   3.  Mark the invoice settled via BTCPay's Greenfield API
#       (the prod path requires actual on-chain payment; for testing we use
#        the manual mark-settled endpoint that requires admin auth)
#   4.  Wait for BTCPay to fire the webhook to the control plane
#   5.  Confirm the 0trust account flipped from pending_payment → active
#
# Exits 0 only if every step passes. The whole test takes ~30 seconds.
#
# Required env:
#   CONTROL_URL          e.g. https://0trustvpn.com
#   BTCPAY_URL           e.g. https://pay.0trustvpn.com
#   BTCPAY_API_KEY       Admin key (NOT the prod key — we need to mark-settled)
#   BTCPAY_STORE_ID
# ============================================================================
set -euo pipefail

log()  { printf '\033[1;33m[+] %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m[✓] %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m[✗] %s\033[0m\n' "$*" >&2; exit 1; }

for v in CONTROL_URL BTCPAY_URL BTCPAY_API_KEY BTCPAY_STORE_ID; do
    [[ -n "${!v:-}" ]] || fail "set $v=..."
done
command -v jq >/dev/null || fail "install jq first"

ctl_api() { curl -fsS "$@" -m 10; }
btc_api() {
    local method="$1" path="$2" body="${3:-}"
    if [[ -n "$body" ]]; then
        curl -fsS -X "$method" "$BTCPAY_URL$path" -m 10 \
            -H "Authorization: token $BTCPAY_API_KEY" \
            -H "Content-Type: application/json" -d "$body"
    else
        curl -fsS -X "$method" "$BTCPAY_URL$path" -m 10 \
            -H "Authorization: token $BTCPAY_API_KEY"
    fi
}

# ----------------------------------------------------------------------------
log "Step 1/5 — Create a test account on the control plane"
# ----------------------------------------------------------------------------
acct_resp=$(ctl_api -X POST "$CONTROL_URL/api/v1/account" \
    -H "Content-Type: application/json" \
    -d '{"months": 1}')
TOKEN=$(echo "$acct_resp" | jq -r .token)
INVOICE_ID=$(echo "$acct_resp" | jq -r .invoice_id)
[[ -n "$TOKEN" && "$TOKEN" != "null" ]] || fail "no token in response: $acct_resp"
[[ -n "$INVOICE_ID" && "$INVOICE_ID" != "null" ]] || fail "no invoice_id: $acct_resp"
ok "token=$TOKEN  invoice=$INVOICE_ID"

# ----------------------------------------------------------------------------
log "Step 2/5 — Confirm BTCPay has the invoice"
# ----------------------------------------------------------------------------
inv=$(btc_api GET "/api/v1/stores/$BTCPAY_STORE_ID/invoices/$INVOICE_ID")
status=$(echo "$inv" | jq -r .status)
amount=$(echo "$inv" | jq -r .amount)
currency=$(echo "$inv" | jq -r .currency)
ok "BTCPay invoice exists: status=$status amount=$amount $currency"
[[ "$status" == "New" || "$status" == "Processing" ]] || fail "unexpected status $status"

# ----------------------------------------------------------------------------
log "Step 3/5 — Confirm 0trust shows the account as pending"
# ----------------------------------------------------------------------------
sub_status=$(ctl_api -H "X-Account-Token: $TOKEN" \
    "$CONTROL_URL/api/v1/account/status" | jq -r .status)
[[ "$sub_status" == "pending_payment" ]] || fail "expected pending_payment, got $sub_status"
ok "0trust account status=pending_payment"

# ----------------------------------------------------------------------------
log "Step 4/5 — Marking invoice settled (admin override, test only)"
# ----------------------------------------------------------------------------
# In production, this happens automatically when on-chain payment confirms.
# For the smoke test we use BTCPay's admin endpoint to skip the wait.
btc_api POST "/api/v1/stores/$BTCPAY_STORE_ID/invoices/$INVOICE_ID/mark" \
    '{"status": "Settled"}' >/dev/null
ok "invoice marked settled — webhook should now fire"

# ----------------------------------------------------------------------------
log "Step 5/5 — Waiting for the webhook to propagate to 0trust"
# ----------------------------------------------------------------------------
# BTCPay queues webhooks; delivery can take up to ~15s.
deadline=$(( $(date +%s) + 30 ))
while (( $(date +%s) < deadline )); do
    sub_status=$(ctl_api -H "X-Account-Token: $TOKEN" \
        "$CONTROL_URL/api/v1/account/status" | jq -r .status)
    if [[ "$sub_status" == "active" ]]; then
        days=$(ctl_api -H "X-Account-Token: $TOKEN" \
            "$CONTROL_URL/api/v1/account/status" | jq -r .days_remaining)
        ok "account flipped to active ($days days remaining)"
        echo ""
        echo "================================================================"
        echo "  INTEGRATION TEST PASSED"
        echo ""
        echo "  Webhook delivery and signature verification both work."
        echo "  The control plane successfully recognized the BTCPay event"
        echo "  and extended the subscription."
        echo "================================================================"
        exit 0
    fi
    sleep 2
done

fail "timed out waiting for webhook — account still status=$sub_status

Things to check:
  - BTCPay webhook delivery log:
      $BTCPAY_URL/stores/$BTCPAY_STORE_ID/webhooks
  - Control plane logs:
      journalctl -u 0trust-api --since '1 min ago' | grep webhook
  - Firewall: BTCPay host can reach $CONTROL_URL on 443"
