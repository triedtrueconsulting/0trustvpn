#!/usr/bin/env python3
"""BTC / XMR / ZEC through both providers, neither of which needs a local node."""
import json, os, shutil, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H
import fake_gateway

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

GATEWAY_PORT = H.pick_port()
TMP = H.tempdir("0trust-pay-"); DB = os.path.join(TMP, "0trust.db")
os.environ["ZTV_DB_PATH"] = DB
sys.path.insert(0, os.path.join(H.REPO, "api"))
import main as api_main; api_main.init_db()
H.seed_nodes(DB)

print("=== provider: btcpay (self-hosted or hosted BTCPay) ===")
H.boot(DB, workers=1)
try:
    st, acct = H.call("POST", "/api/v1/account", {"months": 1})
    check("invoice opened via BTCPay", st == 200, f"{st} {acct}")
    st, methods = H.call("GET", f"/api/v1/payment/{acct['invoice_id']}/methods")
    curs = {m["currency"] for m in methods.get("methods", [])}
    check("BTC offered", "BTC" in curs, curs)
    check("XMR offered", "XMR" in curs, curs)
    code, _ = H.settle(acct["invoice_id"])
    check("settlement credits the account", code == 200, code)
    st, s = H.call("GET", "/api/v1/account/status",
                   headers={"X-Account-Token": acct["token"]})
    check("account active", s["status"] == "active", s)
    # Compare expires_at, not days_remaining. days_remaining is
    # (expires - now) // 86400, so it ticks down on its own: if the second read
    # lands the other side of a whole-day boundary the value drops by one and
    # the test reports a re-credit failure that never happened. That is the
    # intermittent "30 -> 29" this module produced roughly once in three full
    # suite runs. The property under test is that the stored expiry does not
    # move, and that is an absolute timestamp.
    expires = s["expires_at"]
    for _ in range(3):
        H.settle(acct["invoice_id"])
    s2 = H.call("GET", "/api/v1/account/status",
                headers={"X-Account-Token": acct["token"]})[1]
    check("replay still cannot re-credit", s2["expires_at"] == expires,
          f"expiry moved: {expires} -> {s2['expires_at']} "
          f"({(s2['expires_at'] - expires) // 86400} extra days credited)")
finally:
    H.shutdown()

print("\n=== the price is the server's, whatever the client sends ===")
# PRICING is the only place a term costs anything. Nothing in the suite
# checked that, so a request that named its own amount, or ordered a term
# that is not for sale, was never tried against the running system — on the
# one path in this product that moves money.
H.boot(DB, workers=1)
try:
    import main as _m
    check("the signup model has no amount field to override",
          not ({"amount", "amount_usd", "price", "usd"}
               & set(_m.AccountCreateRequest.model_fields)),
          list(_m.AccountCreateRequest.model_fields))

    # Terms that are not for sale. 2 and 13 are the realistic ones: adjacent
    # to a real term, and the shape a client would send if it built the
    # number itself instead of reading /api/v1/config.
    for bad in (0, -1, 2, 13, 999999, 2 ** 40, 1.5, None, "abc"):
        st, body = H.call("POST", "/api/v1/account", {"months": bad})
        check(f"months={bad!r} is refused", st in (400, 422), f"{st} {str(body)[:90]}")

    # A planted price must not reach the invoice. Pydantic ignores the unknown
    # field, which is the correct outcome and is also the silent one — so the
    # check is on the amount that was STORED, not on the status code.
    for months in sorted(_m.PRICING):
        st, acct = H.call("POST", "/api/v1/account",
                          {"months": months, "amount_usd": 0.01, "price": 0.01})
        check(f"{months}-month signup succeeds with a planted price", st == 200,
              f"{st} {str(acct)[:120]}")
        if st != 200:
            continue
        import sqlite3 as _sq
        with _sq.connect(DB) as _c:
            _c.row_factory = _sq.Row
            row = _c.execute("SELECT months, amount_usd FROM invoices WHERE id = ?",
                             (acct["invoice_id"],)).fetchone()
        check(f"the {months}-month invoice is priced from PRICING, not the request",
              row is not None and abs(row["amount_usd"] - _m.PRICING[months]) < 0.001,
              f"stored={dict(row) if row else None} expected={_m.PRICING[months]}")

    # The invoice id is deliberately a bearer capability — that is why nginx
    # and uvicorn both drop this request path from their logs. So the property
    # to hold is not that the route is authenticated (it is not) but that the
    # id cannot be guessed and buys nothing except payment state.
    st, acct = H.call("POST", "/api/v1/account", {"months": 1})
    if st == 200:
        st2, body2 = H.call("GET", f"/api/v1/payment/{acct['invoice_id']}/status")
        check("the invoice id returns payment state and no account token",
              st2 == 200 and acct["token"] not in json.dumps(body2)
              and "token" not in body2, f"{st2} {str(body2)[:120]}")
        st3, _ = H.call("GET", "/api/v1/payment/btc-1-guessed-invoice-id/status")
        check("a guessed invoice id gets nothing", st3 in (401, 403, 404), st3)

    import inspect, re as _re
    import payments as _p
    wsrc = inspect.getsource(_p.WatchOnlyProvider.create_invoice)
    m = _re.search(r"secrets\.token_urlsafe\((\d+)\)", wsrc)
    check("the default provider's invoice id is 16+ bytes of secrets entropy",
          bool(m) and int(m.group(1)) >= 16,
          m.group(1) if m else "no secrets.token_urlsafe literal found")
finally:
    H.shutdown()

print("\n=== provider: hosted gateway (no blockchain infrastructure at all) ===")
gw = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(
    os.path.abspath(__file__)), "fake_gateway.py"), str(GATEWAY_PORT)],
    env={**os.environ, "ZTV_PAYMENT_IPN_SECRET": "ipn-secret",
         "CONTROL_URL": H.API},
    stdout=open(f"{TMP}/gw.log", "w"), stderr=subprocess.STDOUT)
H.free_port_wait(GATEWAY_PORT)

hosted_env = {
    "ZTV_PAYMENT_PROVIDER": "hosted",
    "ZTV_PAYMENT_API_URL": f"http://127.0.0.1:{GATEWAY_PORT}",
    "ZTV_PAYMENT_API_KEY": "gw-key",
    "ZTV_PAYMENT_IPN_SECRET": "ipn-secret",
}
os.environ.update(hosted_env)
try:
    H.boot(DB, workers=1)
    st, acct = H.call("POST", "/api/v1/account", {"months": 12})
    check("invoice opened via hosted gateway", st == 200, f"{st} {acct}")
    check("checkout url is the gateway's",
          "gateway.test" in acct.get("checkout_url", ""), acct)
    st, methods = H.call("GET", f"/api/v1/payment/{acct['invoice_id']}/methods")
    curs = {m["currency"] for m in methods.get("methods", [])}
    check("BTC / XMR / ZEC all offered", {"BTC", "XMR", "ZEC"} <= curs, curs)

    st, before = H.call("GET", "/api/v1/account/status",
                        headers={"X-Account-Token": acct["token"]})
    check("unpaid before IPN", before["status"] == "pending_payment", before)

    bad = json.dumps({"invoice_id": acct["invoice_id"],
                      "payment_status": "finished"}).encode()
    st, _ = H.call("POST", "/api/v1/payment/webhook",
                   json.loads(bad), headers={"x-nowpayments-sig": "00" * 64})
    check("forged IPN signature refused", st == 401, st)
    s = H.call("GET", "/api/v1/account/status",
               headers={"X-Account-Token": acct["token"]})[1]
    check("forged IPN did not activate", s["status"] == "pending_payment", s)

    code, _ = fake_gateway.ipn(acct["invoice_id"], "finished")
    check("signed IPN accepted", code == 200, code)
    s = H.call("GET", "/api/v1/account/status",
               headers={"X-Account-Token": acct["token"]})[1]
    check("account active after IPN", s["status"] == "active", s)
    check("12 months credited", s["days_remaining"] >= 359, s["days_remaining"])
    hosted_expires = s["expires_at"]

    for _ in range(3):
        fake_gateway.ipn(acct["invoice_id"], "finished")
    s2 = H.call("GET", "/api/v1/account/status",
                headers={"X-Account-Token": acct["token"]})[1]
    check("hosted IPN replay cannot re-credit",
          s2["expires_at"] == hosted_expires,
          f"expiry moved: {hosted_expires} -> {s2['expires_at']}")

    st, acct2 = H.call("POST", "/api/v1/account", {"months": 1})
    fake_gateway.ipn(acct2["invoice_id"], "expired")
    s3 = H.call("GET", "/api/v1/account/status",
                headers={"X-Account-Token": acct2["token"]})[1]
    check("expiry event does not activate", s3["status"] == "pending_payment", s3)
    st, ps = H.call("GET", f"/api/v1/payment/{acct2['invoice_id']}/status")
    check("polling reports the expiry", ps.get("status") == "expired", ps)
finally:
    H.shutdown()
    if gw.poll() is None:
        gw.terminate()
        try: gw.wait(timeout=5)
        except Exception: gw.kill()

# ---------------------------------------------------------------------------
# Card rails. A different product from the coins above: a real identity behind
# every payment, and a processor that can reverse one months later. Tested to
# the same standard — signature forgery, replay, and failure must all behave.
# ---------------------------------------------------------------------------
CARD_PORT = H.pick_port()
import fake_cards
cards = subprocess.Popen(
    [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "fake_cards.py"), str(CARD_PORT)],
    env={**os.environ, "CONTROL_URL": H.API,
         "STRIPE_WEBHOOK_SECRET": "whsec_test", "SQUARE_WEBHOOK_KEY": "sq_wh_test",
         "SQUARE_NOTIFICATION_URL": H.API + "/api/v1/payment/webhook"},
    stdout=open(f"{TMP}/cards.log", "w"), stderr=subprocess.STDOUT)
H.free_port_wait(CARD_PORT)
fake_cards.CONTROL = H.API
fake_cards.NOTIFY = H.API + "/api/v1/payment/webhook"

print("\n=== provider: Stripe (cards) ===")
STRIPE_ENV = {
    "ZTV_PAYMENT_PROVIDER": "stripe",
    "STRIPE_API_BASE": f"http://127.0.0.1:{CARD_PORT}/v1",
    "STRIPE_SECRET_KEY": "sk_test_key",
    "STRIPE_WEBHOOK_SECRET": "whsec_test",
    "STRIPE_SUCCESS_URL": "https://0trustvpn.com/welcome",
}
try:
    H.boot(DB, workers=1, env_extra=STRIPE_ENV)
    st, acct = H.call("POST", "/api/v1/account", {"months": 3})
    check("Stripe checkout session created", st == 200, f"{st} {acct}")
    check("customer is sent to Stripe's hosted page",
          "checkout.stripe.test" in (acct.get("checkout_url") or ""), acct)
    sid = acct["invoice_id"]

    st, before = H.call("GET", "/api/v1/account/status",
                        headers={"X-Account-Token": acct["token"]})
    check("unpaid before the webhook", before["status"] == "pending_payment", before)

    code, _ = fake_cards.stripe_webhook(sid, secret="whsec_WRONG")
    check("a webhook signed with the wrong secret is refused", code == 401, code)
    code, _ = fake_cards.stripe_webhook(sid, skew=-3600)
    check("a captured webhook replayed an hour later is refused", code == 401, code)

    code, _ = fake_cards.stripe_webhook(sid)
    check("a correctly signed webhook is accepted", code == 200, code)
    s = H.call("GET", "/api/v1/account/status",
               headers={"X-Account-Token": acct["token"]})[1]
    check("the card payment credits the account", s["status"] == "active", s)
    card_expires = s["expires_at"]
    check("3 months credited", s["days_remaining"] >= 89, s["days_remaining"])

    for _ in range(3):
        fake_cards.stripe_webhook(sid)
    s2 = H.call("GET", "/api/v1/account/status",
                headers={"X-Account-Token": acct["token"]})[1]
    check("replaying a Stripe webhook cannot re-credit",
          s2["expires_at"] == card_expires,
          f"expiry moved: {card_expires} -> {s2['expires_at']}")

    st, methods = H.call("GET", f"/api/v1/payment/{sid}/methods")
    check("a card provider offers no crypto addresses",
          methods.get("methods") == [], methods)
    check("but still hands over the checkout link",
          "checkout.stripe.test" in (methods.get("checkout_url") or ""), methods)
finally:
    H.shutdown()

print("\n=== provider: Square (cards) ===")
SQUARE_ENV = {
    "ZTV_PAYMENT_PROVIDER": "square",
    "SQUARE_API_BASE": f"http://127.0.0.1:{CARD_PORT}",
    "SQUARE_ACCESS_TOKEN": "sq_test_token",
    "SQUARE_LOCATION_ID": "L1",
    "SQUARE_WEBHOOK_KEY": "sq_wh_test",
    "SQUARE_ENV": "sandbox",
    "SQUARE_NOTIFICATION_URL": H.API + "/api/v1/payment/webhook",
}
try:
    H.boot(DB, workers=1, env_extra=SQUARE_ENV)
    st, acct2 = H.call("POST", "/api/v1/account", {"months": 1})
    check("Square payment link created", st == 200, f"{st} {acct2}")
    check("customer is sent to Square's hosted page",
          "square.test" in (acct2.get("checkout_url") or ""), acct2)
    lid = acct2["invoice_id"]

    code, _ = fake_cards.square_webhook(lid, secret="wrong-key")
    check("a Square webhook with a bad signature is refused", code == 401, code)
    code, _ = fake_cards.square_webhook(lid, url="https://evil.test/hook")
    check("a Square webhook signed for a different URL is refused", code == 401, code)

    code, _ = fake_cards.square_webhook(lid)
    check("a correctly signed Square webhook is accepted", code == 200, code)
    s = H.call("GET", "/api/v1/account/status",
               headers={"X-Account-Token": acct2["token"]})[1]
    check("the Square payment credits the account", s["status"] == "active", s)
    card_expires2 = s["expires_at"]
    for _ in range(3):
        fake_cards.square_webhook(lid)
    s2 = H.call("GET", "/api/v1/account/status",
                headers={"X-Account-Token": acct2["token"]})[1]
    check("replaying a Square webhook cannot re-credit",
          s2["expires_at"] == card_expires2,
          f"expiry moved: {card_expires2} -> {s2['expires_at']}")

    st, acct3 = H.call("POST", "/api/v1/account", {"months": 1})
    fake_cards.square_webhook(acct3["invoice_id"], status="FAILED")
    s3 = H.call("GET", "/api/v1/account/status",
                headers={"X-Account-Token": acct3["token"]})[1]
    check("a failed card payment does not activate",
          s3["status"] == "pending_payment", s3)
finally:
    H.shutdown()
    if cards.poll() is None:
        cards.terminate()
        try: cards.wait(timeout=5)
        except Exception: cards.kill()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
