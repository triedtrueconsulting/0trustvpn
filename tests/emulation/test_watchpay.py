#!/usr/bin/env python3
"""
Taking Bitcoin with no merchant account, end to end.

The watch-only provider is the only payment path that works on a VPS built
this morning: no BTCPay to run, no gateway to sign up with, no callback URL to
register. The operator pastes the public half of their wallet and paid signup
works. This drives the whole of it — signup, a derived address, a payment
appearing on a (fake) explorer, the poller crediting the account — against the
real control plane.
"""
import os, shutil, sqlite3, subprocess, sys, tempfile, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H
import fake_explorer

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

EXPLORER_PORT = H.pick_port()
TMP = tempfile.mkdtemp(prefix="0trust-watch-")
DB = os.path.join(TMP, "0trust.db")

# The BIP84 spec's own account key, so the addresses below are ones anybody
# can verify independently.
ZPUB = None

from http.server import ThreadingHTTPServer
srv = ThreadingHTTPServer(("127.0.0.1", EXPLORER_PORT), fake_explorer.H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

sys.path.insert(0, os.path.join(H.REPO, "api"))
import chainwatch as cw

# Derive the account zpub the same way test_chainwatch does.
import hashlib, hmac
seed = hashlib.pbkdf2_hmac("sha512",
                           (" ".join(["abandon"] * 11 + ["about"])).encode(),
                           b"mnemonic", 2048)
_I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
_k, _c = int.from_bytes(_I[:32], "big"), _I[32:]
def _ckd(k, c, index):
    data = (b"\x00" + k.to_bytes(32, "big") + index.to_bytes(4, "big")
            if index >= 0x80000000
            else cw._serialize(cw._point_mul(k)) + index.to_bytes(4, "big"))
    I = hmac.new(c, data, hashlib.sha512).digest()
    return (int.from_bytes(I[:32], "big") + k) % cw.N, I[32:]
for _idx in (84 + 0x80000000, 0x80000000, 0x80000000):
    _k, _c = _ckd(_k, _c, _idx)
_body = ((0x04B24746).to_bytes(4, "big") + bytes([3]) + b"\x00\x00\x00\x00"
         + (0x80000000).to_bytes(4, "big") + _c + cw._serialize(cw._point_mul(_k)))
_chk = hashlib.sha256(hashlib.sha256(_body).digest()).digest()[:4]
_n, ZPUB = int.from_bytes(_body + _chk, "big"), ""
while _n:
    _n, _r = divmod(_n, 58)
    ZPUB = cw._B58[_r] + ZPUB

WATCH_ENV = {
    "ZTV_PAYMENT_PROVIDER": "watch",
    "WALLET_BTC": ZPUB,
    "NODE_RPC_BTC": f"http://127.0.0.1:{EXPLORER_PORT}",
    "ZTV_BTC_CONFIRMATIONS": "1",
}
os.environ.update(WATCH_ENV)
os.environ["ZTV_DB_PATH"] = DB
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=2, env_extra=WATCH_ENV)


def sql(q, *a):
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    rows = c.execute(q, a).fetchall(); c.commit(); c.close()
    return rows


def run_poller():
    return subprocess.run(
        [sys.executable, os.path.join(H.REPO, "api", "poll_invoices.py")],
        capture_output=True, text=True,
        env={**os.environ, **WATCH_ENV, "ZTV_DB_PATH": DB})


try:
    print("[1] signup derives a fresh address from the operator's own wallet")
    st, acct = H.call("POST", "/api/v1/account", {"months": 1})
    check("signup succeeds with no merchant account anywhere",
          st == 200, f"{st} {acct}")
    token, inv_id = acct["token"], acct["invoice_id"]
    row = sql("SELECT * FROM invoices WHERE id = ?", inv_id)[0]
    addr = row["payment_address"]
    check("an address was derived and stored", bool(addr), dict(row))
    # Verifiable against the BIP84 spec by anyone reading the test.
    check("it is the first address of the spec's account key",
          addr == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", addr)
    check("the amount was priced from the explorer's ticker",
          float(row["amount_crypto"]) > 0, dict(row))
    check("index 0 was reserved", row["derivation_index"] == 0, dict(row))

    print("\n[2] the checkout page gets an address and a payable URI")
    st, methods = H.call("GET", f"/api/v1/payment/{inv_id}/methods")
    check("methods returns the address", st == 200
          and methods["methods"][0]["address"] == addr, methods)
    check("and a bitcoin: URI a wallet can scan",
          methods["methods"][0]["uri"].startswith(f"bitcoin:{addr}?amount="),
          methods)
    check("BTC only — nothing we cannot derive is advertised",
          [m["currency"] for m in methods["methods"]] == ["BTC"], methods)

    print("\n[3] a second signup must not reuse the address")
    st, acct2 = H.call("POST", "/api/v1/account", {"months": 3})
    row2 = sql("SELECT * FROM invoices WHERE id = ?", acct2["invoice_id"])[0]
    # Two customers sharing an address makes two payments of the same amount
    # impossible to tell apart, and publishes the whole payment history.
    check("the second invoice got a different address",
          row2["payment_address"] != addr, (addr, row2["payment_address"]))
    check("and the next index", row2["derivation_index"] == 1, dict(row2))

    print("\n[4] unpaid stays unpaid")
    r = run_poller()
    check("poller runs clean", r.returncode == 0, (r.stderr or r.stdout)[-400:])
    check("nothing was credited",
          sql("SELECT status FROM invoices WHERE id = ?", inv_id)[0]["status"]
          == "pending")
    st, s1 = H.call("GET", "/api/v1/account/status",
                    headers={"X-Account-Token": token})
    check("the account is still pending payment",
          s1["status"] == "pending_payment", s1)

    print("\n[5] underpayment does not buy a month")
    sats = int(round(float(row["amount_crypto"]) * 100_000_000))
    fake_explorer.pay(addr, sats // 2)
    run_poller()
    check("half the price credits nothing",
          sql("SELECT status FROM invoices WHERE id = ?", inv_id)[0]["status"]
          == "pending")

    print("\n[6] payment confirms and the account activates")
    fake_explorer.pay(addr, sats - sats // 2)      # top up to the full amount
    r = run_poller()
    check("poller settles it", r.returncode == 0, (r.stderr or r.stdout)[-400:])
    inv_after = sql("SELECT status, settled_at FROM invoices WHERE id = ?",
                    inv_id)[0]
    check("invoice is settled", inv_after["status"] == "settled", dict(inv_after))
    st, s2 = H.call("GET", "/api/v1/account/status",
                    headers={"X-Account-Token": token})
    check("account is active", s2["status"] == "active", s2)
    check("a month was credited", 28 <= s2["days_remaining"] <= 31, s2)

    print("\n[7] the poller cannot be made to credit twice")
    before = sql("SELECT expires_at FROM accounts WHERE id = ?",
                 sql("SELECT account_id FROM invoices WHERE id = ?",
                     inv_id)[0]["account_id"])[0]["expires_at"]
    for _ in range(3):
        run_poller()
    after = sql("SELECT expires_at FROM accounts WHERE id = ?",
                sql("SELECT account_id FROM invoices WHERE id = ?",
                    inv_id)[0]["account_id"])[0]["expires_at"]
    # The money is still sitting at that address; nothing stops the poller
    # seeing it again. Only the conditional UPDATE does.
    check("re-running the poller does not extend the account again",
          after == before, (before, after))

    print("\n[8] there is no webhook to forge")
    # Under this provider nobody sends us anything, so a POST to the webhook
    # endpoint is either a mistake or an attempt.
    st, resp = H.call("POST", "/api/v1/payment/webhook", {"invoice_id": inv_id})
    check("an unsigned webhook is refused", st in (400, 401, 403), f"{st} {resp}")

    print("\n[9] an explorer outage is reported, not silently swallowed")
    st, acct3 = H.call("POST", "/api/v1/account", {"months": 1})
    fake_explorer.DOWN[0] = True
    r = run_poller()
    fake_explorer.DOWN[0] = False
    check("the poller survives the outage", r.returncode == 0,
          (r.stderr or r.stdout)[-300:])
    kinds = [e["kind"] for e in sql("SELECT kind FROM ops_events")]
    # Silence here looks exactly like "no customers are paying", which is the
    # most expensive thing for an operator not to be told.
    check("the operator is told payments are not being credited",
          "payments.explorer_down" in kinds, kinds)

    print("\n[10] health reflects reality")
    st, h = H.call("GET", "/api/v1/health")
    check("api is healthy", st == 200, h)
    import payments as pay
    pay.reset_provider()
    ok, msg = pay.provider().health()
    check("watch provider reports healthy with a wallet set", ok, msg)
    check("and says which explorer it is trusting",
          str(EXPLORER_PORT) in msg, msg)
    pay._instance = None
    os.environ["WALLET_BTC"] = ""
    ok2, msg2 = pay.WatchOnlyProvider().health()
    check("and unhealthy with no wallet", not ok2 and "WALLET_BTC" in msg2, msg2)
    os.environ["WALLET_BTC"] = ZPUB

finally:
    H.shutdown()
    srv.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
