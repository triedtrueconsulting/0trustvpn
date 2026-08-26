#!/usr/bin/env python3
"""
Taking BTC, ZEC and XMR with no merchant account, end to end.

The watch-only provider is the only payment path that works on a VPS built
this morning: no BTCPay to run, no gateway to sign up with, no callback URL to
register. This drives the whole of it — signup, an address, a payment
appearing on a (fake) backend, the poller crediting the account — against the
real control plane.

The three coins do not work the same way, and the test has to reflect that or
it is testing a fiction:

  BTC, ZEC  a fresh address derived from the operator's extended PUBLIC key,
            and a public explorer asked whether it was paid. Two explorer
            shapes: Esplora and Blockchair.
  XMR       no derivation and no explorer, because Monero publishes neither
            recipient nor amount. A view-only monero-wallet-rpc allocates a
            subaddress and answers for it.
"""
import os, shutil, sqlite3, subprocess, sys, threading, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H
import fake_explorer, fake_walletrpc

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

EXPLORER_PORT = H.pick_port()
WALLET_PORT = H.pick_port()
TMP = H.tempdir("0trust-watch-")
DB = os.path.join(TMP, "0trust.db")

from http.server import ThreadingHTTPServer
srv = ThreadingHTTPServer(("127.0.0.1", EXPLORER_PORT), fake_explorer.H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
wsrv = ThreadingHTTPServer(("127.0.0.1", WALLET_PORT), fake_walletrpc.H)
threading.Thread(target=wsrv.serve_forever, daemon=True).start()

sys.path.insert(0, os.path.join(H.REPO, "api"))
import chainwatch as cw
import monerowatch as mw

# The BIP84 spec's own account key, derived rather than pasted, so every
# address below is one anybody can verify against the spec.
ZPUB = H.account_zpub_from_mnemonic(" ".join(["abandon"] * 11 + ["about"]))
# A second, unrelated account for Zcash: sharing one key across two chains
# would work, but it is not what an operator does and it would hide any
# coin/key mix-up.
ZPUB_ZEC = H.account_zpub_from_mnemonic(
    " ".join(["abandon"] * 11 + ["about"]), account=1)

EXPLORER = f"http://127.0.0.1:{EXPLORER_PORT}"
WATCH_ENV = {
    "ZTV_PAYMENT_PROVIDER": "watch",
    "WALLET_BTC": ZPUB,
    "WALLET_ZEC": ZPUB_ZEC,
    "NODE_RPC_BTC": EXPLORER,
    # Deliberately the Blockchair shape, so the second reader is exercised.
    "NODE_RPC_ZEC": EXPLORER + "/blockchair",
    "ZTV_PRICE_API": EXPLORER + "/0/public/Ticker",
    "MONERO_WALLET_RPC": f"http://127.0.0.1:{WALLET_PORT}/json_rpc",
    "ZTV_BTC_CONFIRMATIONS": "1",
    "ZTV_ZEC_CONFIRMATIONS": "1",
    "XMR_CONFIRMATIONS": "10",
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


def invoice(inv_id):
    return sql("SELECT * FROM invoices WHERE id = ?", inv_id)[0]


def status_of(inv_id):
    return invoice(inv_id)["status"]


try:
    print("[1] the deployment offers exactly what it has a wallet for")
    st, cfg = H.call("GET", "/api/v1/config")
    check("config lists all three", st == 200
          and set(cfg["currencies"]) == {"BTC", "ZEC", "XMR"}, cfg)

    print("\n[2] BTC: a fresh address from the operator's own wallet")
    st, acct = H.call("POST", "/api/v1/account", {"months": 1})
    check("signup succeeds with no merchant account anywhere",
          st == 200, f"{st} {acct}")
    token, inv_id = acct["token"], acct["invoice_id"]
    row = invoice(inv_id)
    addr = row["payment_address"]
    check("it is the first address of the spec's account key",
          addr == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", addr)
    check("stored as a BTC invoice", row["pay_currency"] == "BTC", dict(row))
    check("priced from the ticker", float(row["amount_crypto"]) > 0, dict(row))
    check("index 0 was reserved", row["derivation_index"] == 0, dict(row))

    st, methods = H.call("GET", f"/api/v1/payment/{inv_id}/methods")
    check("checkout offers a bitcoin: URI",
          methods["methods"][0]["uri"].startswith(f"bitcoin:{addr}?amount="),
          methods)

    print("\n[3] BTC: underpayment buys nothing, full payment buys a month")
    sats = int(round(float(row["amount_crypto"]) * 100_000_000))
    fake_explorer.pay(addr, sats // 2)
    run_poller()
    check("half the price credits nothing", status_of(inv_id) == "pending")
    fake_explorer.pay(addr, sats - sats // 2)
    r = run_poller()
    check("poller runs clean", r.returncode == 0, (r.stderr or r.stdout)[-300:])
    check("the full amount settles it", status_of(inv_id) == "settled")
    st, s = H.call("GET", "/api/v1/account/status",
                   headers={"X-Account-Token": token})
    check("and the account is active", s["status"] == "active", s)
    before = s["expires_at"]
    run_poller()
    st, s2 = H.call("GET", "/api/v1/account/status",
                    headers={"X-Account-Token": token})
    check("a second poll does not credit twice", s2["expires_at"] == before,
          (before, s2["expires_at"]))

    print("\n[4] ZEC: a transparent address, read through Blockchair")
    st, zacct = H.call("POST", "/api/v1/account",
                       {"months": 1, "currency": "ZEC"})
    check("signup in ZEC succeeds", st == 200, f"{st} {zacct}")
    zrow = invoice(zacct["invoice_id"])
    zaddr = zrow["payment_address"]
    check("stored as a ZEC invoice", zrow["pay_currency"] == "ZEC", dict(zrow))
    check("the address is a transparent t1 address",
          zaddr.startswith("t1") and len(zaddr) == 35, zaddr)
    check("derived from the ZEC wallet, not the BTC one",
          zaddr == cw.receive_address(ZPUB_ZEC, 0, coin="ZEC"), zaddr)
    check("ZEC has its own index counter, starting at 0",
          zrow["derivation_index"] == 0, dict(zrow))
    st, zm = H.call("GET", f"/api/v1/payment/{zacct['invoice_id']}/methods")
    check("checkout offers a zcash: URI",
          zm["methods"][0]["uri"].startswith(f"zcash:{zaddr}?amount="), zm)

    zats = int(round(float(zrow["amount_crypto"]) * 100_000_000))
    fake_explorer.pay(zaddr, zats - 1)
    run_poller()
    check("one zatoshi short does not settle",
          status_of(zacct["invoice_id"]) == "pending")
    fake_explorer.pay(zaddr, 1)
    run_poller()
    check("paid in full settles", status_of(zacct["invoice_id"]) == "settled")

    print("\n[5] XMR: a subaddress from the wallet, not a derivation")
    st, macct = H.call("POST", "/api/v1/account",
                       {"months": 1, "currency": "XMR"})
    check("signup in XMR succeeds", st == 200, f"{st} {macct}")
    mrow = invoice(macct["invoice_id"])
    check("stored as an XMR invoice", mrow["pay_currency"] == "XMR", dict(mrow))
    check("the wallet's subaddress was stored",
          (mrow["payment_address"] or "").startswith("8")
          and len(mrow["payment_address"]) == 95, mrow["payment_address"])
    midx = mrow["derivation_index"]
    check("and the wallet's own index, not one we chose",
          isinstance(midx, int) and midx >= 1,
          f"{midx} — index 0 is the primary address, never a subaddress")
    st, mm = H.call("GET", f"/api/v1/payment/{macct['invoice_id']}/methods")
    check("checkout offers a monero: URI with tx_amount",
          mm["methods"][0]["uri"].startswith("monero:")
          and "tx_amount=" in mm["methods"][0]["uri"], mm)

    print("\n[6] XMR: the units are piconero, and shallow blocks do not count")
    atomic = int(round(float(mrow["amount_crypto"]) * mw.ATOMIC))
    check("the invoice is priced in whole XMR, not satoshis",
          atomic > 10 ** 9,
          f"{atomic} atomic units — a satoshi-scaled amount would be tiny")
    # The bug this pins: the poller multiplied every amount by 1e8. Against a
    # 1e12 coin that makes a dust payment look like the full price.
    fake_walletrpc.pay(midx, int(round(float(mrow["amount_crypto"]) * 100_000_000)),
                       confirmations=99)
    run_poller()
    check("a payment 10,000x too small does NOT settle it",
          status_of(macct["invoice_id"]) == "pending",
          "the poller is treating XMR as an 8-decimal coin")
    fake_walletrpc.pay(midx, atomic, confirmations=3)
    run_poller()
    check("nor does the right amount with too few confirmations",
          status_of(macct["invoice_id"]) == "pending")
    fake_walletrpc.pay(midx, atomic, confirmations=11)
    run_poller()
    check("the right amount, deep enough, settles",
          status_of(macct["invoice_id"]) == "settled")

    print("\n[7] each coin's money stays its own")
    rows = sql("SELECT pay_currency, payment_address, derivation_index "
               "FROM invoices ORDER BY created_at")
    addrs = [r["payment_address"] for r in rows]
    check("no two invoices share an address", len(addrs) == len(set(addrs)),
          addrs)
    check("every invoice records which coin it is in",
          all(r["pay_currency"] in ("BTC", "ZEC", "XMR") for r in rows),
          [dict(r) for r in rows])

    print("\n[8] a coin this deployment cannot take is refused, not faked")
    st, err = H.call("POST", "/api/v1/account", {"months": 1, "currency": "DOGE"})
    check("an unsupported coin is a 400, not a 502", st == 400, (st, err))
    check("and the error says what IS taken",
          "BTC" in str(err) and "XMR" in str(err), err)

    print("\n[9] when a backend is down, nobody gets a free month")
    st, acct3 = H.call("POST", "/api/v1/account", {"months": 1})
    inv3 = acct3["invoice_id"]
    fake_explorer.DOWN[0] = True
    r = run_poller()
    check("the poller survives an explorer outage", r.returncode == 0,
          (r.stderr or r.stdout)[-300:])
    check("and credits nothing", status_of(inv3) == "pending")
    fake_explorer.DOWN[0] = False

    fake_walletrpc.DOWN[0] = True
    st, mm2 = H.call("POST", "/api/v1/account", {"months": 1, "currency": "XMR"})
    check("signup in XMR fails cleanly when the wallet is down",
          st in (400, 502), (st, mm2))
    fake_walletrpc.DOWN[0] = False

    fake_explorer.PRICE_DOWN[0] = True
    st, pm = H.call("POST", "/api/v1/account", {"months": 1})
    check("signup fails when the price feed is down, rather than guessing",
          st == 502, (st, pm))
    n_before = len(sql("SELECT id FROM accounts"))
    fake_explorer.PRICE_DOWN[0] = False
    check("and the half-made account was rolled back",
          len(sql("SELECT id FROM accounts")) == n_before,
          "a pending_payment row with no invoice is unreachable forever")

    print("\n[10] health reports every configured coin")
    st, health = H.call("GET", "/api/v1/admin/payments/health")
    # Unauthenticated; just confirm the provider's own health string covers
    # all three, via the module rather than the guarded endpoint.
    import payments as pay
    pay.reset_provider()
    ok, detail = pay.provider().health()
    check("health is ok with all three configured", ok, detail)
    for coin in ("BTC", "ZEC", "XMR"):
        check(f"health mentions {coin}", coin in detail, detail)

    print("\n[11] the Monero setup script refuses the mistake that costs money")
    SETUP = os.path.join(H.REPO, "scripts", "setup-monero-watch.sh")
    check("setup-monero-watch.sh is executable", os.access(SETUP, os.X_OK))
    hexkey = "a" * 64
    addr4 = "4" + "A" * 94

    def setup(*args, stdin=""):
        return subprocess.run(["bash", SETUP, *args], input=stdin,
                              capture_output=True, text=True, timeout=120)

    r = setup("--address", "notanaddress", "--view-key", hexkey)
    check("a malformed address is refused", r.returncode != 0,
          (r.stdout + r.stderr)[-200:])
    r = setup("--address", addr4, "--view-key", "nope")
    check("a malformed view key is refused", r.returncode != 0,
          (r.stdout + r.stderr)[-200:])

    # A spend key is also 64 hex characters, so nothing can tell them apart by
    # shape. The only defence is making the operator say which one it is, and
    # a script that proceeds on silence has no defence at all.
    r = setup("--address", addr4, "--view-key", hexkey, stdin="\n")
    check("it will not proceed without the typed confirmation",
          r.returncode != 0, (r.stdout + r.stderr)[-200:])
    r = setup("--address", addr4, "--view-key", hexkey, stdin="yes\n")
    check("and 'yes' is not the confirmation either", r.returncode != 0,
          "anything but the exact word would let a reflexive y through")
    r = setup("--dry-run", "--restore-height", "3100000", "--address", addr4,
              "--view-key", hexkey, stdin="view\n")
    check("a confirmed dry run renders the plan", r.returncode == 0,
          (r.stdout + r.stderr)[-300:])
    check("and it says the wallet is view-only",
          "view-only" in r.stdout, r.stdout[-200:])

    src = open(SETUP).read()
    check("the script warns that a spend key looks identical",
          "spend key looks identical" in src or "A spend key looks identical" in src,
          "the one mistake here loses money rather than breaking a feature")
    check("and binds wallet-rpc to loopback only",
          "--rpc-bind-ip 127.0.0.1" in src,
          "a wallet-rpc on a public interface with --disable-rpc-login is an "
          "open door to the wallet")

finally:
    srv.shutdown(); wsrv.shutdown(); H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
