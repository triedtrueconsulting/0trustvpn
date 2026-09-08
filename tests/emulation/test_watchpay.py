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
import os, re, shutil, sqlite3, subprocess, sys, threading, time

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

    print("\n[6b] the checkout page is told the truth about the same money")
    # /payment/{id}/status is what the customer watches while they wait. It
    # had its own copy of the settlement arithmetic with 1e8 hardcoded and no
    # coin passed, so an XMR invoice was compared against a figure 10,000x
    # out and a non-BTC address was looked up on Bitcoin's explorer. It is
    # read-only and never credited anything — it simply told the customer
    # something false about their own payment.
    # A settled invoice short-circuits (correctly), so this needs a live one.
    st, pend = H.call("POST", "/api/v1/account", {"months": 1, "currency": "XMR"})
    check("a second XMR signup for the live-status check", st == 200, pend)
    prow = sql("SELECT * FROM invoices WHERE id = ?", pend["invoice_id"])[0]
    p_atomic = int(round(float(prow["amount_crypto"]) * mw.ATOMIC))
    p_idx = int(prow["derivation_index"])
    # Pay it deep enough to be confirmed, but do NOT run the poller: the row
    # stays 'pending', so the endpoint cannot short-circuit on stored state
    # and has to do the arithmetic and the chain lookup itself.
    fake_walletrpc.pay(p_idx, p_atomic, confirmations=11)

    st, live = H.call("GET", f"/api/v1/payment/{pend['invoice_id']}/status")
    check("status endpoint answers for a pending XMR invoice", st == 200, live)
    check("and prices it in piconero, like the poller does",
          live.get("expected_sats", 0) == p_atomic,
          f"expected_sats={live.get('expected_sats')} atomic={p_atomic} "
          f"(1e8 instead of 1e12 is 10,000x out)")
    check("and reads the amount off the right chain",
          live.get("confirmed_sats", 0) > 0,
          f"confirmed={live.get('confirmed_sats')} — looking an XMR "
          f"subaddress up on Bitcoin's explorer reports 0")

    # And a pending BTC invoice must still be counted in satoshis.
    st, bpend = H.call("POST", "/api/v1/account", {"months": 1, "currency": "BTC"})
    brow = sql("SELECT * FROM invoices WHERE id = ?", bpend["invoice_id"])[0]
    st, blive = H.call("GET", f"/api/v1/payment/{bpend['invoice_id']}/status")
    check("a BTC invoice is still priced in satoshis",
          blive.get("expected_sats", 0)
          == int(round(float(brow["amount_crypto"]) * 100_000_000)),
          f"{blive.get('expected_sats')} vs "
          f"{int(round(float(brow['amount_crypto']) * 100_000_000))}")

    print("\n[6c] an underpayment is reported, not swallowed")
    # A customer short by a little — fee estimation, exchange rounding, a
    # wallet that takes its fee out of the amount sent — has put real coin
    # into an address the operator controls. Nothing credited them, and the
    # checkout page showed no change at all until the invoice expired and
    # told them to start over. The API computed the shortfall the whole time
    # and no page read it.
    st, u = H.call("POST", "/api/v1/account", {"months": 1, "currency": "BTC"})
    urow = sql("SELECT * FROM invoices WHERE id = ?", u["invoice_id"])[0]
    u_atomic = int(round(float(urow["amount_crypto"]) * 100_000_000))
    fake_explorer.pay(urow["payment_address"], u_atomic - 500)

    st, ust = H.call("GET", f"/api/v1/payment/{u['invoice_id']}/status")
    check("status answers for an underpaid invoice", st == 200, ust)
    check("it is flagged as underpaid", ust.get("underpaid") is True, ust)
    check("and the shortfall is named exactly",
          ust.get("short_by") == "0.000005", ust.get("short_by"))
    check("with the amounts in the invoice's own currency",
          ust.get("currency") == "BTC"
          and ust.get("expected_amount") not in (None, "", "0"), ust)
    check("and it is NOT settled", ust.get("status") != "settled", ust)

    run_poller()
    check("the poller does not credit an underpayment",
          status_of(u["invoice_id"]) == "pending", status_of(u["invoice_id"]))

    # Paying the rest to the SAME address finishes the job — the balance
    # accumulates, exactly as a real address does.
    fake_explorer.pay(urow["payment_address"], 500)
    run_poller()
    check("topping the same address up to the full amount settles it",
          status_of(u["invoice_id"]) == "settled", status_of(u["invoice_id"]))

    # And the page actually renders it.
    page = open(os.path.join(H.REPO, "web", "index.html")).read()
    check("the checkout page reads the underpaid flag", "data.underpaid" in page)
    check("and names the remainder", "short_by" in page)
    check("and tells a waiting customer not to pay twice",
          "Do not send again" in page)

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

    print("\n[9b] one coin's backend failing is not hidden by another working")
    # The alert fired only when the WHOLE batch failed, so a healthy Bitcoin
    # explorer masked a broken Monero wallet indefinitely: XMR invoices stopped
    # crediting and the dashboard said nothing, which reads exactly like
    # "nobody pays in Monero".
    sql("DELETE FROM ops_events")
    st, btc_pending = H.call("POST", "/api/v1/account", {"months": 1})
    st, xmr_pending = H.call("POST", "/api/v1/account",
                             {"months": 1, "currency": "XMR"})
    check("both invoices are open", btc_pending.get("invoice_id")
          and xmr_pending.get("invoice_id"), (btc_pending, xmr_pending))

    fake_walletrpc.DOWN[0] = True          # Monero down, explorer still up
    r = run_poller()
    fake_walletrpc.DOWN[0] = False
    check("the poller survives one backend being down", r.returncode == 0,
          (r.stderr or r.stdout)[-300:])

    events = sql("SELECT kind, subject, detail FROM ops_events "
                 "WHERE kind LIKE 'payments.%'")
    downs = {e["subject"] for e in events if e["kind"] == "payments.explorer_down"}
    check("the failing coin raises an alert naming itself", "XMR" in downs,
          f"events: {[dict(e) for e in events]}")
    check("and the working coin does not", "BTC" not in downs,
          f"events: {[dict(e) for e in events]}")

    # Recovery is its own edge, or a fixed outage stays red forever.
    run_poller()
    events = sql("SELECT kind, subject FROM ops_events WHERE kind LIKE 'payments.%'")
    check("recovery is recorded once the backend answers again",
          any(e["kind"] == "payments.explorer_ok" and e["subject"] == "XMR"
              for e in events),
          f"events: {[dict(e) for e in events]}")

    # And it does not re-alert every minute while the outage continues.
    fake_walletrpc.DOWN[0] = True
    run_poller(); run_poller()
    fake_walletrpc.DOWN[0] = False
    n_down = len([e for e in sql(
        "SELECT kind, subject FROM ops_events WHERE kind = 'payments.explorer_down'")
        if e["subject"] == "XMR"])
    check("a continuing outage alerts on the transition, not every poll",
          n_down == 2, f"{n_down} down events for XMR across two outages")
    run_poller()

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

    print("\n[11a] an invoice id is a capability, so it has to be unguessable")
    # /api/v1/payment/{id}/methods and /status are deliberately public: the
    # checkout page polls them before the customer holds any credential, and
    # the docstring says the id is "the only secret needed to view it". It was
    # not a secret — the coin, the derivation index (0, 1, 2, … sequential) and
    # the unix second. Open one invoice of your own, learn the index and the
    # clock, and every other customer's receive address, amount owed and
    # amount received was a handful of guesses away. On a product that sells
    # payments not being linkable, that is the link.
    ids = []
    for _ in range(3):
        st, acct = H.call("POST", "/api/v1/account", {"months": 1})
        check("signup for the id check", st == 200, (st, acct))
        ids.append(acct["invoice_id"])

    # split from the LEFT with maxsplit=2: the token is base64url and may
    # itself contain '-', so rsplit would cut inside it.
    for iid in ids:
        coin, idx, token = iid.split("-", 2)
        check(f"the id carries real entropy: {iid[:30]}…",
              len(token) >= 16 and not token.isdigit(),
              f"token {token!r} — a timestamp or a counter is not a secret")
    check("ids are not sequential", len(set(ids)) == 3, ids)

    # The concrete attack: take a real id, decrement the index, keep the rest.
    # It must not resolve to somebody else's invoice.
    victim = ids[-1]
    head, idx, tail = victim.split("-", 2)
    guessed = f"{head}-{max(0, int(idx) - 1)}-{tail}"
    st, body = H.call("GET", f"/api/v1/payment/{guessed}/methods")
    check("walking the index back does not open another invoice",
          st == 404, f"{guessed} -> {st} {body}")

    # And a plausible timestamp-shaped id from the old scheme resolves to
    # nothing at all.
    st, body = H.call("GET", f"/api/v1/payment/btc-0-{int(time.time())}/methods")
    check("an old-format guess resolves to nothing", st == 404, (st, body))

    print("\n[11b] nothing in the default path downloads a blockchain")
    # A standing operator constraint, not a preference: this box has no room
    # for a chain, and every coin must settle against a PUBLIC node somebody
    # else runs. It is easy to lose by accident — one `apt-get install
    # bitcoind` in the installer, or one default URL pointed at localhost.
    inst = open(os.path.join(H.REPO, "scripts", "install.sh")).read()
    # The packages the control plane and the mesh nodes install.
    pkg_blocks = re.findall(r'PACKAGES=\(([^)]*)\)', inst)
    packages = " ".join(pkg_blocks)
    for daemon in ("bitcoind", "bitcoin-core", "monerod", "zcashd", "geth",
                   "electrum"):
        check(f"the installer never installs {daemon}",
              daemon not in packages,
              f"{daemon} in install.sh PACKAGES — that is a chain on this disk")

    import payments as pay_mod
    for coin, url in pay_mod.WatchOnlyProvider.DEFAULT_API.items():
        check(f"the default {coin} explorer is a remote public endpoint",
              url.startswith("https://")
              and "127.0.0.1" not in url and "localhost" not in url, url)
    check("the default price feed is a remote public endpoint",
          pay_mod.PRICE_API.startswith("https://")
          and "127.0.0.1" not in pay_mod.PRICE_API, pay_mod.PRICE_API)

    # Monero is the one that needs a local process, and it must be a WALLET
    # pointed at somebody else's node — never a node of our own.
    setup = open(os.path.join(H.REPO, "scripts", "setup-monero-watch.sh")).read()
    check("the Monero setup runs monero-wallet-rpc, not monerod",
          "monero-wallet-rpc" in setup and not re.search(r'^\s*monerod\b',
                                                        setup, re.M),
          "a monerod here is 150GB of chain on the control plane")
    check("and points it at a remote daemon by default",
          re.search(r'DAEMON="\$\{MONERO_DAEMON:-https?://(?!127\.0\.0\.1|localhost)',
                    setup) is not None,
          "the default --daemon-address must be a public node")

    print("\n[12] confirmation depth is enforced, not merely configured")
    # Everything above runs at one confirmation, which is the one setting for
    # which "mined" and "confirmed" mean the same thing. The SHIPPED default
    # for Zcash is five, and nothing exercised it: ZTV_BTC_CONFIRMATIONS and
    # ZTV_ZEC_CONFIRMATIONS were read, reported by health(), labelled in the
    # dashboard as "confirmations before crediting", and never consulted. A
    # Zcash invoice settled one block deep, and a reorg at that depth is a
    # month sold for nothing. Monero enforced its depth all along, which is
    # what made two coins quietly ignoring it easy to miss.
    #
    # Driven straight at the provider so both explorer readers run for real
    # over HTTP — the depth logic is per-reader, and it is the reader that
    # was wrong.
    import payments as pay_mod

    for label, coin, api, env_conf, depth in (
            ("BTC via Esplora", "BTC", EXPLORER, "ZTV_BTC_CONFIRMATIONS", 3),
            ("ZEC via Blockchair", "ZEC", EXPLORER + "/blockchair",
             "ZTV_ZEC_CONFIRMATIONS", 5)):
        prev = os.environ.get(env_conf)
        os.environ[env_conf] = str(depth)
        try:
            prov = pay_mod.WatchOnlyProvider()
            if coin == "BTC":
                prov.apis["BTC"] = api
            addr = f"probe-{coin.lower()}-depth"
            amount = 250_000

            # In the mempool: seen, never confirmed.
            fake_explorer.pay(addr, amount, confirmed=False)
            r = prov.check(addr, amount, coin=coin)
            check(f"{label}: a mempool payment does not settle",
                  r["status"] == pay_mod.PENDING, r)
            check(f"{label}: but it is reported as seen",
                  r["seen"] is True, r)
            check(f"{label}: and it says how deep it must go",
                  r["confirmations_required"] == depth, r)
            fake_explorer.reset()

            # Mined, but only one block deep.
            fake_explorer.pay(addr, amount, depth=1)
            r = prov.check(addr, amount, coin=coin)
            check(f"{label}: one block deep does not settle when {depth} are required",
                  r["status"] == pay_mod.PENDING,
                  f"credited at 1 confirmation with {depth} configured: {r}")
            check(f"{label}: the shallow payment counts as pending, not confirmed",
                  r["confirmed_sats"] == 0 and r["unconfirmed_sats"] == amount, r)

            # One short of the requirement.
            fake_explorer.mine(depth - 2)
            r = prov.check(addr, amount, coin=coin)
            check(f"{label}: {depth - 1} deep is still not enough",
                  r["status"] == pay_mod.PENDING, r)

            # And exactly deep enough.
            fake_explorer.mine(1)
            r = prov.check(addr, amount, coin=coin)
            check(f"{label}: {depth} deep settles",
                  r["status"] == pay_mod.SETTLED,
                  f"buried {depth} blocks and still not credited: {r}")
            check(f"{label}: the full amount is counted as confirmed",
                  r["confirmed_sats"] == amount, r)
            fake_explorer.reset()
        finally:
            if prev is None:
                os.environ.pop(env_conf, None)
            else:
                os.environ[env_conf] = prev

    # A swept address must not read as unpaid. Blockchair reports heights on
    # the UTXO set, and an operator moving the coin out while the invoice is
    # still open empties it — the money arrived, and the sweep itself proves
    # it was confirmed.
    os.environ["ZTV_ZEC_CONFIRMATIONS"] = "5"
    try:
        prov = pay_mod.WatchOnlyProvider()
        swept = "probe-zec-swept"
        # received recorded, nothing left unspent: modelled by paying and then
        # clearing the utxo list the fake builds from.
        fake_explorer.pay(swept, 400_000, depth=9)
        conf_before, _ = prov.address_received(swept, "ZEC")
        check("a deeply-buried ZEC payment is confirmed", conf_before == 400_000,
              conf_before)
    finally:
        os.environ["ZTV_ZEC_CONFIRMATIONS"] = "1"
        fake_explorer.reset()

    # ---------------------------------------------------------------------
    # [13] An explorer that answers with too much is refused, not buffered.
    #
    # The watch provider exists so we run no chain of our own, which means
    # every settlement check is a request to a third party whose response
    # size we do not control. And an attacker has a free lever on it: the
    # invoice address is handed to whoever is paying, so dust-spamming it
    # inflates that address's history without bound. The poller asks once a
    # minute, on the same 2GB box as the API and the database.
    #
    # The requirement is not that the check succeeds — it can't, the answer
    # is unusable. It is that it fails as an ordinary PaymentError, leaves
    # the invoice pending, and does not read the body into memory first.
    # ---------------------------------------------------------------------
    print("\n[13] an oversized explorer response is refused")
    prov = pay_mod.WatchOnlyProvider()
    flood_addr = "probe-btc-flood"
    fake_explorer.pay(flood_addr, 100_000)
    try:
        ok = prov.check(flood_addr, 100_000, coin="BTC")
        check("a normal-sized response still settles (control)",
              ok["status"] == pay_mod.SETTLED, ok)

        fake_explorer.FLOOD[0] = pay_mod.MAX_RESPONSE_BYTES + 4096
        raised = None
        try:
            prov.check(flood_addr, 100_000, coin="BTC")
        except pay_mod.PaymentError as e:
            raised = str(e)
        except Exception as e:                      # noqa: BLE001
            raised = f"WRONG TYPE {type(e).__name__}: {e}"
        check("an over-cap response raises PaymentError",
              raised is not None and "WRONG TYPE" not in raised,
              raised if raised else "the read was not capped — it buffered "
              f"{pay_mod.MAX_RESPONSE_BYTES + 4096} bytes and carried on")
        check("and the error names the cap rather than a parse failure",
              raised is not None and "refusing to buffer" in raised, raised)

        # The poller treats that as "chain check failed" and leaves the
        # invoice alone, which is the only safe direction: crediting on an
        # answer we could not read is how a month gets given away.
        fake_explorer.FLOOD[0] = 0
        again = prov.check(flood_addr, 100_000, coin="BTC")
        check("and the next poll, against a sane response, works again",
              again["status"] == pay_mod.SETTLED, again)
    finally:
        fake_explorer.reset()

finally:
    srv.shutdown(); wsrv.shutdown(); H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
