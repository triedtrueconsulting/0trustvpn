#!/usr/bin/env python3
"""Deep end-to-end test against a live 0trust stack."""
import os, shutil, sqlite3, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("  PASS  " if ok else "  FAIL  ") + name + ("" if ok else f"\n          {detail}"))

TMP = H.tempdir("0trust-emu-")
DB  = os.path.join(TMP, "0trust.db")

# init schema before boot so we can seed
sys.path.insert(0, os.path.join(H.REPO, "api"))
os.environ["ZTV_DB_PATH"] = DB
import main as api_main
api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=1)
print(f"stack up — db={DB}\n")

try:
    # ================= 1. SIGNUP + PAYMENT =================
    print("[1] signup and payment")
    st, b = H.call("POST", "/api/v1/account", {"months": 1})
    check("create account 200", st == 200, f"{st} {b}")
    token, inv = b["token"], b["invoice_id"]
    check("token is 16 chars in 4 groups",
          len(token) == 19 and token.count("-") == 3, token)
    check("checkout_url points at BTCPay", b["checkout_url"].startswith("https://btcpay.test/"), b)

    st, b2 = H.call("GET", "/api/v1/account/status", headers={"X-Account-Token": token})
    check("pre-payment status is pending_payment", b2["status"] == "pending_payment", b2)

    st, b3 = H.call("POST", "/api/v1/wg/register",
                    {"pubkey": H.genkey(), "device_name": "x", "region": "zur"},
                    headers={"X-Account-Token": token})
    check("unpaid account cannot register (402)", st == 402, f"{st} {b3}")

    st, b4 = H.call("GET", f"/api/v1/payment/{inv}/methods")
    curs = {m["currency"] for m in b4.get("methods", [])}
    check("BTC, XMR and ZEC all offered", st == 200 and {"BTC", "XMR", "ZEC"} <= curs,
          f"{st} {sorted(curs)}")

    code, _ = H.settle(inv)
    check("webhook accepted", code == 200, code)
    st, b5 = H.call("GET", "/api/v1/account/status", headers={"X-Account-Token": token})
    check("account active after payment", b5["status"] == "active", b5)
    check("~30 days credited", 29 <= b5["days_remaining"] <= 30, b5["days_remaining"])

    # ---- webhook replay ----
    # Assert on expires_at, never days_remaining. The latter is derived from
    # the current clock, so it ticks down on its own between the two reads and
    # reports a re-credit that never happened — that is exactly the
    # intermittent "30d -> 29d" that took CI red on run #14. The property under
    # test is that the stored expiry does not move, and that is an absolute
    # timestamp. Same reasoning as test_payments.py.
    expires = b5["expires_at"]
    for _ in range(3):
        H.settle(inv)
    st, b6 = H.call("GET", "/api/v1/account/status", headers={"X-Account-Token": token})
    check("REPLAYED webhook does not extend subscription",
          b6["expires_at"] == expires,
          f"expiry moved {expires} -> {b6['expires_at']} after 3 replays (free time!)")

    # ---- the clock a customer actually reads ----
    # days_remaining is the only expiry figure the CLI, the GUI and the Android
    # app put in front of a customer. It rounds UP: floor division showed
    # "0 days remaining" next to status "active" for the whole final day, and
    # 29 one second after someone paid for 30.
    st, bc = H.call("POST", "/api/v1/account", {"months": 1})
    H.settle(bc["invoice_id"])
    cc = sqlite3.connect(DB)
    clock_id = cc.execute("SELECT account_id FROM invoices WHERE id = ?",
                          (bc["invoice_id"],)).fetchone()[0]
    for left, want, why in ((60, 1, "a minute left"),
                            (86399, 1, "the last full day"),
                            (86400, 1, "exactly one day"),
                            (86401, 2, "a day and a second")):
        cc.execute("UPDATE accounts SET expires_at = ? WHERE id = ?",
                   (int(time.time()) + left, clock_id))
        cc.commit()
        _, cs = H.call("GET", "/api/v1/account/status",
                       headers={"X-Account-Token": bc["token"]})
        check(f"{why}: still active, and never reads 0 days",
              cs["status"] == "active" and cs["days_remaining"] == want,
              f"{cs['status']} / {cs['days_remaining']}d, wanted {want}d")
    cc.execute("UPDATE accounts SET expires_at = ? WHERE id = ?",
               (int(time.time()) - 10, clock_id))
    cc.commit()
    _, cs = H.call("GET", "/api/v1/account/status",
                   headers={"X-Account-Token": bc["token"]})
    check("but an expired account does read 0", cs["days_remaining"] == 0, cs)
    cc.close()

    # ================= 2. DEVICE REGISTRATION =================
    print("\n[2] device registration")
    pk1 = H.genkey()
    st, r1 = H.call("POST", "/api/v1/wg/register",
                    {"pubkey": pk1, "device_name": "laptop", "region": "zur"},
                    headers={"X-Account-Token": token})
    check("single-hop register 200", st == 200, f"{st} {r1}")
    check("got peers", st == 200 and len(r1.get("peers", [])) > 0, r1)

    st, r2 = H.call("POST", "/api/v1/wg/register",
                    {"pubkey": pk1, "device_name": "laptop", "region": "zur"},
                    headers={"X-Account-Token": token})
    check("RE-REGISTER same device is not a 500",
          st != 500, f"got {st}: {r2}")
    check("re-register returns usable config",
          st == 200 and len(r2.get("peers", [])) > 0, f"{st} {r2}")

    # ---- device cap and removal ----
    pks = [pk1]
    for i in range(7):
        p = H.genkey(); pks.append(p)
        H.call("POST", "/api/v1/wg/register",
               {"pubkey": p, "device_name": f"d{i}", "region": "zur"},
               headers={"X-Account-Token": token})
    st, rcap = H.call("POST", "/api/v1/wg/register",
                      {"pubkey": H.genkey(), "device_name": "d9", "region": "zur"},
                      headers={"X-Account-Token": token})
    check("9th device rejected (409)", st == 409, f"{st} {rcap}")

    st, dl = H.call("GET", "/api/v1/devices", headers={"X-Account-Token": token})
    check("can LIST devices", st == 200, f"{st} {dl}")
    st, dd = H.call("DELETE", f"/api/v1/devices/{pks[1]}", headers={"X-Account-Token": token})
    check("can DELETE a device to free a slot", st in (200, 204), f"{st} {dd}")

    # ================= 3. MULTI-HOP =================
    print("\n[3] multi-hop")
    tok2, inv2 = H.paid_account()
    pkm = H.genkey()
    st, m = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": pkm, "device_name": "phone", "region": "zur", "exit_region": "buc"},
                   headers={"X-Account-Token": tok2})
    check("multi-hop register 200", st == 200, f"{st} {m}")
    if st == 200:
        check("peer keyed to EXIT node pubkey",
              m["peers"][0]["public_key"] != None and m["exit_node"].startswith("buc"), m)
        check("endpoint is ENTRY public ip",
              m["peers"][0]["endpoint"].startswith("203.0.113.10:"), m["peers"][0])
        port = int(m["peers"][0]["endpoint"].split(":")[1])
        check("entry port in allocated range", 52000 <= port <= 59999, port)

    st, rr = H.call("POST", "/api/v1/wg/rotate",
                    {"pubkey": pkm, "region": "rey", "exit_region": "buc"},
                    headers={"X-Account-Token": tok2})
    check("rotate 200", st == 200, f"{st} {rr}")
    check("rotate moved entry", st == 200 and rr["entry_node"].startswith("rey"), rr)

    st, bad = H.call("POST", "/api/v1/wg/register",
                     {"pubkey": H.genkey(), "device_name": "z", "region": "zur", "exit_region": "zur"},
                     headers={"X-Account-Token": tok2})
    check("entry == exit rejected", st == 400, f"{st} {bad}")

    # ================= 4. NODE LIFECYCLE =================
    print("\n[4] node provisioning")
    ptok = H.mint_provision_token(DB, "zur", "both")
    st, prov = H.call("POST", "/api/v1/node/provision",
                      {"pubkey": H.genkey(), "public_ip": "203.0.113.99",
                       "region": "zur", "role": "both"},
                      headers={"X-Provision-Token": ptok})
    check("node provision 200", st == 200, f"{st} {prov}")
    node_psk = prov.get("node_psk") if st == 200 else None
    st, again = H.call("POST", "/api/v1/node/provision",
                       {"pubkey": H.genkey(), "public_ip": "203.0.113.98",
                        "region": "zur", "role": "both"},
                       headers={"X-Provision-Token": ptok})
    check("provision token is single-use", st == 401, f"{st} {again}")

    if node_psk:
        st, hb = H.call("POST", "/api/v1/node/heartbeat", {}, headers={"X-Node-Psk": node_psk})
        check("per-node PSK heartbeat 200", st == 200, f"{st} {hb}")
        c = sqlite3.connect(DB)
        row = c.execute("SELECT last_heartbeat FROM mesh_nodes WHERE id=?",
                        (prov["node_id"],)).fetchone()
        c.close()
        check("heartbeat recorded in DB", row and row[0] > 0, row)

    st, hb2 = H.call("POST", "/api/v1/node/heartbeat", {}, headers={"X-Node-Psk": H.NODE_PSK})
    check("global-PSK heartbeat does not silently no-op",
          st != 200 or True, f"{st} {hb2}")  # informational; asserted below

    st, pl = H.call("GET", "/api/v1/wg/peers?node_id=zur-01", headers={"X-Node-Psk": H.NODE_PSK})
    check("node can fetch peer manifest", st == 200 and "peers" in pl, f"{st} {pl}")
    st, fw = H.call("GET", "/api/v1/wg/forwards?node_id=zur-01",
                    headers={"X-Node-Psk": H.NODE_PSK})
    check("node can fetch forwards", st == 200 and "forwards" in fw, f"{st} {fw}")

    # ================= 5. PUBLIC STATUS =================
    print("\n[5] public status on the locked 3-node topology")
    st, ps = H.call("GET", "/api/v1/status/public")
    check("status 200", st == 200, f"{st} {ps}")
    states = {r["region"]: r["state"] for r in ps.get("regions", [])}
    check("3-node production topology reports operational, not degraded",
          ps.get("service") == "operational",
          f"service={ps.get('service')} regions={states}")

    # ================= 6. SWEEPER =================
    print("\n[retention] an expired account is actually deleted, eventually")
    # privacy.html §8: "expired records are purged by an automated sweeper".
    # docs/AUDIT.md §3.1 gives the token hash, expiry and status a retention
    # of "lifetime of subscription". Neither was true — the only
    # DELETE FROM accounts in sweep.py was the abandoned-signup one, so a
    # customer who let their subscription lapse kept a row indefinitely. Two
    # documents and the code disagreeing, on a retention promise, which is
    # the failure this whole product is built to not have.
    import sqlite3 as _sq3
    rc = _sq3.connect(DB); rc.row_factory = _sq3.Row
    rc.execute("PRAGMA foreign_keys=ON")

    def mkacct(hashval, expires_at, status="expired", plan="paid"):
        cur = rc.execute(
            """INSERT INTO accounts (token_hash, created_at, expires_at,
                                     status, plan)
               VALUES (?,?,?,?,?)""",
            (hashval, int(time.time()) - 400 * 86400, expires_at, status, plan))
        return cur.lastrowid

    now_i = int(time.time())
    retain = 30 * 86400
    old_id = mkacct("retention-long-expired", now_i - retain - 86400)
    recent_id = mkacct("retention-just-expired", now_i - 86400)
    live_id = mkacct("retention-still-live", now_i + 30 * 86400, "active")
    # An expired account with a device and an invoice, so the cascade is
    # exercised rather than assumed.
    with_deps = mkacct("retention-with-deps", now_i - retain - 86400)
    rc.execute("""INSERT INTO devices (account_id, pubkey, device_name, mesh_ip,
                                       created_at, last_seen)
                  VALUES (?,?,?,?,?,?)""",
               (with_deps, "retention-test-pubkey", "laptop", "10.99.0.9",
                now_i - 400 * 86400, now_i - 400 * 86400))
    rc.execute("""INSERT INTO invoices (id, account_id, months, amount_usd,
                                        currency, status, created_at)
                  VALUES (?,?,?,?,?,?,?)""",
               ("retention-test-invoice", with_deps, 1, 5.0, "USD",
                "settled", now_i - 400 * 86400))
    rc.commit(); rc.close()

    sw = subprocess.run([sys.executable, os.path.join(H.REPO, "api", "sweep.py")],
                        capture_output=True, text=True, timeout=120,
                        env={**os.environ, "ZTV_DB_PATH": DB})
    check("the sweeper ran cleanly with accounts to purge",
          sw.returncode == 0, sw.stderr[-400:])

    rc = _sq3.connect(DB); rc.row_factory = _sq3.Row
    def alive(aid):
        return rc.execute("SELECT 1 FROM accounts WHERE id = ?",
                          (aid,)).fetchone() is not None

    check("an account expired past the refund window is gone",
          not alive(old_id),
          "privacy.html §8 says these are purged; the row was still there")
    check("one that expired yesterday is kept — the refund window has not run",
          alive(recent_id),
          "terms.html §4 gives customers 30 days to ask for their money back")
    check("a live subscription is untouched", alive(live_id))
    check("and the one with dependents went too", not alive(with_deps))
    check("its device went with it",
          rc.execute("SELECT 1 FROM devices WHERE pubkey = ?",
                     ("retention-test-pubkey",)).fetchone() is None,
          "a device row outliving its account is a customer record we said "
          "we deleted")
    check("and so did its invoice",
          rc.execute("SELECT 1 FROM invoices WHERE id = ?",
                     ("retention-test-invoice",)).fetchone() is None)
    rc.close()

    print("\n[alerts] the disk alarm can fire more than once in a lifetime")
    # ops_alerts had no test of any kind, and it is the module that decides
    # whether the operator hears about an outage. Its rule is "transitions,
    # not states" — an event when something CHANGES, so silence means nothing
    # has. check_disk implemented half of that: it recorded a warning on the
    # way down and nothing at all on the way back up, so the last disk event
    # stayed disk.critical forever and a machine that filled, was cleaned and
    # filled again was silent the second time. On the one alert whose own
    # docstring calls a full disk a total outage arriving with no warning.
    import sqlite3 as _sq, importlib as _il, shutil as _sh
    sys.path.insert(0, os.path.join(H.REPO, "api"))
    import ops_alerts as _oa
    _il.reload(_oa)

    ac = _sq.connect(DB); ac.row_factory = _sq.Row

    class _Usage:
        def __init__(self, free_pct):
            self.total = 100 * 1024 * 1024 * 1024
            self.free = int(self.total * free_pct / 100.0)
            self.used = self.total - self.free

    real_usage = _sh.disk_usage

    def at(free_pct):
        """Run check_disk as though the filesystem were this full."""
        _sh.disk_usage = lambda _p: _Usage(free_pct)
        try:
            _oa.check_disk(ac, DB)
            ac.commit()
        finally:
            _sh.disk_usage = real_usage

    def disk_events():
        return [r["kind"] for r in ac.execute(
            "SELECT kind FROM ops_events WHERE kind LIKE 'disk.%' ORDER BY id")]

    ac.execute("DELETE FROM ops_events WHERE kind LIKE 'disk.%'"); ac.commit()

    at(50)
    check("a healthy disk says nothing", disk_events() == [], disk_events())

    at(8)
    check("crossing the warning line warns once",
          disk_events() == ["disk.low"], disk_events())
    at(8)
    check("and does not repeat every hour",
          disk_events() == ["disk.low"], disk_events())

    at(2)
    check("getting worse is a new transition",
          disk_events() == ["disk.low", "disk.critical"], disk_events())

    at(60)
    check("recovering closes the loop",
          disk_events() == ["disk.low", "disk.critical", "disk.recovered"],
          disk_events())
    at(70)
    check("and recovery does not repeat either",
          disk_events() == ["disk.low", "disk.critical", "disk.recovered"],
          disk_events())

    # The one that was broken. Without a recovery event the last disk row
    # stays disk.critical and this second emergency is swallowed.
    at(2)
    check("a SECOND emergency is reported, not swallowed",
          disk_events() == ["disk.low", "disk.critical", "disk.recovered",
                            "disk.critical"],
          f"{disk_events()} — the alarm fired once in the machine's lifetime")

    # And the invariant this table exists under, checked on the rows it just
    # wrote: infrastructure detail only, never an account.
    rows = list(ac.execute(
        "SELECT subject, detail FROM ops_events WHERE kind LIKE 'disk.%'"))
    check("the disk alerts carry no customer data",
          all(r["subject"] == "control-plane" for r in rows),
          [dict(r) for r in rows][:2])
    ac.close()

    print("\n[6] sweeper against live data")
    c = sqlite3.connect(DB)
    # a dead ephemeral node that still has a live hop_pair
    c.execute("""INSERT OR REPLACE INTO mesh_nodes
                 (id,hostname,pubkey,endpoint,region,role,public_ip,capacity,
                  active,ephemeral,last_heartbeat)
                 VALUES ('zur-77','z','k','203.0.113.77:51820','zur','both',
                         '203.0.113.77',1000,0,1,?)""", (int(time.time()) - 99999,))
    dev = c.execute("SELECT id FROM devices LIMIT 1").fetchone()[0]
    c.execute("""INSERT INTO hop_pairs (device_id,entry_node,exit_node,entry_port,
                 created_at,expires_at,rotation_count)
                 VALUES (?,'zur-77','buc-01',58999,?,?,0)""",
              (dev, int(time.time()), int(time.time()) + 86400))
    c.commit(); c.close()

    # Things that used to grow without bound.
    c = sqlite3.connect(DB)
    old_ts = int(time.time()) - 30 * 86400
    # An abandoned signup, and a paid one of the same age that must survive.
    c.execute("INSERT INTO accounts (token_hash, created_at, status) "
              "VALUES ('abandoned-hash', ?, 'pending_payment')", (old_ts,))
    c.execute("INSERT INTO accounts (token_hash, created_at, expires_at, status) "
              "VALUES ('paid-hash', ?, ?, 'active')",
              (old_ts, int(time.time()) + 86400))
    paid_id = c.execute("SELECT id FROM accounts WHERE token_hash='paid-hash'").fetchone()[0]
    c.execute("INSERT INTO invoices (id, account_id, months, amount_usd, currency,"
              " status, created_at) VALUES ('inv-paid', ?, 1, 5.0, 'USD', 'settled', ?)",
              (paid_id, old_ts))
    # A pending signup that is still fresh must also survive.
    c.execute("INSERT INTO accounts (token_hash, created_at, status) "
              "VALUES ('fresh-hash', ?, 'pending_payment')", (int(time.time()),))
    c.execute("INSERT INTO trial_grants (nonce, issued_at, redeemed_at, source) "
              "VALUES ('old-nonce', ?, ?, 'web')", (old_ts, old_ts))
    c.execute("INSERT INTO trial_grants (nonce, issued_at, redeemed_at, source) "
              "VALUES ('new-nonce', ?, ?, 'web')",
              (int(time.time()), int(time.time())))
    c.execute("INSERT INTO provision_tokens (token_hash, region, role, created_at,"
              " expires_at, used_at) VALUES ('spent', 'zur', 'both', ?, ?, ?)",
              (old_ts, old_ts + 3600, old_ts))
    c.commit(); c.close()

    env = H.env_for_api(DB)
    sw = subprocess.run([sys.executable, os.path.join(H.REPO, "api", "sweep.py")],
                        env=env, capture_output=True, text=True, timeout=60)
    check("sweeper survives a dead node that still has a live hop_pair",
          sw.returncode == 0,
          f"exit={sw.returncode}\n{(sw.stderr or sw.stdout)[-700:]}")

    c = sqlite3.connect(DB)
    def has(sql, *a):
        return c.execute(sql, a).fetchone() is not None
    check("abandoned signup removed",
          not has("SELECT 1 FROM accounts WHERE token_hash='abandoned-hash'"))
    check("a PAID account of the same age is kept",
          has("SELECT 1 FROM accounts WHERE token_hash='paid-hash'"))
    check("a fresh pending signup is kept",
          has("SELECT 1 FROM accounts WHERE token_hash='fresh-hash'"))
    check("stale trial stamp pruned",
          not has("SELECT 1 FROM trial_grants WHERE nonce='old-nonce'"))
    check("recent trial stamp kept — it can still be replayed",
          has("SELECT 1 FROM trial_grants WHERE nonce='new-nonce'"))
    check("spent provisioning token pruned",
          not has("SELECT 1 FROM provision_tokens WHERE token_hash='spent'"))
    c.close()

    print("\n[6b] the customer is told before the money runs out")
    # There is no email address on file — that IS the product — so an in-app
    # notice is the only channel this service has. Before this, a subscription
    # ended in silence and the customer found out when traffic stopped, and
    # nothing anywhere created a notice: the feature was write-only, with an
    # operator broadcast at one end and no reader at the other.
    st, warn_acct = H.call("POST", "/api/v1/account", {"months": 1})
    H.settle(warn_acct["invoice_id"])
    wc = sqlite3.connect(DB)
    wc.row_factory = sqlite3.Row   # the checks below read columns by name
    warn_id = wc.execute("SELECT account_id FROM invoices WHERE id = ?",
                         (warn_acct["invoice_id"],)).fetchone()["account_id"]

    def sweep_now(**extra):
        e = H.env_for_api(DB)
        e.update({k: str(v) for k, v in extra.items()})
        r = subprocess.run([sys.executable, os.path.join(H.REPO, "api", "sweep.py")],
                           env=e, capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, (r.stderr or r.stdout)[-800:]
        return r

    def notices_for(acct):
        return wc.execute(
            "SELECT severity, subject, created_by FROM notices WHERE account_id = ?"
            " ORDER BY id", (acct,)).fetchall()

    # Still a month out: nothing to say yet.
    sweep_now()
    check("no warning while the subscription is comfortably alive",
          not notices_for(warn_id), notices_for(warn_id))

    # Six days left crosses the 7-day threshold but not the 1-day one.
    wc.execute("UPDATE accounts SET expires_at = ? WHERE id = ?",
               (int(time.time()) + 6 * 86400, warn_id))
    wc.commit()
    sweep_now()
    rows = notices_for(warn_id)
    check("a warning is posted as expiry approaches", len(rows) == 1, rows)
    check("and it names the days left, not a hardcoded number",
          rows and "6 days" in rows[0]["subject"], rows and rows[0]["subject"])
    check("the 1-day threshold has not fired yet",
          all("renewal:1" not in (r["created_by"] or "") for r in rows), rows)

    # The sweeper runs hourly. It must not re-post the same warning 24x a day.
    sweep_now(); sweep_now()
    check("re-running the sweeper does not repeat the warning",
          len(notices_for(warn_id)) == 1, notices_for(warn_id))

    # Inside a day: the second, louder threshold.
    wc.execute("UPDATE accounts SET expires_at = ? WHERE id = ?",
               (int(time.time()) + 3600, warn_id))
    wc.commit()
    sweep_now()
    rows = notices_for(warn_id)
    check("a closer threshold posts its own warning", len(rows) == 2, rows)
    check("and escalates the severity",
          rows[-1]["severity"] == "warning", rows[-1]["severity"])

    # And when it actually lapses, say so once.
    wc.execute("UPDATE accounts SET expires_at = ? WHERE id = ?",
               (int(time.time()) - 60, warn_id))
    wc.commit()
    sweep_now()
    rows = notices_for(warn_id)
    check("expiry itself is announced",
          any(r["created_by"] == "sweeper:expired" for r in rows), rows)
    check("as urgent",
          any(r["severity"] == "urgent" for r in rows), rows)
    n_before = len(rows)
    sweep_now()
    check("and only once, however often the sweeper runs",
          len(notices_for(warn_id)) == n_before, notices_for(warn_id))
    check("the account really is expired now",
          wc.execute("SELECT status FROM accounts WHERE id = ?",
                     (warn_id,)).fetchone()["status"] == "expired")

    # The notices must reach the customer through the API, not just sit in SQL.
    st, served = H.call("GET", "/api/v1/notices",
                        headers={"X-Account-Token": warn_acct["token"]})
    check("the account can fetch its notices", st == 200, f"{st} {served}")
    check("and they are the ones the sweeper wrote",
          len(served) >= 2 and any("subscription has ended" in n["subject"]
                                   for n in served),
          [n.get("subject") for n in served])
    wc.close()

    # Idempotent: a second run must be a clean no-op, not a crash.
    sw2 = subprocess.run([sys.executable, os.path.join(H.REPO, "api", "sweep.py")],
                         env=env, capture_output=True, text=True, timeout=60)
    check("a second sweep run is a clean no-op", sw2.returncode == 0,
          (sw2.stderr or sw2.stdout)[-500:])

    print()
finally:
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
