#!/usr/bin/env python3
"""
The admin backend: auth, authorization, and every control it offers.

This surface can ban customers, hand out free time and change where money
lands, so it gets tested like it matters — both that the controls work and
that they cannot be reached without credentials.
"""
import http.cookiejar, json, os, shutil, sqlite3, sys, time
import urllib.error, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

TMP = H.tempdir("0trust-admin-"); DB = os.path.join(TMP, "0trust.db")
os.environ["ZTV_DB_PATH"] = DB
os.environ["ZTV_TRIAL_SECRET"] = "admin-test"
os.environ["ZTV_TRIAL_POW_BITS"] = "10"
os.environ.pop("ZTV_ADMIN_USER", None)
os.environ.pop("ZTV_ADMIN_PASSWORD", None)
sys.path.insert(0, os.path.join(H.REPO, "api"))
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=1)

# A cookie-aware client, because the admin session is a cookie.
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
CSRF = {"v": None}


def adm(method, path, body=None, csrf=True, timeout=25, extra=None):
    url = H.API + "/api/v1/admin" + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    headers.update(extra or {})
    if csrf and CSRF["v"] and method not in ("GET", "HEAD"):
        headers["X-Admin-CSRF"] = CSRF["v"]
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, {"raw": raw.decode("utf-8", "replace")[:300]}


try:
    print("[1] nothing is reachable before signing in")
    for path in ("/overview", "/accounts", "/nodes", "/settings", "/audit",
                 "/invoices", "/notices"):
        st, _ = adm("GET", path)
        check(f"GET {path} refused when signed out", st == 401, st)
    st, _ = adm("POST", "/accounts/1/ban", {"reason": "x"})
    check("ban refused when signed out", st == 401, st)

    print("\n[2] first-run setup")
    st, state = adm("GET", "/state")
    check("state says setup is needed", st == 200 and state["needs_setup"], state)
    st, r = adm("POST", "/setup", {"username": "ops", "password": "short"})
    check("a weak password is refused", st == 422, st)
    st, r = adm("POST", "/setup",
                {"username": "ops", "password": "correct-horse-battery-staple"})
    check("first operator created and signed in", st == 200 and r.get("ok"), r)
    CSRF["v"] = r.get("csrf")
    check("a CSRF token was issued", bool(CSRF["v"]))
    st, r2 = adm("POST", "/setup", {"username": "sneak", "password": "another-long-one"})
    check("setup cannot be run twice", st == 409, f"{st} {r2}")

    print("\n[3] CSRF is enforced on mutations")
    st, _ = adm("POST", "/notices",
                {"subject": "x", "body": "y"}, csrf=False)
    check("a mutation without the CSRF header is refused", st == 403, st)

    print("\n[4] overview")
    st, ov = adm("GET", "/overview")
    check("overview loads", st == 200, ov)
    check("counts accounts", "accounts" in ov and "active" in ov["accounts"], ov)
    check("lists the seeded nodes", len(ov.get("nodes", [])) == 3, ov.get("nodes"))
    check("reports the active payment provider", ov.get("provider"), ov)

    print("\n[5] accounts: search, ban, extend")
    tok, _ = H.paid_account()
    pk = H.genkey()
    H.call("POST", "/api/v1/wg/register",
           {"pubkey": pk, "device_name": "laptop", "region": "zur"},
           headers={"X-Account-Token": tok})
    st, lst = adm("GET", "/accounts")
    check("accounts listed", st == 200 and lst["total"] >= 1, lst)
    acct_id = lst["accounts"][0]["id"]

    st, found = adm("GET", f"/accounts?q={tok}")
    check("an account is findable by its token", found["total"] == 1, found)
    check("the token hash is never echoed back",
          "token_hash" not in json.dumps(found), "token_hash leaked")
    import urllib.parse as _up
    st, bypk = adm("GET", f"/accounts?q={_up.quote(pk, safe='')}")
    check("findable by device pubkey", bypk.get("total") == 1, bypk)
    # An operator pasting a key without encoding it: '+' arrives as a space.
    st, bysloppy = adm("GET", f"/accounts?q={pk}")
    check("a pasted, unencoded pubkey still finds the account",
          bysloppy.get("total") == 1, bysloppy)

    st, detail = adm("GET", f"/accounts/{acct_id}")
    check("account detail loads", st == 200 and detail["devices"], detail)
    check("detail omits the token hash", "token_hash" not in json.dumps(detail))

    st, r = adm("POST", f"/accounts/{acct_id}/ban", {"reason": "abuse report #12"})
    check("ban succeeds", st == 200, r)
    check("banning removes the devices, cutting traffic now",
          r.get("devices_removed") == 1, r)
    st, s2 = H.call("GET", "/api/v1/account/status", headers={"X-Account-Token": tok})
    check("a banned account is refused by the customer API", s2 is not None and st == 403,
          f"{st} {s2}")
    st, peers = H.call("GET", "/api/v1/wg/peers?node_id=zur-01",
                       headers={"X-Node-Psk": H.NODE_PSK})
    check("the banned device is gone from the peer manifest",
          all(p["public_key"] != pk for p in peers["peers"]), peers)

    st, r = adm("POST", f"/accounts/{acct_id}/unban")
    check("unban restores the right status", st == 200 and r["status"] == "active", r)
    st, s3 = H.call("GET", "/api/v1/account/status", headers={"X-Account-Token": tok})
    check("the customer can use the account again", st == 200, s3)

    before = H.call("GET", "/api/v1/account/status",
                    headers={"X-Account-Token": tok})[1]["days_remaining"]
    st, r = adm("POST", f"/accounts/{acct_id}/extend",
                {"days": 60, "reason": "support goodwill"})
    after = H.call("GET", "/api/v1/account/status",
                   headers={"X-Account-Token": tok})[1]["days_remaining"]
    check("extend adds days", after >= before + 59, f"{before} -> {after}")
    st, r = adm("POST", f"/accounts/{acct_id}/extend", {"days": -60, "reason": "undo"})
    after2 = H.call("GET", "/api/v1/account/status",
                    headers={"X-Account-Token": tok})[1]["days_remaining"]
    check("extend can also subtract", after2 <= after - 59, f"{after} -> {after2}")

    print("\n[6] nodes")
    st, r = adm("POST", "/nodes", {
        "id": "zur-02", "region": "zur", "role": "exit",
        "pubkey": H.genkey(), "public_ip": "203.0.113.55", "capacity": 500})
    check("a node can be added from the dashboard", st == 200, r)
    st, nodes = adm("GET", "/nodes")
    check("it appears in the list",
          any(n["id"] == "zur-02" for n in nodes["nodes"]), nodes)
    check("node PSK hashes are never returned",
          "psk_hash" not in json.dumps(nodes), "psk_hash leaked")
    st, r = adm("POST", "/nodes", {
        "id": "xxx-01", "region": "xxx", "role": "both",
        "pubkey": H.genkey(), "public_ip": "203.0.113.56"})
    check("a node outside the jurisdiction allowlist is refused", st == 400, r)
    st, r = adm("PATCH", "/nodes/zur-02", {"active": False})
    check("a node can be taken out of rotation", st == 200, r)
    st, r = adm("POST", "/nodes/provision-token", {"region": "rey", "role": "both"})
    check("a provisioning token can be minted", st == 200 and r.get("token"), r)
    ptok = r["token"]
    st, prov = H.call("POST", "/api/v1/node/provision",
                      {"pubkey": H.genkey(), "public_ip": "198.51.100.9",
                       "region": "rey", "role": "both"},
                      headers={"X-Provision-Token": ptok})
    check("the minted token actually provisions a node", st == 200, prov)
    st, r = adm("DELETE", "/nodes/zur-02")
    check("a node can be removed", st == 200, r)

    print("\n[7] payments")
    st, health = adm("GET", "/payments/health")
    check("payment health reports the provider", st == 200 and health["provider"], health)
    check("it lists what is still missing", "missing_settings" in health, health)
    st, b = H.call("POST", "/api/v1/account", {"months": 1})
    st, inv = adm("GET", "/invoices")
    check("invoices are listed", st == 200 and inv["total"] >= 1, inv)
    st, r = adm("POST", f"/invoices/{b['invoice_id']}/settle")
    check("an invoice can be settled by hand", st == 200, r)
    st, s = H.call("GET", "/api/v1/account/status",
                   headers={"X-Account-Token": b["token"]})
    check("manual settlement credits the account", s["status"] == "active", s)
    # expires_at, not days_remaining: the latter is derived from the current
    # clock and ticks down between the two reads, which reads as a re-credit
    # that never happened. See test_payments.py.
    expires = s["expires_at"]
    st, r = adm("POST", f"/invoices/{b['invoice_id']}/settle")
    check("settling twice is refused as a duplicate", r.get("duplicate"), r)
    s2 = H.call("GET", "/api/v1/account/status",
                headers={"X-Account-Token": b["token"]})[1]
    check("and does not double the subscription", s2["expires_at"] == expires,
          f"expiry moved {expires} -> {s2['expires_at']}")

    print("\n[8] settings")
    st, cfg = adm("GET", "/settings")
    check("settings load", st == 200 and "ZTV_PAYMENT_PROVIDER" in cfg["settings"], cfg)
    st, r = adm("POST", "/settings", {"values": {
        "WALLET_BTC": "zpub6-test-wallet", "STRIPE_SECRET_KEY": "sk_test_secret123"}})
    check("settings save", st == 200 and "WALLET_BTC" in r["changed"], r)
    st, cfg2 = adm("GET", "/settings")
    check("a wallet reads back in the clear",
          cfg2["settings"]["WALLET_BTC"]["value"] == "zpub6-test-wallet", cfg2)
    masked = cfg2["settings"]["STRIPE_SECRET_KEY"]["value"]
    check("a secret is masked in the response", "sk_test_secret123" not in masked, masked)
    check("but shows it is set", cfg2["settings"]["STRIPE_SECRET_KEY"]["set"], cfg2)
    st, r = adm("POST", "/settings", {"values": {"STRIPE_SECRET_KEY": masked}})
    check("re-saving the masked value does not clobber the real secret",
          "STRIPE_SECRET_KEY" not in r["changed"], r)
    st, r = adm("POST", "/settings", {"values": {"ZTV_DB_PATH": "/tmp/evil.db"}})
    check("a setting outside the allowlist is ignored",
          "ZTV_DB_PATH" not in r.get("changed", []), r)
    st, r = adm("POST", "/settings",
                {"values": {"ZTV_PAYMENT_PROVIDER": "stripe"}})
    st, health2 = adm("GET", "/payments/health")
    check("switching provider takes effect without a restart",
          health2["provider"] == "stripe", health2)
    check("card provider advertises card currency, not coins",
          health2["currencies"] == ["USD (card)"], health2)
    adm("POST", "/settings", {"values": {"ZTV_PAYMENT_PROVIDER": "btcpay"}})

    print("\n[9] notices reach the customer")
    st, r = adm("POST", "/notices", {
        "subject": "Scheduled maintenance", "body": "buc-01 reboots at 02:00 UTC.",
        "severity": "warning"})
    check("a broadcast notice is created", st == 200, r)
    check("it reports how many accounts it reaches", r.get("reach", 0) >= 1, r)
    st, mine = H.call("GET", "/api/v1/notices", headers={"X-Account-Token": tok})
    check("the customer can fetch it", st == 200 and len(mine) >= 1, mine)
    check("subject and body come through",
          any(n["subject"] == "Scheduled maintenance" for n in mine), mine)
    st, s = H.call("GET", "/api/v1/account/status", headers={"X-Account-Token": tok})
    check("status reports the unread count", s.get("notices", 0) >= 1, s)
    nid = mine[0]["id"]
    st, _ = H.call("POST", f"/api/v1/notices/{nid}/read",
                   headers={"X-Account-Token": tok})
    st, mine2 = H.call("GET", "/api/v1/notices", headers={"X-Account-Token": tok})
    check("marking it read removes it", all(n["id"] != nid for n in mine2), mine2)

    st, r = adm("POST", "/notices", {
        "subject": "Just for you", "body": "About your report.",
        "account_id": acct_id, "severity": "urgent"})
    check("a targeted notice is created", st == 200, r)
    tok2, _ = H.paid_account()
    st, other = H.call("GET", "/api/v1/notices", headers={"X-Account-Token": tok2})
    check("another customer does not receive it",
          all(n["subject"] != "Just for you" for n in other), other)

    print("\n[10] the audit trail")
    st, log = adm("GET", "/audit")
    check("audit entries exist", st == 200 and log["total"] > 0, log)
    actions = {e["action"] for e in log["entries"]}
    for want in ("account.ban", "account.extend", "node.add", "settings.update",
                 "notice.create", "invoice.manual_settle"):
        check(f"{want} was recorded", want in actions, sorted(actions))
    detail = json.dumps(log["entries"])
    check("the audit log never contains a secret value",
          "sk_test_secret123" not in detail, "secret leaked into audit")

    print("\n[11] session lifecycle")
    st, r = adm("POST", "/password", {
        "current_password": "wrong-password-entirely",
        "new_password": "another-very-long-password"})
    check("a wrong current password is refused", st == 403, r)
    st, r = adm("POST", "/logout")
    check("logout succeeds", st == 200, r)
    st, _ = adm("GET", "/overview")
    check("the session is dead afterwards", st == 401, st)
    st, r = adm("POST", "/login", {"username": "ops", "password": "wrong"})
    check("a bad password is refused", st == 401, r)
    st, r = adm("POST", "/login",
                {"username": "ops", "password": "correct-horse-battery-staple"})
    check("signing back in works", st == 200, r)
    print("\n[lockout] a stranger's failures do not lock the operator out")
    # The API sees 127.0.0.1 for every request behind nginx, so rate limiting
    # on the TCP peer put the whole internet in one bucket: eight wrong
    # guesses from anybody left the real operator staring at 429 for the rest
    # of the window. nginx sets X-Real-IP from the address it actually saw and
    # a client cannot forge it through nginx, so that is what the limiter uses
    # — and only when the peer is a proxy we trust.
    st, r = adm("POST", "/logout")
    attacker = {"X-Real-IP": "198.51.100.66"}
    codes = []
    for _ in range(12):
        st, _ = adm("POST", "/login",
                    {"username": "ops", "password": "definitely-not-it"},
                    extra=attacker)
        codes.append(st)
    check("the attacker's address is throttled", 429 in codes, codes)

    # A different address, correct password: must still get in.
    st, r = adm("POST", "/login",
                {"username": "ops", "password": "correct-horse-battery-staple"},
                extra={"X-Real-IP": "203.0.113.9"})
    check("the operator can still sign in from elsewhere", st == 200,
          f"{st} {r} — anyone who can reach the login endpoint could lock the "
          "dashboard, which is where bans and refunds live")
    if st == 200 and isinstance(r, dict) and r.get("csrf"):
        CSRF["v"] = r["csrf"]

    # And the forwarded header must not be believed from an untrusted peer,
    # or the limiter is trivially evaded with a fresh value per attempt.
    import admin as admin_mod
    check("forwarded headers are only trusted from a known proxy",
          "127.0.0.1" in admin_mod.TRUSTED_PROXIES
          and "10.0.0.1" not in admin_mod.TRUSTED_PROXIES,
          sorted(admin_mod.TRUSTED_PROXIES))

    # Wrong passwords must still be refused while the username is hot — the
    # exemption is for a CORRECT password, not for the endpoint.
    st, _ = adm("POST", "/login",
                {"username": "ops", "password": "still-not-it"},
                extra={"X-Real-IP": "203.0.113.9"})
    check("a wrong password is still refused during the window",
          st in (401, 429), st)

    st, aud = adm("GET", "/audit")
    entries = (aud or {}).get("entries") or []
    failed = [e for e in entries if e.get("action") == "admin.login.failed"]
    check("failed logins are recorded with the real address",
          any("198.51.100.66" in (e.get("detail") or "") for e in failed),
          "the audit log said 127.0.0.1 for every attempt — useless on the one "
          "record an operator reads after an intrusion attempt")

    print("\n[events] the operator can see what broke")
    st, ev = adm("GET", "/events")
    check("events feed loads", st == 200, ev)
    check("it reports whether a webhook is set",
          "webhook_configured" in ev, ev)
    check("it carries an unresolved count for the badge",
          isinstance(ev.get("unresolved"), int), ev)
    # Distinct from the audit log on purpose: audit is what the operator did,
    # events are what the system did on its own.
    st_a, aud = adm("GET", "/audit")
    check("events are not just the audit log again",
          set(ev.get("events", [{}])[0].keys()) != set(
              (aud.get("entries") or [{}])[0].keys())
          if ev.get("events") and aud.get("entries") else True, (ev, aud))

finally:
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
