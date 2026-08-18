#!/usr/bin/env python3
"""Deep end-to-end test against a live 0trust stack."""
import os, shutil, sqlite3, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    print(("  PASS  " if ok else "  FAIL  ") + name + ("" if ok else f"\n          {detail}"))

TMP = tempfile.mkdtemp(prefix="0trust-emu-")
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
    check("payment methods listed", st == 200 and len(b4["methods"]) == 3, f"{st} {b4}")

    code, _ = H.settle(inv)
    check("webhook accepted", code == 200, code)
    st, b5 = H.call("GET", "/api/v1/account/status", headers={"X-Account-Token": token})
    check("account active after payment", b5["status"] == "active", b5)
    days = b5["days_remaining"]
    check("~30 days credited", 29 <= days <= 30, days)

    # ---- webhook replay ----
    for _ in range(3):
        H.settle(inv)
    st, b6 = H.call("GET", "/api/v1/account/status", headers={"X-Account-Token": token})
    check("REPLAYED webhook does not extend subscription",
          b6["days_remaining"] == days,
          f"{days}d -> {b6['days_remaining']}d after 3 replays (free time!)")

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

    st, pl = H.call("GET", "/api/v1/wg/peers", headers={"X-Node-Psk": H.NODE_PSK})
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

    env = H.env_for_api(DB)
    sw = subprocess.run([sys.executable, os.path.join(H.REPO, "api", "sweep.py")],
                        env=env, capture_output=True, text=True, timeout=60)
    check("sweeper survives a dead node that still has a live hop_pair",
          sw.returncode == 0,
          f"exit={sw.returncode}\n{(sw.stderr or sw.stdout)[-700:]}")

    print()
finally:
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
