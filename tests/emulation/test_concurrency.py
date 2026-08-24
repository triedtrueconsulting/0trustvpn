#!/usr/bin/env python3
"""Second probe: concurrency, degenerate topologies, auth edges."""
import concurrent.futures as cf, os, shutil, sqlite3, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

TMP = H.tempdir("0trust-emu2-"); DB = os.path.join(TMP, "0trust.db")
sys.path.insert(0, os.path.join(H.REPO, "api"))
os.environ["ZTV_DB_PATH"] = DB
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=4)          # multiple workers => real concurrency on SQLite
print("stack up (4 workers)\n")

try:
    print("[A] concurrent device registration (mesh-IP / port races)")
    tok, _ = H.paid_account(12)
    pks = [H.genkey() for _ in range(8)]
    def reg(p):
        return H.call("POST", "/api/v1/wg/register",
                      {"pubkey": p, "device_name": "c", "region": "zur"},
                      headers={"X-Account-Token": tok})
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        res = list(ex.map(reg, pks))
    codes = [r[0] for r in res]
    check("no 500s under concurrent registration",
          500 not in codes, f"codes={codes}")
    ips = [r[1].get("interface_ip") for r in res if r[0] == 200]
    check("no duplicate mesh IPs handed out",
          len(ips) == len(set(ips)), f"{sorted(ips)}")

    print("\n[B] concurrent multi-hop (entry-port races)")
    tok2, _ = H.paid_account(12)
    pks2 = [H.genkey() for _ in range(8)]
    def regm(p):
        return H.call("POST", "/api/v1/wg/register",
                      {"pubkey": p, "device_name": "m", "region": "zur", "exit_region": "buc"},
                      headers={"X-Account-Token": tok2})
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        res2 = list(ex.map(regm, pks2))
    codes2 = [r[0] for r in res2]
    check("no 500s under concurrent multi-hop", 500 not in codes2, f"codes={codes2}")
    ports = [r[1]["peers"][0]["endpoint"].split(":")[1] for r in res2 if r[0] == 200]
    check("no duplicate entry ports", len(ports) == len(set(ports)), sorted(ports))

    print("\n[C] concurrent node provisioning (node_id race)")
    toks = [H.mint_provision_token(DB, "rey", "both") for _ in range(5)]
    def prov(t):
        return H.call("POST", "/api/v1/node/provision",
                      {"pubkey": H.genkey(), "public_ip": "198.51.100.5",
                       "region": "rey", "role": "both"},
                      headers={"X-Provision-Token": t})
    with cf.ThreadPoolExecutor(max_workers=5) as ex:
        res3 = list(ex.map(prov, toks))
    codes3 = [r[0] for r in res3]
    check("no 500s under concurrent provisioning", 500 not in codes3, f"codes={codes3}")
    ids = [r[1].get("node_id") for r in res3 if r[0] == 200]
    check("node ids unique", len(ids) == len(set(ids)), ids)

    print("\n[D] degenerate topology: only entry-role nodes")
    c = sqlite3.connect(DB)
    c.execute("UPDATE mesh_nodes SET role='entry'")
    c.commit(); c.close()
    tok3, _ = H.paid_account()
    st, r = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": H.genkey(), "device_name": "e", "region": "zur"},
                   headers={"X-Account-Token": tok3})
    check("no exit node available -> error, not an empty peer list",
          st >= 400, f"got {st} with peers={r.get('peers') if isinstance(r, dict) else r}")
    c = sqlite3.connect(DB); c.execute("UPDATE mesh_nodes SET role='both'"); c.commit(); c.close()

    print("\n[E] token handling")
    tok4, _ = H.paid_account()
    st, _ = H.call("GET", "/api/v1/account/status",
                   headers={"X-Account-Token": tok4.lower()})
    check("token accepted lowercase (hash normalizes)", st == 200, st)
    st, _ = H.call("GET", "/api/v1/account/status",
                   headers={"X-Account-Token": tok4.replace("-", "")})
    check("token accepted without dashes", st == 200, st)
    st, _ = H.call("GET", "/api/v1/account/status", headers={"X-Account-Token": "  "})
    check("blank token rejected", st in (401, 422), st)
    st, _ = H.call("GET", "/api/v1/account/status")
    check("missing token header rejected", st in (401, 422), st)

    print("\n[F] webhook auth")
    st, b = H.call("POST", "/api/v1/account", {"months": 1})
    iid = b["invoice_id"]
    st2, _ = H.call("POST", "/api/v1/payment/webhook",
                    {"type": "InvoiceSettled", "invoiceId": iid},
                    headers={"BTCPay-Sig": "sha256=deadbeef"})
    check("forged webhook signature rejected", st2 == 401, st2)
    st3, b3 = H.call("GET", "/api/v1/account/status", headers={"X-Account-Token": b["token"]})
    check("forged webhook did not activate account", b3["status"] == "pending_payment", b3)

    print("\n[G] expired account drops out of the peer manifest")
    tok5, _ = H.paid_account()
    pk5 = H.genkey()
    H.call("POST", "/api/v1/wg/register",
           {"pubkey": pk5, "device_name": "exp", "region": "zur"},
           headers={"X-Account-Token": tok5})
    st, pl = H.call("GET", "/api/v1/wg/peers?node_id=zur-01", headers={"X-Node-Psk": H.NODE_PSK})
    present = any(p["public_key"] == pk5 for p in pl["peers"])
    c = sqlite3.connect(DB)
    c.execute("UPDATE accounts SET expires_at=? WHERE token_hash=?",
              (int(time.time()) - 10, api_main.hash_token(tok5)))
    c.commit(); c.close()
    st, pl2 = H.call("GET", "/api/v1/wg/peers?node_id=zur-01", headers={"X-Node-Psk": H.NODE_PSK})
    gone = not any(p["public_key"] == pk5 for p in pl2["peers"])
    check("active device in manifest, expired device removed", present and gone,
          f"present={present} gone_after_expiry={gone}")
    st, rg = H.call("POST", "/api/v1/wg/rotate", {"pubkey": pk5, "region": "zur"},
                    headers={"X-Account-Token": tok5})
    check("expired account cannot rotate", st == 402, st)
finally:
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
