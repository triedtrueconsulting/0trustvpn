#!/usr/bin/env python3
"""Free trial: proof-of-work, redemption, limits, and conversion to paid."""
import hashlib, os, shutil, sqlite3, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

def solve(nonce, bits):
    """Grind the stamp the browser would grind."""
    need_bytes, need_bits = divmod(bits, 8)
    i = 0
    while True:
        sol = str(i)
        d = hashlib.sha256(f"{nonce}:{sol}".encode()).digest()
        if not any(d[k] for k in range(need_bytes)) and \
           (not need_bits or not d[need_bytes] >> (8 - need_bits)):
            return sol
        i += 1

TMP = tempfile.mkdtemp(prefix="0trust-trial-"); DB = os.path.join(TMP, "0trust.db")
os.environ["ZTV_DB_PATH"] = DB
os.environ["ZTV_TRIAL_SECRET"] = "trial-secret-for-tests"
os.environ["ZTV_TRIAL_POW_BITS"] = "12"     # keep the suite fast
os.environ["ZTV_TRIAL_MAX_DEVICES"] = "2"
sys.path.insert(0, os.path.join(H.REPO, "api"))
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=2)

try:
    print("[1] challenge / redeem")
    st, ch = H.call("GET", "/api/v1/trial/challenge")
    check("challenge issued", st == 200 and "nonce" in ch, f"{st} {ch}")
    check("difficulty advertised", ch.get("bits") == 12, ch)
    sol = solve(ch["nonce"], ch["bits"])
    st, tr = H.call("POST", "/api/v1/trial", {
        "nonce": ch["nonce"], "expires_at": ch["expires_at"],
        "signature": ch["signature"], "solution": sol, "source": "surf"})
    check("trial redeemed", st == 200, f"{st} {tr}")
    token = tr.get("token")
    check("plan is trial", tr.get("plan") == "trial", tr)
    check("30 days granted", 29 <= (tr["expires_at"] - int(time.time())) // 86400 <= 30, tr)

    print("\n[2] the stamp is single-use")
    st, dup = H.call("POST", "/api/v1/trial", {
        "nonce": ch["nonce"], "expires_at": ch["expires_at"],
        "signature": ch["signature"], "solution": sol})
    check("replaying a redeemed stamp is refused", st == 409, f"{st} {dup}")

    print("\n[3] forged and unsolved challenges")
    st, ch2 = H.call("GET", "/api/v1/trial/challenge")
    st2, bad = H.call("POST", "/api/v1/trial", {
        "nonce": ch2["nonce"], "expires_at": ch2["expires_at"],
        "signature": ch2["signature"], "solution": "0"})
    check("unsolved proof of work refused", st2 == 400 and "work" in str(bad).lower(),
          f"{st2} {bad}")
    st3, forged = H.call("POST", "/api/v1/trial", {
        "nonce": "deadbeef" * 4, "expires_at": int(time.time()) + 600,
        "signature": "00" * 32, "solution": "0"})
    check("forged challenge signature refused", st3 == 400, f"{st3} {forged}")
    st4, stale = H.call("POST", "/api/v1/trial", {
        "nonce": ch2["nonce"], "expires_at": int(time.time()) - 10,
        "signature": ch2["signature"], "solution": solve(ch2["nonce"], 12)})
    check("expired challenge refused", st4 == 400, f"{st4} {stale}")

    print("\n[4] a trial is a working account")
    st, stat = H.call("GET", "/api/v1/account/status",
                      headers={"X-Account-Token": token})
    check("status active", st == 200 and stat["status"] == "active", stat)
    check("status reports the trial plan", stat.get("plan") == "trial", stat)
    check("status reports the trial device cap", stat.get("max_devices") == 2, stat)
    pk_laptop = H.genkey()
    st, reg = H.call("POST", "/api/v1/wg/register",
                     {"pubkey": pk_laptop, "device_name": "laptop", "region": "zur"},
                     headers={"X-Account-Token": token})
    check("trial can register a device", st == 200 and reg["peers"], f"{st} {reg}")
    pk_phone = H.genkey()
    st, mh = H.call("POST", "/api/v1/wg/register",
                    {"pubkey": pk_phone, "device_name": "phone",
                     "region": "zur", "exit_region": "buc"},
                    headers={"X-Account-Token": token})
    check("trial gets multi-hop too", st == 200 and mh.get("multihop"), f"{st} {mh}")

    print("\n[5] trial device cap")
    st, over = H.call("POST", "/api/v1/wg/register",
                      {"pubkey": H.genkey(), "device_name": "third", "region": "zur"},
                      headers={"X-Account-Token": token})
    check("third device refused on a 2-device trial", st == 409, f"{st} {over}")
    check("refusal points at upgrading", "Upgrade" in str(over), over)

    print("\n[6] the trial's devices reach only the nodes that route them")
    def peers_at(node):
        st, b = H.call("GET", f"/api/v1/wg/peers?node_id={node}",
                       headers={"X-Node-Psk": H.NODE_PSK})
        return st, {p["public_key"] for p in b.get("peers", [])}

    st_z, at_zur = peers_at("zur-01")
    st_b, at_buc = peers_at("buc-01")
    st_r, at_rey = peers_at("rey-01")
    check("manifest served", st_z == 200 and st_b == 200 and st_r == 200,
          (st_z, st_b, st_r))
    # The laptop is single-hop in zur; the phone is multi-hop zur -> buc, and
    # only the EXIT terminates its tunnel.
    check("single-hop laptop is routable at zur-01", pk_laptop in at_zur,
          f"zur={at_zur}")
    check("multi-hop phone reaches its EXIT node", pk_phone in at_buc,
          f"buc={at_buc}")
    check("the entry node never receives the multi-hop device's key",
          pk_phone not in at_zur, f"zur={at_zur}")
    check("the exit node does not receive the unrelated single-hop key",
          pk_laptop not in at_buc, f"buc={at_buc}")
    check("an uninvolved node receives nothing at all", not at_rey, at_rey)

    print("\n[7] converting to paid")
    st, inv = H.call("POST", "/api/v1/account/topup", {"months": 3},
                     headers={"X-Account-Token": token})
    check("trial account can open a top-up invoice", st == 200, f"{st} {inv}")
    before = H.call("GET", "/api/v1/account/status",
                    headers={"X-Account-Token": token})[1]["days_remaining"]
    H.settle(inv["invoice_id"])
    after = H.call("GET", "/api/v1/account/status",
                   headers={"X-Account-Token": token})[1]
    check("plan flips to paid", after.get("plan") == "paid", after)
    check("paid months stack on the trial remainder",
          after["days_remaining"] > before + 85, f"{before} -> {after['days_remaining']}")
    check("device cap rises to the paid limit", after.get("max_devices") == 8, after)
    st, third = H.call("POST", "/api/v1/wg/register",
                       {"pubkey": H.genkey(), "device_name": "third", "region": "zur"},
                       headers={"X-Account-Token": token})
    check("third device now allowed", st == 200, f"{st} {third}")

    print("\n[8] expiry")
    c = sqlite3.connect(DB)
    c.execute("UPDATE accounts SET expires_at=?, status='active' WHERE plan='paid'",
              (int(time.time()) - 10,))
    c.commit(); c.close()
    st, exp = H.call("POST", "/api/v1/wg/register",
                     {"pubkey": H.genkey(), "device_name": "x", "region": "zur"},
                     headers={"X-Account-Token": token})
    check("expired account cannot register", st == 402, f"{st} {exp}")
finally:
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
