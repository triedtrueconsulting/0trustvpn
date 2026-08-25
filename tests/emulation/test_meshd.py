#!/usr/bin/env python3
"""Run the REAL meshd against the live control plane with stubbed wg/nft/ip."""
import os, shutil, signal, sqlite3, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

def wait_for(pred, timeout=25, interval=0.4):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if pred(): return True
        except Exception: pass
        time.sleep(interval)
    return False

EMU = os.path.dirname(os.path.abspath(__file__))
TMP = H.tempdir("0trust-meshd-"); DB = os.path.join(TMP, "0trust.db")
sys.path.insert(0, os.path.join(H.REPO, "api"))
os.environ["ZTV_DB_PATH"] = DB
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=2)

os.makedirs(f"{TMP}/wg", exist_ok=True)
open(f"{TMP}/wg/wg0.key", "w").write("QFVwUE5RZUt5MFFRbHFHZm5hNXlZbGN3TUE9PQ==\n")

MESH_ENV = {
    **os.environ,
    "PATH": os.path.join(EMU, "bin") + ":" + os.environ["PATH"],
    "STUB_LOG": f"{TMP}/stub.log", "STUB_STATE": TMP,
    "CONTROL_URL": H.API, "NODE_API_PSK": H.NODE_PSK,
    "NODE_ID": "zur-01", "NODE_ROLE": "both",
    "WG_PRIVKEY": f"{TMP}/wg/wg0.key",
    "POLL_INTERVAL": "1",
}
proc = None
try:
    print("[1] meshd boots and syncs")
    proc = subprocess.Popen([sys.executable, os.path.join(H.REPO, "wireguard", "0trust-meshd.py")],
                            env=MESH_ENV, stdout=open(f"{TMP}/meshd.log", "w"),
                            stderr=subprocess.STDOUT)
    def log(): return open(f"{TMP}/meshd.log").read()
    check("meshd starts without crashing",
          wait_for(lambda: "starting meshd" in log()), log())
    check("brings up the wg interface",
          wait_for(lambda: os.path.exists(f"{TMP}/iface-wg0.exists")), log())
    check("no sync errors on a healthy control plane",
          wait_for(lambda: "synced" in log()) and "sync failed" not in log(), log())

    print("\n[2] a new customer device propagates to the exit node")
    tok, _ = H.paid_account()
    pk = H.genkey()
    st, r = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": pk, "device_name": "laptop", "region": "zur"},
                   headers={"X-Account-Token": tok})
    check("register 200", st == 200, f"{st} {r}")
    synced = f"{TMP}/wg-synced-wg0.conf"
    check("meshd pushed the new peer into wg",
          wait_for(lambda: os.path.exists(synced) and pk in open(synced).read()),
          (open(synced).read()[:400] if os.path.exists(synced) else "no synced conf"))

    print("\n[3] a multi-hop session becomes a DNAT rule on the entry node")
    tok2, _ = H.paid_account()
    st, m = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": H.genkey(), "device_name": "phone",
                    "region": "zur", "exit_region": "buc"},
                   headers={"X-Account-Token": tok2})
    check("multi-hop register 200", st == 200, f"{st} {m}")
    port = m["peers"][0]["endpoint"].split(":")[1]
    rules = f"{TMP}/nft-ruleset.nft"
    check("meshd installed the DNAT rule for the allocated port",
          wait_for(lambda: os.path.exists(rules) and f"dport {port}" in open(rules).read()),
          (open(rules).read()[:500] if os.path.exists(rules) else "no ruleset"))
    ruleset = open(rules).read() if os.path.exists(rules) else ""
    check("DNAT targets the exit node's endpoint",
          "203.0.113.30:51820" in ruleset, ruleset[:500])
    check("masquerade matches the DNAT'd flows, not a stale port range",
          "ct status dnat masquerade" in ruleset, ruleset[:500])

    print("\n[4] heartbeat reaches the control plane")
    # Backdate first, so a pass can only come from a real heartbeat landing
    # rather than from the value seed_nodes wrote at setup time.
    c = sqlite3.connect(DB)
    c.execute("UPDATE mesh_nodes SET last_heartbeat = 1 WHERE id='zur-01'")
    c.commit(); c.close()
    def hb_now():
        c = sqlite3.connect(DB)
        v = c.execute("SELECT last_heartbeat FROM mesh_nodes WHERE id='zur-01'").fetchone()[0]
        c.close(); return v
    check("static node (shared PSK) heartbeat is actually recorded",
          wait_for(lambda: hb_now() > 1, timeout=20), f"last_heartbeat={hb_now()}")
    check("no heartbeat failures logged", "heartbeat failed" not in log(), log()[-400:])

    print("\n[5] revoking a customer withdraws the peer")
    st, _ = H.call("DELETE", f"/api/v1/devices/{pk.replace('/', '%2F').replace('+', '%2B')}",
                   headers={"X-Account-Token": tok})
    check("device deleted via API", st == 200, st)
    check("meshd removed the peer from wg",
          wait_for(lambda: pk not in open(synced).read(), timeout=20),
          open(synced).read()[:400])

    print("\n[6] meshd survives the control plane going away")
    H.shutdown()
    time.sleep(3)
    check("meshd logs the failure and keeps running",
          proc.poll() is None and "sync failed" in log(), log()[-500:])
finally:
    if proc and proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try: proc.wait(timeout=6)
        except Exception: proc.kill()
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
