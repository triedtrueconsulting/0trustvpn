#!/usr/bin/env python3
"""
Adversarial probe: try to break the authorization boundaries.

Every case here is an attack someone would actually try — forging a
proof-of-work challenge, reaching another account's devices, crediting a
subscription from someone else's invoice, getting SQL through a region code.
Passing means the boundary held, not that it was never tested.
"""
import base64, hashlib, json, os, shutil, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

def solve(nonce, bits):
    wb, rb = divmod(bits, 8)
    i = 0
    while True:
        d = hashlib.sha256(f"{nonce}:{i}".encode()).digest()
        if not any(d[k] for k in range(wb)) and (not rb or not d[wb] >> (8 - rb)):
            return str(i)
        i += 1

TMP = H.tempdir("sec-"); DB = os.path.join(TMP, "0trust.db")
os.environ.update(ZTV_DB_PATH=DB, ZTV_TRIAL_SECRET="sec-secret",
                  ZTV_TRIAL_POW_BITS="10", ZTV_TRIAL_MAX_DEVICES="2")
sys.path.insert(0, os.path.join(H.REPO, "api"))
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=2)

try:
    print("[trial] forging around the proof of work")
    st, ch = H.call("GET", "/api/v1/trial/challenge")
    # Extend the expiry to buy unlimited time, keeping the original signature.
    st1, r1 = H.call("POST", "/api/v1/trial", {
        "nonce": ch["nonce"], "expires_at": ch["expires_at"] + 86400,
        "signature": ch["signature"], "solution": solve(ch["nonce"], 10)})
    check("cannot extend a challenge's expiry (signature covers it)", st1 == 400, f"{st1} {r1}")

    # Swap in a nonce that is easier to solve, keeping a real signature.
    st2, r2 = H.call("POST", "/api/v1/trial", {
        "nonce": "0" * 32, "expires_at": ch["expires_at"],
        "signature": ch["signature"], "solution": solve("0" * 32, 10)})
    check("cannot substitute the nonce", st2 == 400, f"{st2} {r2}")

    # A solution for a DIFFERENT nonce.
    st3, ch3 = H.call("GET", "/api/v1/trial/challenge")
    st4, r4 = H.call("POST", "/api/v1/trial", {
        "nonce": ch3["nonce"], "expires_at": ch3["expires_at"],
        "signature": ch3["signature"], "solution": solve("unrelated", 10)})
    check("a solution for another nonce is rejected", st4 == 400, f"{st4} {r4}")

    # Enormous solution string -> the field is length-capped.
    st5, r5 = H.call("POST", "/api/v1/trial", {
        "nonce": ch3["nonce"], "expires_at": ch3["expires_at"],
        "signature": ch3["signature"], "solution": "A" * 100000})
    check("over-long solution rejected without work", st5 in (400, 422), st5)

    print("\n[devices] cross-account access")
    tokA, _ = H.paid_account()
    tokB, _ = H.paid_account()
    pkA = H.genkey()
    H.call("POST", "/api/v1/wg/register",
           {"pubkey": pkA, "device_name": "a", "region": "zur"},
           headers={"X-Account-Token": tokA})
    st, devsB = H.call("GET", "/api/v1/devices", headers={"X-Account-Token": tokB})
    check("B cannot see A's devices", st == 200 and not devsB, devsB)
    st, r = H.call("DELETE", f"/api/v1/devices/{pkA.replace('/','%2F').replace('+','%2B')}",
                   headers={"X-Account-Token": tokB})
    check("B cannot delete A's device", st == 404, f"{st} {r}")
    st, devsA = H.call("GET", "/api/v1/devices", headers={"X-Account-Token": tokA})
    check("A's device survived", any(d["pubkey"] == pkA for d in devsA), devsA)
    st, r = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": pkA, "device_name": "steal", "region": "zur"},
                   headers={"X-Account-Token": tokB})
    check("B cannot hijack A's pubkey", st == 409, f"{st} {r}")
    st, r = H.call("POST", "/api/v1/wg/rotate", {"pubkey": pkA, "region": "rey"},
                   headers={"X-Account-Token": tokB})
    check("B cannot rotate A's device", st == 404, f"{st} {r}")

    print("\n[payments] invoice binding")
    st, acct = H.call("POST", "/api/v1/account", {"months": 1})
    # Settling someone else's invoice must credit THAT account, not the caller's.
    H.settle(acct["invoice_id"])
    st, sA = H.call("GET", "/api/v1/account/status", headers={"X-Account-Token": tokA})
    check("settling an unrelated invoice does not credit another account",
          sA["days_remaining"] <= 31, sA)
    st, r = H.call("POST", "/api/v1/account", {"months": 999})
    check("unpriced month count rejected", st == 422, st)
    st, r = H.call("POST", "/api/v1/account", {"months": -1})
    check("negative months rejected", st == 422, st)

    print("\n[peer manifest] a node sees only what it routes")
    # One node's PSK used to be enough to enumerate every customer, which is
    # not compatible with "a seized node reveals nothing operational".
    tokC, _ = H.paid_account()
    pk_single = H.genkey()
    H.call("POST", "/api/v1/wg/register",
           {"pubkey": pk_single, "device_name": "s", "region": "zur"},
           headers={"X-Account-Token": tokC})
    pk_multi = H.genkey()
    H.call("POST", "/api/v1/wg/register",
           {"pubkey": pk_multi, "device_name": "m", "region": "zur",
            "exit_region": "buc"},
           headers={"X-Account-Token": tokC})

    def at(node):
        st, b = H.call("GET", f"/api/v1/wg/peers?node_id={node}",
                       headers={"X-Node-Psk": H.NODE_PSK})
        return st, {p["public_key"] for p in b.get("peers", [])}

    _, zur = at("zur-01")
    _, buc = at("buc-01")
    _, rey = at("rey-01")
    check("a node cannot enumerate the whole customer base",
          not (pk_single in buc and pk_multi in buc), f"buc={buc}")
    check("the exit of a multi-hop session gets that key", pk_multi in buc, buc)
    check("the entry of a multi-hop session does not", pk_multi not in zur, zur)
    check("an uninvolved node gets nothing", not rey, rey)

    st, r = H.call("GET", "/api/v1/wg/peers", headers={"X-Node-Psk": H.NODE_PSK})
    check("an unidentified node is refused rather than served everything",
          st == 400, f"{st} {r}")

    print("\n[input] hostile field values")
    long_name = "x" * 100000
    st, r = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": H.genkey(), "device_name": long_name, "region": "zur"},
                   headers={"X-Account-Token": tokA})
    check("over-long device name rejected", st == 422, st)
    st, r = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": "short", "device_name": "d", "region": "zur"},
                   headers={"X-Account-Token": tokA})
    check("malformed pubkey rejected", st == 422, st)
    st, r = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": H.genkey(), "device_name": "d",
                    "region": "zur'; DROP TABLE accounts;--"},
                   headers={"X-Account-Token": tokA})
    check("SQL metacharacters in region are rejected, not executed",
          st == 400, f"{st} {r}")
    st, chk = H.call("GET", "/api/v1/regions")
    check("accounts table still exists after that", st == 200 and chk["regions"], chk)
finally:
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
