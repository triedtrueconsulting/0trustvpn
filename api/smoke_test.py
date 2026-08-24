#!/usr/bin/env python3
"""
Control-plane smoke test.

Implements the live import test CLAUDE.md describes: point ZTV_DB_PATH at a
throwaway file, init_db(), seed mesh_nodes, then drive the API through
fastapi.testclient. No network, no BTCPay, no `wg` binary — the account row is
inserted directly so payment is out of the picture, and the client supplies its
own pubkey so nothing shells out to wireguard-tools.

Guards the invariants in CLAUDE.md that a parse check can't see: the snake_case
wire contract, X-Account-Token auth, entry != exit for multi-hop, the zur/rey/buc
region set, and that a multi-hop peer is keyed to the EXIT node's pubkey while
pointing at the ENTRY node's endpoint.

    ./api/smoke_test.py          # after .venv is on PATH
"""

import atexit, base64, os, shutil, sys, tempfile, time, hashlib

API_DIR = os.path.dirname(os.path.abspath(__file__))

tmp = tempfile.mkdtemp(prefix="0trust-smoke-")
# The database this creates is a full, unencrypted 0trust schema with real
# rows in it. Left behind, it is exactly the finding scripts/audit-verify.sh
# §8 looks for — produced by our own test run, on whatever box ran it.
atexit.register(shutil.rmtree, tmp, True)
os.environ["ZTV_DB_PATH"] = os.path.join(tmp, "0trust.db")
os.environ["NODE_API_PSK"] = "test-node-psk"
sys.path.insert(0, API_DIR)   # main.py imports btcpay by bare name

import main
from fastapi.testclient import TestClient

main.init_db()

NODES = [
    ("zur-01", "zur", "203.0.113.10"),
    ("rey-01", "rey", "203.0.113.20"),
    ("buc-01", "buc", "203.0.113.30"),
]
with main.db() as conn:
    for nid, region, ip in NODES:
        conn.execute(
            """INSERT INTO mesh_nodes
               (id, hostname, pubkey, endpoint, region, role, public_ip,
                capacity, active, ephemeral, last_heartbeat)
               VALUES (?,?,?,?,?,'both',?,1000,1,1,?)""",
            (nid, f"{nid}.0trustvpn.com",
             base64.b64encode(hashlib.sha256(nid.encode()).digest()).decode(),
             f"{ip}:51820", region, ip, int(time.time())),
        )
    token = main.generate_token()
    conn.execute(
        "INSERT INTO accounts (token_hash, created_at, expires_at, status) VALUES (?,?,?,'active')",
        (main.hash_token(token), int(time.time()), int(time.time()) + 30 * 86400),
    )

c = TestClient(main.app)
fails = []

def check(label, cond, detail=""):
    print(("  PASS  " if cond else "  FAIL  ") + label + ("" if cond else f"  <- {detail}"))
    if not cond:
        fails.append(label)

H = {"X-Account-Token": token}

r = c.get("/api/v1/health"); check("GET /health 200", r.status_code == 200, r.text)
check("health status ok", r.json().get("status") == "ok", r.text)

r = c.get("/api/v1/regions")
codes = [x["code"] for x in r.json()["regions"]]
check("GET /regions == [buc, rey, zur]", codes == ["buc", "rey", "zur"], codes)
names = {x["code"]: x["name"] for x in r.json()["regions"]}
check("region display names populated",
      names == {"zur": "Zurich, Switzerland", "rey": "Reykjavik, Iceland",
                "buc": "Bucharest, Romania"}, names)

r = c.get("/api/v1/account/status", headers=H)
check("GET /account/status 200", r.status_code == 200, r.text)
check("account active", r.json()["status"] == "active", r.text)

r = c.get("/api/v1/account/status", headers={"X-Account-Token": "BAD-BAD-BAD-BAD"})
check("bad token -> 401", r.status_code == 401, r.text)

pub = base64.b64encode(b"\x01" * 32).decode()
r = c.post("/api/v1/wg/register", headers=H,
           json={"pubkey": pub, "device_name": "laptop", "region": "zur"})
check("single-hop register 200", r.status_code == 200, r.text)
if r.status_code == 200:
    b = r.json()
    check("single-hop multihop=false", b["multihop"] is False, b)
    check("single-hop has peers", len(b["peers"]) > 0, b)
    check("interface_ip in mesh range",
          b["interface_ip"].startswith("10."), b["interface_ip"])
    check("wire format is snake_case",
          all(k in b["peers"][0] for k in ("public_key", "allowed_ips", "persistent_keepalive")),
          list(b["peers"][0]))

pub2 = base64.b64encode(b"\x02" * 32).decode()
r = c.post("/api/v1/wg/register", headers=H,
           json={"pubkey": pub2, "device_name": "phone",
                 "region": "zur", "exit_region": "buc"})
check("multi-hop register 200", r.status_code == 200, r.text)
if r.status_code == 200:
    b = r.json()
    check("multihop=true", b["multihop"] is True, b)
    check("entry zur / exit buc",
          b["entry_node"].startswith("zur") and b["exit_node"].startswith("buc"), b)
    check("multi-hop peer keyed to EXIT pubkey",
          b["peers"][0]["public_key"] ==
          base64.b64encode(hashlib.sha256(b"buc-01").digest()).decode(), b)
    check("endpoint is ENTRY public ip",
          b["peers"][0]["endpoint"].startswith("203.0.113.10:"), b)
    check("multi-hop pair has expiry", isinstance(b["expires_at"], int), b)

pub3 = base64.b64encode(b"\x03" * 32).decode()
r = c.post("/api/v1/wg/register", headers=H,
           json={"pubkey": pub3, "device_name": "x", "region": "zur", "exit_region": "zur"})
check("entry == exit rejected (400)", r.status_code == 400, r.text)

r = c.post("/api/v1/wg/register", headers=H,
           json={"pubkey": pub3, "device_name": "x", "region": "ams"})
check("stale region 'ams' rejected (400)", r.status_code == 400, r.text)

r = c.post("/api/v1/wg/rotate", headers=H,
           json={"pubkey": pub2, "device_name": "phone",
                 "region": "rey", "exit_region": "buc"})
check("rotate 200", r.status_code == 200, r.text)
if r.status_code == 200:
    check("rotate moved entry to rey", r.json()["entry_node"].startswith("rey"), r.json())

r = c.get("/api/v1/wg/peers?node_id=zur-01", headers={"X-Node-Psk": "test-node-psk"})
check("GET /wg/peers with node PSK 200", r.status_code == 200, r.text)
r = c.get("/api/v1/wg/peers?node_id=zur-01", headers={"X-Node-Psk": "wrong"})
check("bad node PSK -> 401", r.status_code == 401, r.text)

r = c.get("/api/v1/status/public")
check("GET /status/public 200", r.status_code == 200, r.text)

print()
if fails:
    print(f"SMOKE FAILED: {len(fails)} check(s): {fails}")
    sys.exit(1)
print("API SMOKE: all checks passed")
