#!/usr/bin/env python3
"""Shared harness: boots fake BTCPay + the real API, seeds nodes, mints tokens."""
import hashlib, hmac, json, os, signal, socket, subprocess, sys, time, urllib.error, urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EMU  = os.path.dirname(os.path.abspath(__file__))
RUN  = os.path.join(EMU, "run")

API_PORT     = 8099
BTCPAY_PORT  = 8098
API          = f"http://127.0.0.1:{API_PORT}"
WEBHOOK_SEC  = "test-webhook-secret"
NODE_PSK     = "global-node-psk"

_procs = []


def free_port_wait(port, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.15)
    return False


def env_for_api(db):
    e = dict(os.environ)
    e.update(
        ZTV_DB_PATH=db,
        BTCPAY_URL=f"http://127.0.0.1:{BTCPAY_PORT}",
        BTCPAY_STORE_ID="store1",
        BTCPAY_API_KEY="key1",
        BTCPAY_WEBHOOK_SECRET=WEBHOOK_SEC,
        NODE_API_PSK=NODE_PSK,
        PYTHONUNBUFFERED="1",
    )
    return e


def boot(db, workers=1, log_level="warning"):
    os.makedirs(RUN, exist_ok=True)
    e = env_for_api(db)
    e["CONTROL_URL"] = API
    py = sys.executable
    bt = subprocess.Popen([py, os.path.join(EMU, "fake_btcpay.py"), str(BTCPAY_PORT)],
                          env=e, stdout=open(f"{RUN}/btcpay.log", "w"), stderr=subprocess.STDOUT)
    _procs.append(bt)
    api = subprocess.Popen(
        [py, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
         "--port", str(API_PORT), "--workers", str(workers), "--log-level", log_level],
        cwd=os.path.join(REPO, "api"), env=e,
        stdout=open(f"{RUN}/api.log", "w"), stderr=subprocess.STDOUT)
    _procs.append(api)
    if not free_port_wait(BTCPAY_PORT) or not free_port_wait(API_PORT):
        dump_logs(); raise SystemExit("stack failed to boot")
    return api, bt


def shutdown():
    for p in _procs:
        try:
            p.send_signal(signal.SIGTERM); p.wait(timeout=8)
        except Exception:
            try: p.kill()
            except Exception: pass
    _procs.clear()


def dump_logs():
    for n in ("api", "btcpay"):
        p = f"{RUN}/{n}.log"
        if os.path.exists(p):
            print(f"--- {n}.log ---"); print(open(p).read()[-3000:])


# --------------------------------------------------------------- HTTP helpers
def call(method, path, body=None, headers=None, base=None):
    url = (base or API) + path
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try: return e.code, json.loads(raw)
        except Exception: return e.code, {"raw": raw.decode("utf-8", "replace")[:600]}
    except urllib.error.URLError as e:
        return 0, {"error": str(e)}


def settle(invoice_id, event_type="InvoiceSettled"):
    payload = json.dumps({"type": event_type, "invoiceId": invoice_id,
                          "timestamp": int(time.time())}).encode()
    sig = "sha256=" + hmac.new(WEBHOOK_SEC.encode(), payload, hashlib.sha256).hexdigest()
    req = urllib.request.Request(f"{API}/api/v1/payment/webhook", data=payload,
                                 method="POST",
                                 headers={"Content-Type": "application/json", "BTCPay-Sig": sig})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {"raw": e.read().decode("utf-8", "replace")[:400]}


# --------------------------------------------------------------- DB seeding
import base64, sqlite3


def seed_nodes(db, spec=None):
    """spec: list of (id, region, role, public_ip). Default = the locked topology."""
    spec = spec or [("zur-01", "zur", "both", "203.0.113.10"),
                    ("rey-01", "rey", "both", "203.0.113.20"),
                    ("buc-01", "buc", "both", "203.0.113.30")]
    c = sqlite3.connect(db); c.execute("PRAGMA foreign_keys=ON")
    for nid, region, role, ip in spec:
        c.execute(
            """INSERT OR REPLACE INTO mesh_nodes
               (id, hostname, pubkey, endpoint, region, role, public_ip,
                capacity, active, ephemeral, last_heartbeat)
               VALUES (?,?,?,?,?,?,?,1000,1,0,?)""",
            (nid, f"{nid}.0trustvpn.com",
             base64.b64encode(hashlib.sha256(nid.encode()).digest()).decode(),
             f"{ip}:51820", region, role, ip, int(time.time())))
    c.commit(); c.close()
    return spec


def mint_provision_token(db, region, role="both", ttl=3600):
    tok = "prov-" + base64.b32encode(os.urandom(10)).decode().strip("=").lower()
    c = sqlite3.connect(db)
    c.execute("""INSERT INTO provision_tokens (token_hash, region, role, created_at, expires_at)
                 VALUES (?,?,?,?,?)""",
              (hashlib.sha256(tok.encode()).hexdigest(), region, role,
               int(time.time()), int(time.time()) + ttl))
    c.commit(); c.close()
    return tok


def genkey():
    """A syntactically valid 44-char base64 WireGuard pubkey."""
    return base64.b64encode(os.urandom(32)).decode()


def paid_account(months=1):
    """Full signup: create account -> settle invoice -> return an active token."""
    st, b = call("POST", "/api/v1/account", {"months": months})
    assert st == 200, (st, b)
    settle(b["invoice_id"])
    return b["token"], b["invoice_id"]
