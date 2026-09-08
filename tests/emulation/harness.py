#!/usr/bin/env python3
"""Shared harness: boots fake BTCPay + the real API, seeds nodes, mints tokens."""
import atexit, hashlib, hmac, json, os, shutil, signal, socket, subprocess, sys, tempfile, time, urllib.error, urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EMU  = os.path.dirname(os.path.abspath(__file__))
RUN  = os.path.join(EMU, "run")

def tempdir(prefix: str) -> str:
    """A scratch directory that does not outlive the run.

    Every module used to call tempfile.mkdtemp() and never clean up, so each
    run left an unencrypted copy of a 0trust database in /tmp — schema, account
    rows, device pubkeys — permanently. scripts/audit-verify.sh looks for
    exactly that and is right to. Set ZTV_KEEP_TMP=1 to keep them when you need
    to pick through the wreckage of a failing run.
    """
    def _force_rm(path):
        # git object files land at mode 444, and rmtree(ignore_errors=True)
        # silently gives up on them and leaves the tree behind. Any module that
        # clones the repo would keep leaking.
        def onerror(fn, target, exc):
            try:
                os.chmod(target, 0o700)
                fn(target)
            except OSError:
                pass
        shutil.rmtree(path, onerror=onerror)

    path = tempfile.mkdtemp(prefix=prefix)
    if not os.environ.get("ZTV_KEEP_TMP"):
        atexit.register(_force_rm, path)
    return path


def pick_port() -> int:
    """
    An unused port, chosen by the kernel.

    Fixed ports made modules interfere: whatever was still listening from an
    adjacent module answered the next one's requests, and the suite failed
    intermittently in a way that looked like a product bug. Asking for :0 and
    reading back what we got removes the class entirely.
    """
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


API_PORT     = pick_port()
BTCPAY_PORT  = pick_port()
API          = f"http://127.0.0.1:{API_PORT}"

# The fake BTCPay / gateway / card servers read CONTROL_URL at import time to
# learn where the control plane is. Set it here, before any test imports them
# in-process, so a signed callback fired from the test process reaches the API
# we actually booted. With fixed ports this worked by accident; with kernel-
# chosen ones the stale default is simply a refused connection.
os.environ["CONTROL_URL"] = API
WEBHOOK_SEC  = "test-webhook-secret"
NODE_PSK     = "global-node-psk"

_procs = []


def free_port_wait(port, timeout=25, proc=None):
    """
    Wait for something to listen on `port`.

    Pass `proc` and it also fails fast if that process died — otherwise a
    server that crashed on startup shows up as a 25-second hang followed by a
    confusing downstream error.
    """
    end = time.time() + timeout
    while time.time() < end:
        if proc is not None and proc.poll() is not None:
            return False
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.15)
    return False


def env_for_api(db):
    e = dict(os.environ)
    e.update(
        ZTV_DB_PATH=db,
        # Say which provider this stack is, rather than inheriting whatever
        # the code falls back to. Most modules here drive the fake BTCPay, and
        # they got it only because "btcpay" happened to be the code's default;
        # when that default moved to `watch` — which is what install.sh has
        # always written — fifteen modules failed at once on a 502. A test
        # stack that depends on an unstated default is testing the default.
        # Modules that want another provider still override through
        # env_extra, which is applied after this.
        ZTV_PAYMENT_PROVIDER="btcpay",
        BTCPAY_URL=f"http://127.0.0.1:{BTCPAY_PORT}",
        BTCPAY_STORE_ID="store1",
        BTCPAY_API_KEY="key1",
        BTCPAY_WEBHOOK_SECRET=WEBHOOK_SEC,
        NODE_API_PSK=NODE_PSK,
        PYTHONUNBUFFERED="1",
    )
    # Carry across payment/admin configuration a test has set on this process.
    for k, v in os.environ.items():
        if k.startswith(("ZTV_PAYMENT_", "STRIPE_", "SQUARE_", "ZTV_TRIAL_",
                         "ZTV_ADMIN_", "WALLET_", "NODE_RPC_")):
            e[k] = v
    return e


def boot(db, workers=1, log_level="warning", env_extra=None, access_log=False):
    os.makedirs(RUN, exist_ok=True)
    e = env_for_api(db)
    e["CONTROL_URL"] = API
    # Providers read their configuration from the environment, and the API
    # runs in its own process, so anything a test reconfigures has to be
    # handed across rather than set in this one.
    e.update({k: str(v) for k, v in (env_extra or {}).items()})
    py = sys.executable
    bt = subprocess.Popen([py, os.path.join(EMU, "fake_btcpay.py"), str(BTCPAY_PORT)],
                          env=e, stdout=open(f"{RUN}/btcpay.log", "w"), stderr=subprocess.STDOUT)
    _procs.append(bt)
    api = subprocess.Popen(
        # --no-access-log matches 0trust-api.service, and it is a privacy
        # control there: two routes carry a secret in the path, so uvicorn's
        # access line wrote a customer's device pubkey into the journal on
        # every DELETE. The default log_level="warning" here hid that for a
        # long time — the flag the product ships has to be the flag the tests
        # run against, or the suite is testing a configuration nobody deploys.
        # test_security.py boots without it on purpose, to prove the leak is
        # real and that the flag is what stops it.
        [py, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
         "--port", str(API_PORT), "--workers", str(workers),
         "--log-level", log_level]
        + ([] if access_log else ["--no-access-log"]),
        cwd=os.path.join(REPO, "api"), env=e,
        stdout=open(f"{RUN}/api.log", "w"), stderr=subprocess.STDOUT)
    _procs.append(api)
    if not free_port_wait(BTCPAY_PORT, proc=bt) or not free_port_wait(API_PORT, proc=api):
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


class SkipModule(Exception):
    """Prerequisites are genuinely absent. Caller exits 77."""


def launch_chromium(pw, **kw):
    """Launch a browser, or raise SkipModule if there genuinely is not one.

    Every browser module used to carry the same glob over /opt/pw-browsers and
    treat ANY launch failure as "no chromium, skip". That is wrong in a way
    that costs coverage silently: pinning a playwright version whose protocol
    did not match the preinstalled chromium turned four modules from passing to
    "skipped" in one commit, and a skipped module looks exactly like a module
    with nothing to say. Try the preinstalled browser, then playwright's own,
    and only skip when neither exists.
    """
    import glob as _glob
    attempts = []
    for cand in sorted(_glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome")):
        try:
            return pw.chromium.launch(executable_path=cand, **kw)
        except Exception as e:
            attempts.append(f"{cand}: {type(e).__name__}: {str(e)[:90]}")
    try:
        return pw.chromium.launch(**kw)
    except Exception as e:
        attempts.append(f"playwright's own browser: {type(e).__name__}: {str(e)[:90]}")
    raise SkipModule("no usable chromium:\n    " + "\n    ".join(attempts))


def account_zpub_from_mnemonic(mnemonic: str, account: int = 0) -> str:
    """
    m/84'/0'/<account>' as a zpub, derived from a BIP39 mnemonic.

    Private derivation, deliberately confined to the test harness: the product
    only ever holds a public key, and adding private-key code to it would
    create a thing worth stealing where none exists today.

    Lives here rather than in one test module because two modules need the
    BIP84 spec vector and the alternative — pasting an extended key from
    memory — is precisely the mistake scripts/check-wallet.sh exists to catch.
    A wrong constant in a test asserts nothing at all.

    `account` exists for the wrong-account paste: m/84'/0'/1' of the same
    seed is a valid zpub that derives addresses the operator can watch in
    their wallet and still cannot match to an invoice.
    """
    import sys as _sys
    _sys.path.insert(0, os.path.join(REPO, "api"))
    import chainwatch as cw

    seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048)
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(I[:32], "big"), I[32:]

    def ckd_priv(k, c, index):
        if index >= 0x80000000:
            data = b"\x00" + k.to_bytes(32, "big") + index.to_bytes(4, "big")
        else:
            data = cw._serialize(cw._point_mul(k)) + index.to_bytes(4, "big")
        I = hmac.new(c, data, hashlib.sha512).digest()
        return (int.from_bytes(I[:32], "big") + k) % cw.N, I[32:]

    H_ = 0x80000000
    for idx in (84 + H_, 0 + H_, account + H_):
        k, c = ckd_priv(k, c, idx)
    body = ((0x04B24746).to_bytes(4, "big") + bytes([3]) + b"\x00\x00\x00\x00"
            + (account + H_).to_bytes(4, "big") + c
            + cw._serialize(cw._point_mul(k)))
    chk = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    num, out = int.from_bytes(body + chk, "big"), ""
    while num:
        num, r = divmod(num, 58)
        out = cw._B58[r] + out
    return out


def genkey():
    """A syntactically valid 44-char base64 WireGuard pubkey."""
    return base64.b64encode(os.urandom(32)).decode()


def paid_account(months=1):
    """Full signup: create account -> settle invoice -> return an active token."""
    st, b = call("POST", "/api/v1/account", {"months": months})
    assert st == 200, (st, b)
    settle(b["invoice_id"])
    return b["token"], b["invoice_id"]
