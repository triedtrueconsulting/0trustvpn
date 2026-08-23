#!/usr/bin/env python3
"""Probe 3: GUI polling pressure, pubkey escaping, rate-limit shape."""
import base64, json, os, re, shutil, subprocess, sys, tempfile, time, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

EMU = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="0trust-p3-"); DB = os.path.join(TMP, "0trust.db")
HOME = os.path.join(TMP, "home"); os.makedirs(HOME)
BIN = os.path.join(TMP, "0trust")
sys.path.insert(0, os.path.join(H.REPO, "api"))
os.environ["ZTV_DB_PATH"] = DB
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
subprocess.run(["go", "build", "-o", BIN, "./cmd/0trust"], cwd=os.path.join(H.REPO, "client"),
               check=True, env={**os.environ, "CGO_ENABLED": "0"})
H.boot(DB, workers=2, log_level="info")   # access logs, to count upstream calls
gui = None
try:
    print("[1] pubkeys containing '/' and '+' survive the DELETE path")
    tok, _ = H.paid_account()
    # force a key with both awkward characters
    raw = bytearray(os.urandom(32)); raw[0] = 0xFF; raw[1] = 0xFF; raw[2] = 0xFE
    pk = base64.b64encode(bytes(raw)).decode()
    while "/" not in pk or "+" not in pk:
        pk = base64.b64encode(os.urandom(32)).decode()
    st, _ = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": pk, "device_name": "slashy", "region": "zur"},
                   headers={"X-Account-Token": tok})
    check("register a key containing / and +", st == 200, st)
    st, dl = H.call("GET", "/api/v1/devices", headers={"X-Account-Token": tok})
    check("it appears in the device list",
          st == 200 and any(d["pubkey"] == pk for d in dl), dl)
    # delete it through the real Go client, which does the escaping
    cli_env = {**os.environ, "HOME": HOME,
               "XDG_CONFIG_HOME": os.path.join(HOME, ".config"),
               "ZTV_API_BASE": H.API,
               "PATH": os.path.join(EMU, "bin") + ":" + os.environ["PATH"],
               "STUB_LOG": f"{TMP}/stub.log", "STUB_STATE": TMP}
    subprocess.run([BIN, "login"], input=tok + "\n", text=True,
                   env=cli_env, capture_output=True, timeout=30)
    r = subprocess.run([BIN, "remove", pk], env=cli_env, capture_output=True,
                       text=True, timeout=30)
    check("client can delete a key containing / and +",
          r.returncode == 0, (r.stdout + r.stderr))
    st, dl2 = H.call("GET", "/api/v1/devices", headers={"X-Account-Token": tok})
    check("it is gone", all(d["pubkey"] != pk for d in dl2), dl2)

    print("\n[2] GUI does not hammer the API on every 3s poll")
    log = os.path.join(H.RUN, "api.log")
    gui_env = {**cli_env, "ZTV_GUI_PORT": "51827"}
    gui = subprocess.Popen([BIN, "gui", "--no-browser"], env=gui_env,
                           stdout=open(f"{TMP}/gui.log", "w"), stderr=subprocess.STDOUT)
    time.sleep(2.5)
    def gui_state():
        with urllib.request.urlopen("http://127.0.0.1:51827/api/state", timeout=10) as r:
            return json.loads(r.read())
    before = len(re.findall(r"/api/v1/account/status", open(log).read()))
    v = None
    for _ in range(12):            # 12 polls == ~36s of real GUI polling
        v = gui_state()
    after = len(re.findall(r"/api/v1/account/status", open(log).read()))
    upstream = after - before
    check("12 GUI polls cause at most 1 upstream status call",
          upstream <= 1, f"{upstream} upstream calls for 12 polls")
    check("GUI still reports the subscription",
          v and v.get("status") == "active", v)
    v2 = gui_state()
    check("GUI reports tunnel state locally each poll", "tunnel_up" in v2, v2)
finally:
    if gui and gui.poll() is None:
        gui.terminate()
        try: gui.wait(timeout=5)
        except Exception: gui.kill()
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
