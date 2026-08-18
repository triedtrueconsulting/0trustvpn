#!/usr/bin/env python3
"""Drive the REAL compiled 0trust binary against the live stack."""
import json, os, shutil, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

EMU  = os.path.dirname(os.path.abspath(__file__))
TMP  = tempfile.mkdtemp(prefix="0trust-cli-")
DB   = os.path.join(TMP, "0trust.db")
HOME = os.path.join(TMP, "home"); os.makedirs(HOME)
BIN  = os.path.join(TMP, "0trust")

sys.path.insert(0, os.path.join(H.REPO, "api"))
os.environ["ZTV_DB_PATH"] = DB
import main as api_main; api_main.init_db()
H.seed_nodes(DB)

subprocess.run(["go", "build", "-o", BIN, "./cmd/0trust"],
               cwd=os.path.join(H.REPO, "client"), check=True,
               env={**os.environ, "CGO_ENABLED": "0"})
H.boot(DB, workers=2)

CLI_ENV = {
    **os.environ,
    "HOME": HOME,
    "XDG_CONFIG_HOME": os.path.join(HOME, ".config"),
    "ZTV_API_BASE": H.API,
    "PATH": os.path.join(EMU, "bin") + ":" + os.environ["PATH"],
    "STUB_LOG": os.path.join(TMP, "stub.log"),
    "STUB_STATE": TMP,
    "WG_CONFIG_DIR": TMP,
}

def cli(*args, stdin=None):
    r = subprocess.run([BIN, *args], env=CLI_ENV, capture_output=True,
                       text=True, input=stdin, timeout=60)
    return r.returncode, (r.stdout + r.stderr)

try:
    print("[1] login / status")
    token, _ = H.paid_account(3)
    rc, out = cli("login", stdin=token + "\n")
    check("login accepts the token", rc == 0, out)
    rc, out = cli("status")
    check("status shows active subscription", rc == 0 and "active" in out, out)
    check("status shows days remaining", "89" in out or "90" in out or "days" in out, out)

    print("\n[2] regions")
    rc, out = cli("regions")
    check("regions lists zur/rey/buc",
          rc == 0 and all(r in out for r in ("zur", "rey", "buc")), out)

    print("\n[3] connect (single-hop) — the real binary, stubbed netlink")
    rc, out = cli("connect", "zur")
    check("first connect succeeds", rc == 0, out)
    check("wrote a wg config", "config written" in out, out)

    print("\n[4] SECOND connect — the bug that used to 500")
    rc2, out2 = cli("connect", "zur")
    check("second connect succeeds", rc2 == 0, out2)
    check("second connect is not an api 500", "api 500" not in out2, out2)

    print("\n[5] multi-hop connect + rotate")
    rc, out = cli("connect", "zur", "--exit", "buc")
    check("multi-hop connect succeeds", rc == 0, out)
    check("reports entry and exit nodes",
          "entry=zur" in out and "exit=buc" in out, out)
    rc, out = cli("rotate")
    check("rotate succeeds", rc == 0, out)

    print("\n[6] devices / remove (new commands)")
    rc, out = cli("devices")
    check("devices lists this device", rc == 0 and "* " in out, out)
    check("device slot count shown", "of 8 device slots" in out, out)
    rc, out = cli("remove", "this")
    check("remove this device succeeds", rc == 0 and "removed" in out, out)
    rc, out = cli("devices")
    check("device list now empty", rc == 0 and "no devices" in out, out)
    rc, out = cli("connect", "zur")
    check("can reconnect after removal (fresh key)", rc == 0, out)

    print("\n[7] export for mobile")
    rc, out = cli("export", "--exit", "buc", "--name", "phone", "--out", TMP)
    check("export succeeds", rc == 0, out)
    check("wrote a .conf", os.path.exists(os.path.join(TMP, "phone.conf")), os.listdir(TMP))
    if os.path.exists(os.path.join(TMP, "phone.conf")):
        conf = open(os.path.join(TMP, "phone.conf")).read()
        check("conf has Interface + Peer", "[Interface]" in conf and "[Peer]" in conf, conf[:300])
        check("conf carries a private key", "PrivateKey" in conf, conf[:300])

    print("\n[8] disconnect / logout")
    rc, out = cli("disconnect")
    check("disconnect succeeds", rc == 0, out)
    rc, out = cli("logout")
    check("logout succeeds", rc == 0, out)
    rc, out = cli("status")
    check("status after logout tells you to log in",
          "not logged in" in out.lower(), out)

    print("\n[9] error paths")
    rc, out = cli("login", stdin="AAAA-BBBB-CCCC-DDDD\n")
    check("bogus token rejected at login", rc != 0 or "401" in out or "Invalid" in out, out)
finally:
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
