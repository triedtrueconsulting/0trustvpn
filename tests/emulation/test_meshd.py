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

    print("\n[7] a malformed peer is skipped, not fatal to the whole sync")
    # Load the real daemon's config builder directly. `wg syncconf` is atomic
    # and meshd runs it with check=True, so before this guard a single bad
    # [Peer] block failed the sync for every customer on the node. The control
    # plane validates keys at ingest now; this is the belt to that braces.
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "meshd_mod", os.path.join(H.REPO, "wireguard", "0trust-meshd.py"))
    meshd = importlib.util.module_from_spec(spec)
    # meshd reads these at import time.
    os.environ.setdefault("CONTROL_URL", "http://127.0.0.1:1")
    os.environ.setdefault("NODE_API_PSK", "x")
    os.environ.setdefault("NODE_ID", "test")
    # WG_PRIV is read at build time; point it at a temp file with a real key.
    import base64 as _b64
    keyfile = os.path.join(TMP, "priv.key")
    open(keyfile, "w").write(_b64.b64encode(b"k" * 32).decode())
    try:
        spec.loader.exec_module(meshd)
        meshd.WG_PRIV = __import__("pathlib").Path(keyfile)
        good = _b64.b64encode(b"g" * 32).decode()
        cfg = meshd.build_wg_config([
            {"public_key": good, "allowed_ips": "10.64.0.5/32"},
            {"public_key": "AAAA=\nListenPort=1" + "A" * 27, "allowed_ips": "10.64.0.6/32"},
            {"public_key": "not-base64-at-all-" + "A" * 26 + "=", "allowed_ips": "10.64.0.7/32"},
        ])
        check("the good peer is in the config", good in cfg, cfg)
        check("the two malformed peers are dropped",
              cfg.count("[Peer]") == 1, cfg)
        check("no injected directive survived",
              "ListenPort = 1" not in cfg and cfg.count("ListenPort") == 1, cfg)

        # A peer's AllowedIPs is never installed as a route blindly: _in_mesh
        # only accepts prefixes inside the mesh network, so a compromised or
        # hostile peer cannot make the node route 0.0.0.0/0, ::/0 or another
        # customer's LAN toward itself. This is the Phase 11/12 protection —
        # arbitrary client-advertised routes are refused by construction.
        check("a mesh /32 is accepted as a route", meshd._in_mesh("10.64.0.9/32"))
        check("a mesh v6 /128 is accepted", meshd._in_mesh(
            meshd.mesh_ip6("10.64.0.9") + "/128") if hasattr(meshd, "mesh_ip6")
            else meshd._in_mesh("fd0e:5f7a:c21b::a40:9/128"))
        for hostile in ("0.0.0.0/0", "::/0", "192.168.1.0/24", "8.8.8.8/32",
                        "10.0.0.0/8"):
            check(f"a route outside the mesh is refused: {hostile}",
                  not meshd._in_mesh(hostile))
        check("a malformed CIDR is refused, not crashed on",
              not meshd._in_mesh("not-a-cidr") and not meshd._in_mesh("10.64.0.0/999"))
    except Exception as e:
        check("build_wg_config skip guard", False, f"{type(e).__name__}: {e}")

    print("\n[8] the control channel can run through SOCKS5, and never falls back")
    # Jitter hides the CADENCE of the check-in; it does nothing about the
    # DESTINATION. Every node connecting to the same control-plane address is
    # what lets an observer of two nodes' uplinks group them into one system.
    # ZTV_CONTROL_PROXY sends the check-in through Tor instead. Two properties
    # matter and both are asserted here: the hostname is resolved BY THE PROXY
    # (a .onion has no DNS entry, so local resolution is not merely a leak but
    # a failure), and a dead proxy does NOT silently revert to a direct
    # connection — that would restore the signal exactly when someone was
    # interfering with Tor, and nothing would say so.
    import socket as _sock, threading as _thr, http.server as _hs
    asked = []

    def _socks5(port):
        srv = _sock.socket(); srv.setsockopt(_sock.SOL_SOCKET, _sock.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port)); srv.listen(8)
        def handle(c):
            try:
                n = c.recv(2)[1]; c.recv(n); c.sendall(b"\x05\x00")
                hdr = c.recv(4)
                if hdr[3] != 0x03:
                    asked.append(f"WRONG-ATYP-{hdr[3]}"); c.close(); return
                ln = c.recv(1)[0]; host = c.recv(ln).decode()
                dport = int.from_bytes(c.recv(2), "big")
                asked.append(f"{host}:{dport}")
                up = _sock.create_connection(("127.0.0.1", dport), timeout=5)
                c.sendall(b"\x05\x00\x00\x01" + b"\x00" * 4 + b"\x00\x00")
                def pipe(a, b):
                    try:
                        while True:
                            d = a.recv(65536)
                            if not d: break
                            b.sendall(d)
                    except Exception: pass
                    finally:
                        try: b.shutdown(_sock.SHUT_WR)
                        except Exception: pass
                _thr.Thread(target=pipe, args=(c, up), daemon=True).start()
                pipe(up, c)
            except Exception: pass
            finally:
                try: c.close()
                except Exception: pass
        def loop():
            while True:
                try: conn, _ = srv.accept()
                except OSError: return
                _thr.Thread(target=handle, args=(conn,), daemon=True).start()
        _thr.Thread(target=loop, daemon=True).start()
        return srv

    class _Stub(_hs.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            b = b'{"peers": [], "generated_at": 1}'
            self.send_response(200); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)

    api_port, socks_port, dead_port = H.pick_port(), H.pick_port(), H.pick_port()
    stub = _hs.HTTPServer(("127.0.0.1", api_port), _Stub)
    _thr.Thread(target=stub.serve_forever, daemon=True).start()
    socks_srv = _socks5(socks_port)
    try:
        def _load(proxy, tag, control=None):
            for k, v in {"CONTROL_URL": control or f"http://control.invalid:{api_port}",
                         "NODE_API_PSK": "psk", "NODE_ID": "zur-01",
                         "ZTV_CONTROL_PROXY": proxy}.items():
                os.environ[k] = v
            sp = importlib.util.spec_from_file_location(
                f"meshd_socks_{tag}",
                os.path.join(H.REPO, "wireguard", "0trust-meshd.py"))
            mod = importlib.util.module_from_spec(sp); sp.loader.exec_module(mod)
            return mod

        live = _load(f"127.0.0.1:{socks_port}", "live")
        # Catch rather than let it escape: an exception here would skip the two
        # checks below entirely, and a check that silently does not run looks
        # exactly like a check that passed. Removing the proxy handler made
        # this section vanish from the results until it was written this way.
        try:
            body = live._get("/api/v1/wg/peers")
        except Exception as e:
            body = f"{type(e).__name__}: {e}"
        check("a request completes through the SOCKS5 proxy",
              body == {"peers": [], "generated_at": 1}, body)
        # 'control.invalid' does not resolve anywhere. Reaching the stub at all
        # proves the proxy did the lookup, which is what a .onion requires.
        check("the proxy was asked for the host by NAME, not a resolved address",
              asked == [f"control.invalid:{api_port}"], asked)

        # For THIS case the control plane must be directly reachable, or the
        # check proves nothing: with an unresolvable CONTROL_URL a fallback
        # would fail on its own and the test would pass whether or not the
        # fallback existed. Point it straight at the stub, so a fallback
        # SUCCEEDS and gets caught.
        down = _load(f"127.0.0.1:{dead_port}", "down",
                     control=f"http://127.0.0.1:{api_port}")
        fell_back = False
        try:
            down._get("/api/v1/wg/peers"); fell_back = True
        except Exception:
            pass
        check("a dead proxy fails the sync rather than reverting to clearnet",
              not fell_back,
              "it reached the control plane directly — the shared-destination "
              "signal is back and nothing reported it")
    finally:
        try: socks_srv.close()
        except Exception: pass
        try: stub.shutdown()
        except Exception: pass
        for k in ("ZTV_CONTROL_PROXY",):
            os.environ.pop(k, None)
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
