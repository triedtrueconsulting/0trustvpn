#!/usr/bin/env python3
"""
The visitor proxy, against a real origin server.

guards.resolve_public is patched to permit the loopback test origin ONLY —
the guard exists precisely to block loopback, so exercising the fetch path
means carving out the one host we control. Every other guard stays live, and
test_proxy_guards covers the blocking behaviour with the patch off.
"""
import os, shutil, socket, subprocess, sys, tempfile, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

ORIGIN_PORT = 8097
PROXY_PORT  = 8096

PAGE = """<!doctype html><html><head><title>Origin</title>
<link rel="stylesheet" href="/style.css">
<script>window.EVIL = 1; document.title = 'pwned';</script>
</head><body onload="alert(1)">
<h1>Hello from the origin</h1>
<a href="/second.html">second page</a>
<a href="https://elsewhere.test/x">offsite</a>
<img src="/pic.png" onerror="alert(2)">
<form action="/submit"><input name="q"></form>
<div style="background:url('/bg.png')">styled</div>
</body></html>"""


class Origin(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/", "/index.html"):
            b = PAGE.encode(); ct = "text/html; charset=utf-8"
        elif p == "/style.css":
            b = b"body{background:url('/deep.png')}"; ct = "text/css"
        elif p == "/big":
            b = b"x" * (6 * 1024 * 1024); ct = "text/plain"
        elif p == "/zip":
            b = b"PK\x03\x04binary"; ct = "application/zip"
        elif p == "/redirect-public":
            self.send_response(302); self.send_header("Location", "/second.html")
            self.end_headers(); return
        elif p == "/redirect-private":
            # The rebinding case: a vetted public URL bouncing somewhere internal.
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers(); return
        elif p == "/second.html":
            b = b"<html><body><h1>Second</h1></body></html>"; ct = "text/html"
        elif p == "/setcookie":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "origin_track=abc; Path=/")
            self.end_headers(); self.wfile.write(b"<html><body>ck</body></html>"); return
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)


def wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0: return True
        time.sleep(0.15)
    return False


TMP = tempfile.mkdtemp(prefix="0trust-proxy-")
srv = ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), Origin)
threading.Thread(target=srv.serve_forever, daemon=True).start()

# Boot the proxy with resolve_public allowing only our loopback origin.
shim = os.path.join(TMP, "run_proxy.py")
open(shim, "w").write(f'''
import sys, os
sys.path.insert(0, {os.path.join(H.REPO, "proxy")!r})
import guards
_real = guards.resolve_public
def patched(host, port):
    if host in ("127.0.0.1", "localhost") and port == {ORIGIN_PORT}:
        return ["127.0.0.1"]
    return _real(host, port)
guards.resolve_public = patched
guards.ALLOWED_PORTS = guards.ALLOWED_PORTS + ({ORIGIN_PORT},)
import server
server.check_url.__globals__["resolve_public"] = patched
import uvicorn
uvicorn.run(server.app, host="127.0.0.1", port={PROXY_PORT}, log_level="warning")
''')
proc = subprocess.Popen([sys.executable, shim],
                        stdout=open(f"{TMP}/proxy.log", "w"), stderr=subprocess.STDOUT)

def get(path, timeout=25):
    req = urllib.request.Request(f"http://127.0.0.1:{PROXY_PORT}{path}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)

try:
    if not wait_port(PROXY_PORT):
        print(open(f"{TMP}/proxy.log").read()); raise SystemExit("proxy did not start")
    O = f"http%3A%2F%2F127.0.0.1%3A{ORIGIN_PORT}"

    print("[1] landing page")
    st, body, _ = get("/surf")
    check("landing renders", st == 200 and "Read a page through 0trust" in body, st)
    check("landing states it is not the VPN", "not the VPN" in body, body[:400])

    print("\n[2] fetch and rewrite")
    st, body, hdrs = get(f"/surf?url={O}%2F")
    check("proxied page returns 200", st == 200, st)
    check("origin content present", "Hello from the origin" in body, body[:300])
    check("banner injected", "0trust" in body and "ztv-banner" in body, body[:300])
    check("links rewritten back through the proxy",
          "/surf?url=http%3A%2F%2F127.0.0.1" in body, body[:900])
    check("offsite link also proxied", "elsewhere.test" in body and
          body.count("/surf?url=") >= 3, body[:900])

    print("\n[3] active content stripped")
    check("<script> removed", "window.EVIL" not in body, body[:600])
    check("inline onload removed", "alert(1)" not in body, body[:600])
    check("inline onerror removed", "alert(2)" not in body, body[:900])
    check("CSP forbids scripts",
          "script-src 'none'" in hdrs.get("content-security-policy", ""), hdrs)
    check("nosniff set", hdrs.get("x-content-type-options") == "nosniff", hdrs)
    check("noindex set", "noindex" in hdrs.get("x-robots-tag", ""), hdrs)

    print("\n[4] CSS urls rewritten")
    st, css, _ = get(f"/surf?url={O}%2Fstyle.css")
    check("css proxied", st == 200, st)
    check("url() rewritten", "/surf?url=" in css, css[:200])
    check("inline style url() rewritten", "bg.png" in body.replace("%2F", "/"), "inline style")

    print("\n[5] guards hold on the live fetch path")
    st, body5, _ = get(f"/surf?url={O}%2Fbig")
    check("oversize page refused", st == 400 and "5 MB" in body5, (st, body5[:200]))
    st, body6, _ = get(f"/surf?url={O}%2Fzip")
    check("archive content-type refused", st == 400, (st, body6[:200]))
    st, body7, _ = get(f"/surf?url={O}%2Fredirect-private")
    check("redirect into link-local refused", st == 400 and "private" in body7.lower(),
          (st, body7[:300]))
    st, body8, _ = get(f"/surf?url={O}%2Fredirect-public")
    check("ordinary redirect still followed", st == 200 and "Second" in body8, (st, body8[:200]))
    st, body9, _ = get("/surf?url=http%3A%2F%2F169.254.169.254%2F")
    check("direct metadata fetch refused", st == 400, (st, body9[:200]))
    st, body10, _ = get("/surf?url=file%3A%2F%2F%2Fetc%2Fpasswd")
    check("file scheme refused", st == 400, (st, body10[:200]))

    print("\n[6] visitor isolation")
    st, _, hdrs11 = get(f"/surf?url={O}%2Fsetcookie")
    sc = hdrs11.get("set-cookie", "")
    check("origin Set-Cookie not passed to the visitor", "origin_track" not in sc, sc)
    check("only our own view counter is set", "ztv_views" in sc, sc)

    print("\n[7] funnel")
    check("trial link present on proxied pages", "/trial?from=surf" in body, body[:600])
    st, robots, _ = get("/robots.txt")
    check("robots.txt disallows indexing", "Disallow: /" in robots, robots)
    st, hz, _ = get("/healthz")
    check("healthz responds", st == 200, st)
finally:
    if proc.poll() is None:
        proc.terminate()
        try: proc.wait(timeout=6)
        except Exception: proc.kill()
    srv.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
