#!/usr/bin/env python3
"""
The visitor proxy, against a real origin server.

guards.resolve_public is patched to permit the loopback test origin ONLY —
the guard exists precisely to block loopback, so exercising the fetch path
means carving out the one host we control. Every other guard stays live, and
test_proxy_guards covers the blocking behaviour with the patch off.
"""
import os, shutil, socket, subprocess, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

ORIGIN_PORT = H.pick_port()
PROXY_PORT  = H.pick_port()

# How long /slow holds a connection open. Long enough that a serialized proxy
# is unmistakable, short enough not to pad the suite.
SLOW_SECS = 3.0

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
        elif p == "/slow":
            # A page that answers, eventually. Real sites do this; so does
            # anyone who wants to tie up the proxy. Sleeps inside the handler
            # with the response half-written, which is what a slow origin
            # looks like from urllib's side.
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            time.sleep(SLOW_SECS)
            self.wfile.write(b"<html><body><h1>Slow</h1></body></html>")
            return
        elif p == "/second.html":
            b = b"<html><body><h1>Second</h1></body></html>"; ct = "text/html"
        elif p == "/setcookie":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "origin_track=abc; Path=/")
            self.end_headers(); self.wfile.write(b"<html><body>ck</body></html>"); return
        elif p == "/err-zip":
            # The bypass: a disallowed content type behind an error status.
            # fetch()'s success path runs content_type_allowed; its HTTPError
            # branch used to return the origin's type unchecked, so any site
            # could hand us any payload by serving it with a 404.
            b = b"PK\x03\x04binary"
            self.send_response(404)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b); return
        elif p == "/err-svg":
            # image/* IS allowed, so this one must still come through — the
            # fix is an allowlist on both paths, not a blanket refusal of
            # error bodies.
            b = b"<svg xmlns='http://www.w3.org/2000/svg'></svg>"
            self.send_response(404)
            self.send_header("Content-Type", "image/svg+xml")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b); return
        elif p == "/err-big":
            b = b"x" * (6 * 1024 * 1024)
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b); return
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


class Internal(BaseHTTPRequestHandler):
    """Stands in for whatever the SSRF was aiming at.

    On a real VPS this is 169.254.169.254 and the body is cloud credentials.
    Here it is a second loopback address on the same port, which is what lets
    the DNS answer change the destination without changing the URL.
    """
    def log_message(self, *a): pass
    def do_GET(self):
        b = b"<html><body>INTERNAL-SECRET-REACHED</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)


TMP = H.tempdir("0trust-proxy-")
srv = ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), Origin)
threading.Thread(target=srv.serve_forever, daemon=True).start()
internal = ThreadingHTTPServer(("127.0.0.2", ORIGIN_PORT), Internal)
threading.Thread(target=internal.serve_forever, daemon=True).start()

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
    # The guard approves flip.test at the SAFE address...
    if host == "flip.test" and port == {ORIGIN_PORT}:
        return ["127.0.0.1"]
    return _real(host, port)
guards.resolve_public = patched
guards.ALLOWED_PORTS = guards.ALLOWED_PORTS + ({ORIGIN_PORT},)

# ...and by the time anything resolves the name again, it answers with the
# internal one. A short TTL on an attacker-controlled domain does exactly
# this; here it is one function so the race is deterministic rather than a
# matter of timing.
import socket as _sock
_real_gai = _sock.getaddrinfo
def _flip_gai(host, port, *a, **kw):
    if host == "flip.test":
        return [(_sock.AF_INET, _sock.SOCK_STREAM, 6, "",
                 ("127.0.0.2", int(port)))]
    return _real_gai(host, port, *a, **kw)
_sock.getaddrinfo = _flip_gai
import server
server.check_url.__globals__["resolve_public"] = patched
import uvicorn
uvicorn.run(server.app, host="127.0.0.1", port={PROXY_PORT}, log_level="warning")
''')
# A trial length the code could not have hardcoded, and a control plane that is
# not there: this pins the phrasing to configuration and exercises the fallback
# an operator gets when the API is briefly down.
DEAD_API = H.pick_port()
proc = subprocess.Popen(
    [sys.executable, shim],
    env={**os.environ, "ZTV_TRIAL_DAYS": "14",
         "ZTV_API_BASE": f"http://127.0.0.1:{DEAD_API}"},
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
    check("landing offers the configured trial, not a hardcoded month",
          "two weeks of the real thing" in body, body[:900])

    # Two copies of the same phrasing exist on purpose: the proxy has to name
    # the offer even when the control plane is unreachable. Two copies that
    # disagree would put a different offer on /surf than on the trial page, so
    # the identity is asserted rather than assumed.
    os.environ.setdefault("ZTV_DB_PATH", os.path.join(TMP, "phrase.db"))
    sys.path.insert(0, os.path.join(H.REPO, "api"))
    sys.path.insert(0, os.path.join(H.REPO, "proxy"))
    import main as api_main, server as proxy_server
    drift = [d for d in range(1, 800)
             if proxy_server._plain_label(d) != api_main.duration_label(d)]
    check("the proxy's offline wording never drifts from the API's",
          not drift, f"first mismatches: {drift[:5]}")

    print("\n[2] fetch and rewrite")
    st, body, hdrs = get(f"/surf?url={O}%2F")
    check("proxied page returns 200", st == 200, st)
    check("origin content present", "Hello from the origin" in body, body[:300])
    check("banner injected", "0trust" in body and "ztv-banner" in body, body[:300])
    check("banner's CTA states the configured trial length",
          "two weeks of the full VPN" in body, body[:1200])
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

    print("\n[5a] the address that was vetted is the address we connect to")
    # resolve_public() vetted the addresses and threw them away: the URL then
    # went to urllib, which resolved the name a SECOND time. An attacker
    # controlling DNS for their own domain only has to serve a short TTL that
    # alternates — public for our check, 169.254.169.254 for the fetch. That
    # is the textbook SSRF bypass, and on a cloud VPS the second address is
    # the metadata service.
    #
    # flip.test is approved at 127.0.0.1 and resolves to 127.0.0.2, where a
    # second server is listening on the same port. If the fetch lands there,
    # the guard vetted one host and talked to another.
    st, body, _ = get(f"/surf?url=http%3A%2F%2Fflip.test%3A{ORIGIN_PORT}%2F")
    check("the fetch does not follow the changed DNS answer",
          "INTERNAL-SECRET-REACHED" not in body,
          "the proxy connected to the address DNS gave it AFTER the check — "
          "this is the SSRF the whole guard module exists to prevent")
    # The safe origin's own content, not just "a page came back" — the
    # first version of this looked for the proxy's own chrome, which is
    # present whichever server answered, so it passed while the check above
    # it was failing.
    check("and it reaches the address the guard approved",
          "Hello from the origin" in body, body[:200])

    print("\n[5b] the rails hold on an error response too")
    # An error response is still a response. fetch() checked the content type
    # and the size cap on the 2xx path and neither on the HTTPError path, so
    # an origin could serve any payload of any type by attaching a 404 to it
    # — and we would return it from OUR origin. What kept that from being an
    # XSS on 0trustvpn.com was the proxy's CSP (`script-src 'none'`), not
    # anything on this path; a rail that only holds on 2xx is not a rail.
    def ctype(hdrs):
        for k, v in hdrs.items():
            if k.lower() == "content-type":
                return v.split(";")[0].strip().lower()
        return ""

    st, body, hdrs = get(f"/surf?url={O}%2Ferr-zip")
    check("a disallowed type behind a 404 is not served",
          ctype(hdrs) != "application/zip",
          f"served {ctype(hdrs)!r} from our own origin")
    check("the visitor gets the proxy's own refusal instead", st == 400, st)
    check("and it says what was refused", "does not serve" in body.lower(),
          body[:200])

    # An allowlist, not a blanket block on error bodies: an allowed type
    # behind an error status still has to come through, or every 404 page
    # anyone reads through /surf stops rendering.
    st2, body2, hdrs2 = get(f"/surf?url={O}%2Ferr-svg")
    # The status is deliberately not passed through — /surf is a reader, and
    # it answers 200 with whatever the origin gave it to show. What matters
    # here is that an ALLOWED type behind an error status still reaches the
    # visitor, so the fix is an allowlist on both paths and not a blanket
    # refusal of error bodies, which would blank every 404 page anyone reads.
    check("an ALLOWED type behind a 404 still reaches the visitor",
          ctype(hdrs2) == "image/svg+xml" and "<svg" in body2,
          f"status {st2}, type {ctype(hdrs2)!r}, body {body2[:80]!r}")

    st3, body3, _ = get(f"/surf?url={O}%2Ferr-big")
    check("the size cap applies to an error body too",
          st3 == 400 and "larger than" in body3.lower(),
          f"status {st3} — a truncated body rendered as a whole page is "
          f"worse than a refusal")

    print("\n[6] visitor isolation")
    st, _, hdrs11 = get(f"/surf?url={O}%2Fsetcookie")
    sc = hdrs11.get("set-cookie", "")
    check("origin Set-Cookie not passed to the visitor", "origin_track" not in sc, sc)
    check("only our own view counter is set", "ztv_views" in sc, sc)

    print("\n[7] funnel")
    # Fetch a proxied page here rather than reading a `body` left over from a
    # section several blocks up. That dependency was invisible and undeclared:
    # inserting anything above that reassigned `body` turned this check red
    # while naming the funnel, which is not where the problem was.
    _, proxied, _ = get(f"/surf?url={O}%2F")
    check("trial link present on proxied pages",
          "/trial?from=surf" in proxied, proxied[:600])
    st, robots, _ = get("/robots.txt")
    check("robots.txt disallows indexing", "Disallow: /" in robots, robots)
    st, hz, _ = get("/healthz")
    check("healthz responds", st == 200, st)
    print("\n[xss] the error page does not reflect what you put in ?url=")
    # `?url=http://<img src=x onerror=…>.test/` came back with the payload
    # verbatim inside <p>{e}</p>: guards.py builds "Could not resolve {host}"
    # from the attacker's hostname and the page interpolated the exception
    # raw. The error path also set NO CSP — that was only on the success path
    # — and nginx's site-wide policy allows 'unsafe-inline', so it would have
    # executed. Reflected XSS on the funnel's front door, which is the one
    # page whose entire job is being trustworthy.
    import urllib.parse as _up
    for payload, label in (
        ('http://<img src=x onerror=alert(1)>.test/', 'tag injection'),
        ('http://a"><script>alert(1)</script>.test/', 'attribute break-out'),
        ("http://'onmouseover='alert(1).test/", 'quote break-out'),
    ):
        st, body, hdrs = get("/surf?url=" + _up.quote(payload, safe=''))
        check(f"{label} is not reflected raw",
              "<img src=x" not in body and "<script>alert" not in body
              and "onmouseover='alert" not in body,
              body[body.find("Could not") - 40:][:220] if "Could not" in body else body[:220])
        check(f"{label}: response still carries a CSP",
              "content-security-policy" in {k.lower() for k in hdrs},
              sorted(hdrs))

    # The headers were attached inside the success handler, so anything that
    # returned early — every error, the landing page, robots.txt — went out
    # bare. They belong on every response.
    for path, label in (("/surf", "landing page"),
                        ("/surf?url=nonsense", "blocked page"),
                        ("/healthz", "health check")):
        st, body, hdrs = get(path)
        low = {k.lower(): v for k, v in hdrs.items()}
        check(f"{label} sets a CSP", "content-security-policy" in low, sorted(low))
        check(f"{label} forbids scripts outright",
              "script-src 'none'" in low.get("content-security-policy", ""),
              low.get("content-security-policy"))
        check(f"{label} sets nosniff",
              low.get("x-content-type-options") == "nosniff", low)

    # -------------------------------------------------------------------
    # A slow origin must not take the service down with it.
    #
    # fetch() is urllib: it blocks for FETCH_TIMEOUT per hop and then reads
    # up to 5 MB from whatever trickle the origin sends. While `surf` was an
    # `async def`, all of that ran on the event loop, so one visitor pointing
    # ?url= at a slow host froze the worker and everybody else queued behind
    # it — an unauthenticated GET, on the most exposed service we run.
    #
    # The measurement is a race, not a stopwatch: fire a slow fetch, and
    # while it is in flight ask for the landing page, which touches no
    # network at all. If the landing page comes back before the slow fetch
    # finishes, the handler is off the event loop. If it comes back after,
    # the worker was blocked. SLOW_SECS is the margin between those.
    # -------------------------------------------------------------------
    print("\n[concurrency] a slow origin does not block the service")
    import concurrent.futures
    slow_url = f"/surf?url=http%3A%2F%2F127.0.0.1%3A{ORIGIN_PORT}%2Fslow"
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        t0 = time.time()
        slow = pool.submit(get, slow_url, 30)
        time.sleep(0.5)                       # let the slow fetch get going
        quick = pool.submit(get, "/surf", 30)
        quick_st, quick_body, _ = quick.result()
        quick_done = time.time() - t0
        slow_st, slow_body, _ = slow.result()
        slow_done = time.time() - t0

    check("the slow page is still served correctly",
          slow_st == 200 and "Slow" in slow_body, f"{slow_st} {slow_body[:200]}")
    check("the slow fetch really was slow (control)",
          slow_done >= SLOW_SECS, f"finished in {slow_done:.1f}s — /slow did not "
          f"hold the connection, so the check below proves nothing")
    check("the landing page answers while a slow fetch is in flight",
          quick_st == 200 and quick_done < slow_done - 1.0,
          f"landing took {quick_done:.1f}s, slow fetch {slow_done:.1f}s — the "
          f"handler is blocking the event loop")

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
