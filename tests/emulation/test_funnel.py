#!/usr/bin/env python3
"""
The signup funnel in a real browser.

Chromium drives web/trial.html against the live control plane, so the
proof-of-work the page grinds is the one the API verifies — a mismatch
between the JS and Python implementations would silently break every
free signup, and no server-side test would notice.

Skips (exit 77) if Playwright or a browser is unavailable.
"""
import functools, glob, http.server, os, shutil, sys, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("  SKIP  playwright not installed")
    sys.exit(77)

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

WEB_PORT = H.pick_port()
TMP = H.tempdir("0trust-funnel-"); DB = os.path.join(TMP, "0trust.db")
os.environ["ZTV_DB_PATH"] = DB
os.environ["ZTV_TRIAL_SECRET"] = "funnel-secret"
os.environ["ZTV_TRIAL_POW_BITS"] = "14"
sys.path.insert(0, os.path.join(H.REPO, "api"))
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=2)


class Site(http.server.SimpleHTTPRequestHandler):
    """Serves web/ and forwards /api/ to the control plane, as nginx does."""
    def log_message(self, *a): pass

    def do_GET(self):
        if self.path.startswith("/api/"):
            return self._forward("GET")
        if self.path in ("/trial", "/trial?from=surf"):
            self.path = "/trial.html"
        if self.path.startswith("/trial?"):
            self.path = "/trial.html"
        return super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            return self._forward("POST")
        self.send_response(404); self.end_headers()

    def _forward(self, method):
        import urllib.error, urllib.request
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n) if n else None
        req = urllib.request.Request(H.API + self.path, data=body, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                data, status = r.read(), r.status
        except urllib.error.HTTPError as e:
            data, status = e.read(), e.code
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)


handler = functools.partial(Site, directory=os.path.join(H.REPO, "web"))
site = http.server.ThreadingHTTPServer(("127.0.0.1", WEB_PORT), handler)
threading.Thread(target=site.serve_forever, daemon=True).start()

try:
    with sync_playwright() as pw:
        # PLAYWRIGHT_BROWSERS_PATH holds a pinned build that may not match the
        # installed playwright package's expected revision, so find the real
        # binary and point at it rather than triggering a download.
        try:
            browser = H.launch_chromium(pw)
        except H.SkipModule as e:
            print(f"  SKIP  {e}")
            sys.exit(77)
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))

        print("[1] trial page loads")
        page.goto(f"http://127.0.0.1:{WEB_PORT}/trial?from=surf", timeout=30000)
        # The headline is assembled from /api/v1/config after load, so wait for
        # it rather than reading whatever the served fallback said.
        headline = api_main.duration_label(api_main.TRIAL_DAYS).capitalize() + ", free"
        try:
            page.wait_for_function("t => document.querySelector('h1').innerText === t",
                                   arg=headline, timeout=8000)
        except Exception:
            pass
        got = page.inner_text("h1")
        check(f"headline reflects the configured trial ({headline})",
              got == headline, f"page says {got!r}")
        check("states there is no email or card",
              "No email" in page.content() and "No card" in page.content())
        check("distinguishes itself from the /surf proxy",
              "only covers one browser tab" in page.content())

        print("\n[2] the browser grinds the proof of work and redeems it")
        page.click("#go")
        page.wait_for_selector("#doneCard:not(.hide)", timeout=90000)
        token = page.inner_text("#token").strip()
        check("a token was issued", len(token) == 19 and token.count("-") == 3, token)
        check("no JS errors on the page", not errors, errors)
        check("device cap shown", page.inner_text("#devs").strip() == "2",
              page.inner_text("#devs"))
        check("expiry date shown", len(page.inner_text("#exp").strip()) == 10,
              page.inner_text("#exp"))
        # Collapse whitespace: the sentence wraps in the source.
        text = " ".join(page.inner_text("body").split())
        check("warns the token is unrecoverable",
              "no way for us to look it up" in text, text[:300])

        print("\n[3] the issued token actually works")
        st, s = H.call("GET", "/api/v1/account/status",
                       headers={"X-Account-Token": token})
        check("control plane knows the token", st == 200, f"{st} {s}")
        check("account is an active trial",
              s.get("status") == "active" and s.get("plan") == "trial", s)
        st, reg = H.call("POST", "/api/v1/wg/register",
                         {"pubkey": H.genkey(), "device_name": "browser-trial",
                          "region": "zur"},
                         headers={"X-Account-Token": token})
        check("the trial can bring up a tunnel", st == 200 and reg["peers"], f"{st} {reg}")

        print("\n[4] a second visitor gets a different account")
        page2 = browser.new_page()
        page2.goto(f"http://127.0.0.1:{WEB_PORT}/trial", timeout=30000)
        page2.click("#go")
        page2.wait_for_selector("#doneCard:not(.hide)", timeout=90000)
        token2 = page2.inner_text("#token").strip()
        check("distinct token", token2 != token, f"{token} vs {token2}")
        browser.close()
finally:
    site.shutdown()
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
