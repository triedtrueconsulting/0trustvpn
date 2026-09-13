#!/usr/bin/env python3
"""
The signup funnel in a real browser.

Chromium drives web/trial.html against the live control plane, so the
proof-of-work the page grinds is the one the API verifies — a mismatch
between the JS and Python implementations would silently break every
free signup, and no server-side test would notice.

Skips (exit 77) if Playwright or a browser is unavailable.
"""
import functools, glob, http.server, os, shutil, sqlite3, sys, threading
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
        if self.path.split("?")[0] == "/renew":
            self.path = "/renew.html"
        return super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            return self._forward("POST")
        self.send_response(404); self.end_headers()

    def _forward(self, method):
        import urllib.error, urllib.request
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n) if n else None
        headers = {"Content-Type": "application/json"}
        # The renewal page authenticates with the account token in a header,
        # exactly so it never lands in a URL or a log. nginx passes it through;
        # this stand-in has to as well or the page cannot work here.
        if self.headers.get("X-Account-Token"):
            headers["X-Account-Token"] = self.headers["X-Account-Token"]
        req = urllib.request.Request(H.API + self.path, data=body, method=method,
                                     headers=headers)
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
        headline = api_main.duration_label(api_main.TRIAL_DAYS_DEFAULT).capitalize() + ", free"
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

        print("\n[5] the same visitor renews the account they just got")
        # Nothing on the website could top up an existing account. The expiry
        # notice told the customer to run `0trust topup` or visit the site —
        # and a phone-only customer has no command line and the site's Begin
        # flow opens a NEW account. They were told to pay and given no way to.
        before = H.call("GET", "/api/v1/account/status",
                        headers={"X-Account-Token": token})[1]
        page.goto(f"http://127.0.0.1:{WEB_PORT}/renew", timeout=30000)
        page.wait_for_selector("#cardToken", timeout=15000)

        page.fill("#tok", "AAAA-BBBB-CCCC-DDDD")
        page.click("#lookup")
        page.wait_for_timeout(2500)
        check("an unknown token is refused before anyone is asked for money",
              page.is_visible("#tokErr") and not page.is_visible("#cardTerm"),
              page.inner_text("#tokErr"))

        # Lowercase and undashed: the same three shapes the CLI normalises.
        page.fill("#tok", token.replace("-", "").lower())
        page.click("#lookup")
        page.wait_for_selector("#cardTerm:not(.hide)", timeout=20000)
        check("a real token is accepted however it was pasted", True)
        check("and the page shows the account it is about to charge",
              page.inner_text("#acExp").strip() != "—",
              page.inner_text("#cardTerm")[:200])
        # The cap is 2 on a trial and 8 paid, and a client that prints a
        # constant tells half its customers the wrong number (bug class #11).
        check("the device cap comes from the account, not from the page",
              f"of {before['max_devices']}" in page.inner_text("#acDev"),
              f"page says {page.inner_text('#acDev')!r}, API says "
              f"{before['max_devices']}")

        terms = page.eval_on_selector_all(
            ".term", "els => els.map(e => e.innerText.replace(/\\n/g, ' '))")
        prices = {m: usd for m, usd in api_main.PRICING.items()}
        check("every term the control plane prices is offered",
              len(terms) == len(prices), terms)
        for months, usd in prices.items():
            check(f"{months} month(s) is offered at ${usd:.0f}",
                  any(f"${usd:.0f}" in t and f"{months} month" in t for t in terms),
                  terms)

        page.click('.term[data-months="3"]')
        page.click("#buy")
        page.wait_for_selector("#cardPay:not(.hide)", timeout=25000)
        addr = page.inner_text("#payAddr").strip()
        check("an invoice opens with a payment address",
              addr and addr != "\u2014", addr)
        check("and names the dollar amount the control plane invoiced",
              "5.00" not in page.inner_text("#payFiat")
              and "13.00" in page.inner_text("#payFiat"),
              page.inner_text("#payFiat"))

        inv = H.call("GET", "/api/v1/account/status",
                     headers={"X-Account-Token": token})[1]
        _c = sqlite3.connect(DB); _c.row_factory = sqlite3.Row
        rows = [dict(r) for r in _c.execute(
            "SELECT id, account_id, months, amount_usd, status "
            "FROM invoices ORDER BY rowid DESC LIMIT 1")]
        _c.close()
        check("the invoice tops up THIS account for the term chosen",
              rows and rows[0]["months"] == 3
              and float(rows[0]["amount_usd"]) == float(api_main.PRICING[3]),
              rows)

        # Paying it has to stack on what the trial had left, not replace it.
        H.settle(rows[0]["id"])
        after = H.call("GET", "/api/v1/account/status",
                       headers={"X-Account-Token": token})[1]
        added = (after["expires_at"] - before["expires_at"]) / 86400.0
        check("paying stacks 90 days on top of the trial's remaining time",
              89.9 < added < 90.1,
              f"{before['expires_at']} -> {after['expires_at']} ({added:.2f}d)")
        check("and the account is paid now, not trial",
              after.get("plan") == "paid", after)

        check("no JS errors anywhere in the funnel", not errors, errors[:3])
        browser.close()
finally:
    site.shutdown()
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
