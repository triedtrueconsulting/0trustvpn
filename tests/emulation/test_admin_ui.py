#!/usr/bin/env python3
"""
The operations dashboard in a real browser.

The backend is covered by test_admin; this drives the page an operator
actually uses — first-run setup, sign in, and each control end to end,
checking the effect landed in the control plane rather than just that a
button existed.

Skips (77) without Playwright or a browser.
"""
import functools, glob, http.server, json, os, shutil, sys, threading
import urllib.error, urllib.request
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

PORT = H.pick_port()
TMP = H.tempdir("0trust-adminui-"); DB = os.path.join(TMP, "0trust.db")
os.environ["ZTV_DB_PATH"] = DB
os.environ["ZTV_TRIAL_SECRET"] = "adminui"
os.environ["ZTV_TRIAL_POW_BITS"] = "10"
os.environ.pop("ZTV_ADMIN_USER", None)
os.environ.pop("ZTV_ADMIN_PASSWORD", None)
sys.path.insert(0, os.path.join(H.REPO, "api"))
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=1)


class Site(http.server.SimpleHTTPRequestHandler):
    """web/ plus the nginx rewrites, forwarding /api to the control plane."""
    def log_message(self, *a): pass

    def _proxy(self, method):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(n) if n else None
        req = urllib.request.Request(H.API + self.path, data=body, method=method,
                                     headers={"Content-Type": "application/json"})
        for h in ("Cookie", "X-Admin-CSRF"):
            if self.headers.get(h):
                req.add_header(h, self.headers[h])
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                data, status, hdrs = r.read(), r.status, r.headers
        except urllib.error.HTTPError as e:
            data, status, hdrs = e.read(), e.code, e.headers
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for c in (hdrs.get_all("Set-Cookie") or []):
            self.send_header("Set-Cookie", c)
        self.end_headers(); self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/api/"): return self._proxy("GET")
        if self.path.split("?")[0] == "/admin": self.path = "/admin.html"
        return super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"): return self._proxy("POST")
        self.send_response(404); self.end_headers()

    def do_DELETE(self):
        if self.path.startswith("/api/"): return self._proxy("DELETE")
        self.send_response(404); self.end_headers()

    def do_PATCH(self):
        if self.path.startswith("/api/"): return self._proxy("PATCH")
        self.send_response(404); self.end_headers()


srv = http.server.ThreadingHTTPServer(
    ("127.0.0.1", PORT), functools.partial(Site, directory=os.path.join(H.REPO, "web")))
threading.Thread(target=srv.serve_forever, daemon=True).start()

PASSWORD = "operations-password-2026"
browser = None
try:
    with sync_playwright() as pw:
        try:
            browser = H.launch_chromium(pw)
        except H.SkipModule as e:
            print(f"  SKIP  {e}")
            sys.exit(77)

        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("dialog", lambda d: d.accept("automated test"))

        print("[1] first run asks for an operator")
        page.goto(f"http://127.0.0.1:{PORT}/admin", timeout=30000)
        page.wait_for_selector("#setup-form:not(.hidden)", timeout=20000)
        check("setup form is shown when no operator exists", True)
        check("login form is hidden", page.is_hidden("#login-form"))
        check("warns there is no password reset",
              "no password reset" in " ".join(page.inner_text("#setup-form").split()))

        page.fill("#su-user", "ops")
        page.fill("#su-pass", PASSWORD)
        page.fill("#su-pass2", "does-not-match-at-all")
        page.click("#setup-form button[type=submit]")
        page.wait_for_timeout(400)
        check("mismatched passwords are refused client-side",
              page.is_visible("#gate-err"), page.inner_text("#gate-err"))

        page.fill("#su-pass2", PASSWORD)
        page.click("#setup-form button[type=submit]")
        page.wait_for_selector("#app:not(.hidden)", timeout=30000)
        check("creating the operator signs you straight in", True)
        check("the operator name is shown", page.inner_text("#who-name").strip() == "ops")

        print("\n[2] overview")
        page.wait_for_selector("#stat-row .stat", timeout=15000)
        # .stat .k and th are uppercased by CSS on purpose, so fold the case.
        stats = page.inner_text("#stat-row").lower()
        check("stat tiles render", "active" in stats and "devices" in stats, stats[:200])
        check("the three seeded nodes are listed",
              page.inner_text("#node-health").count("healthy") >= 3,
              page.inner_text("#node-health")[:300])

        print("\n[3] accounts: find, ban, extend")
        tok, _ = H.paid_account()
        pk = H.genkey()
        H.call("POST", "/api/v1/wg/register",
               {"pubkey": pk, "device_name": "laptop", "region": "zur"},
               headers={"X-Account-Token": tok})
        page.click("#tabs button[data-tab=accounts]")
        page.fill("#acct-q", tok)
        page.click("#acct-search")
        page.wait_for_function(
            "() => document.querySelectorAll('#acct-list tbody tr').length === 1",
            timeout=15000)
        check("searching by token finds exactly one account", True)
        page.click("#acct-list tbody tr button")
        page.wait_for_selector("#acct-detail:not(.hidden)", timeout=15000)
        detail = page.inner_text("#acct-detail")
        check("account detail opens", "Devices" in detail and "laptop" in detail,
              detail[:300])

        page.click("#acct-detail button:has-text('Ban')")
        page.wait_for_function(
            "() => document.querySelector('#acct-detail').innerText.includes('Unban')",
            timeout=15000)
        st, s = H.call("GET", "/api/v1/account/status", headers={"X-Account-Token": tok})
        check("the ban took effect in the control plane", st == 403, f"{st} {s}")
        page.click("#acct-detail button:has-text('Unban')")
        page.wait_for_function(
            "() => document.querySelector('#acct-detail').innerText.includes('Ban')",
            timeout=15000)
        st, s = H.call("GET", "/api/v1/account/status", headers={"X-Account-Token": tok})
        check("unbanning restores access", st == 200, f"{st} {s}")

        before = H.call("GET", "/api/v1/account/status",
                        headers={"X-Account-Token": tok})[1]["days_remaining"]
        page.click("#acct-detail button:has-text('+30 days')")
        page.wait_for_timeout(1200)
        after = H.call("GET", "/api/v1/account/status",
                       headers={"X-Account-Token": tok})[1]["days_remaining"]
        check("extending adds the days", after >= before + 29, f"{before} -> {after}")

        print("\n[3b] refunding from the account detail")
        # A refund request arrives as a token, so this is the screen the
        # operator is already on. The control existed on both screens and had
        # never been clicked by anything: it pre-stringified its body into an
        # api() helper that stringifies, so every click returned 422 and the
        # operation terms.html §4 promises did not happen.
        exp_before = H.call("GET", "/api/v1/account/status",
                            headers={"X-Account-Token": tok})[1]["expires_at"]
        check("the account detail offers a refund on a settled invoice",
              page.is_visible("#acct-detail button:has-text('Record refund')"),
              page.inner_text("#acct-detail")[-400:])
        page.click("#acct-detail button:has-text('Record refund')")
        try:
            page.wait_for_function(
                "() => document.querySelector('#acct-detail').innerText.includes('refunded')",
                timeout=15000)
        except Exception as e:
            check("clicking Record refund records the refund", False,
                  f"{type(e).__name__}: still {page.inner_text('#acct-detail')[-200:]}")
        st, after_acct = H.call("GET", "/api/v1/account/status",
                                headers={"X-Account-Token": tok})
        # expires_at is the stored absolute timestamp; days_remaining is derived
        # from now on every request and ticks between two reads (bug class #10).
        taken = (exp_before - after_acct["expires_at"]) / 86400.0
        check("the month the invoice paid for comes back off the subscription",
              29.9 < taken < 30.1, f"{exp_before} -> {after_acct['expires_at']} ({taken}d)")
        check("and the invoice is marked refunded on the page",
              "refunded" in page.inner_text("#acct-detail"),
              page.inner_text("#acct-detail")[-300:])

        print("\n[4] nodes")
        page.click("#tabs button[data-tab=nodes]")
        page.wait_for_selector("#node-list table", timeout=15000)
        check("nodes are listed", page.inner_text("#node-list").count("zur-01") >= 1)
        page.fill("#node-form [name=id]", "zur-09")
        page.select_option("#node-region", "zur")
        page.fill("#node-form [name=public_ip]", "203.0.113.99")
        page.fill("#node-form [name=pubkey]", H.genkey())
        page.click("#node-form button[type=submit]")
        page.wait_for_function(
            "() => document.querySelector('#node-list').innerText.includes('zur-09')",
            timeout=15000)
        check("a node added from the UI appears in the list", True)
        st, nodes = H.call("GET", "/api/v1/regions")
        check("the new node is live in the control plane",
              any(r["code"] == "zur" for r in nodes["regions"]), nodes)

        page.select_option("#ptok-region", "zur")
        page.click("#ptok-form button[type=submit]")
        page.wait_for_selector("#ptok-out .secret-out", timeout=15000)
        tokentext = page.inner_text("#ptok-out .secret-out").strip()
        check("a provisioning token is shown once", tokentext.startswith("ztvp-"), tokentext[:20])
        st, prov = H.call("POST", "/api/v1/node/provision",
                          {"pubkey": H.genkey(), "public_ip": "198.51.100.44",
                           "region": "zur", "role": "both"},
                          headers={"X-Provision-Token": tokentext})
        check("the token from the UI actually provisions a node", st == 200, prov)

        # The command an operator will actually paste onto the VPS. If the UI
        # only shows the token, they have to go and find the flags somewhere
        # else, and the flag that gets forgotten is the one that matters.
        check("and the page hands over the command to run on the node",
              "install.sh --mode node" in page.inner_text("#ptok-out"),
              page.inner_text("#ptok-out")[:300])

        page.wait_for_selector("#ptok-list table", timeout=15000)
        listed = page.inner_text("#ptok-list")
        check("the token appears in the outstanding list", "spent" in listed
              or "live" in listed, listed[:300])
        check("and shows what it is scoped to", "zur/both" in listed,
              listed[:300])

        # An enrolment token lives on a node's disk, so being able to kill one
        # from here is the difference between a seized box being a problem and
        # being a way back into the mesh.
        page.fill("#ptok-form [name=uses]", "5")
        page.click("#ptok-form button[type=submit]")
        page.wait_for_function(
            "() => document.querySelectorAll('#ptok-list tbody tr').length >= 2",
            timeout=15000)
        check("an enrolment token can be minted with more than one use",
              "5" in page.inner_text("#ptok-list"), page.inner_text("#ptok-list")[:400])
        # A dialog handler is already registered for the whole session; a
        # second one double-accepts the same confirm() and throws.
        # Only live rows carry a button — a spent or expired token has nothing
        # left to revoke — so target the button rather than a row position.
        page.click("#ptok-list button")
        page.wait_for_function(
            "() => document.querySelector('#ptok-list').innerText.includes('revoked')",
            timeout=15000)
        check("and revoked from the dashboard", True)

        print("\n[5] settings")
        page.click("#tabs button[data-tab=settings]")
        page.wait_for_selector("#settings-groups .set-group", timeout=15000)
        text_raw = page.inner_text("#settings-groups")
        text = text_raw.lower()
        for group in ("Business wallets", "Public chain endpoints", "Stripe", "Square"):
            check(f"settings show the {group} group", group.lower() in text, text_raw[:400])
        check("chain group explains we host no chain",
              "never syncs a chain locally" in text_raw, text_raw[:600])
        page.fill("#set-WALLET_ETH", "0xtest-eth-wallet")
        page.fill("#set-STRIPE_SECRET_KEY", "sk_live_supersecret")
        page.click("#settings-form button[type=submit]")
        page.wait_for_timeout(1500)
        with __import__("sqlite3").connect(DB) as c:
            got = dict(c.execute("SELECT key, value FROM settings").fetchall())
        check("a wallet is persisted", got.get("WALLET_ETH") == "0xtest-eth-wallet", got)
        check("a secret is persisted", got.get("STRIPE_SECRET_KEY") == "sk_live_supersecret")
        page.reload()
        page.wait_for_selector("#app:not(.hidden)", timeout=20000)
        page.click("#tabs button[data-tab=settings]")
        page.wait_for_selector("#set-STRIPE_SECRET_KEY", timeout=15000)
        shown = page.input_value("#set-STRIPE_SECRET_KEY")
        check("the secret is masked when it comes back", "supersecret" not in shown, shown)

        print("\n[5b] the settings grid stays aligned")
        # A label long enough to wrap used to push its own input half a row
        # below its neighbours'. Measure it precisely: group cells by the row
        # the grid put them in, then check the inputs inside a row share a
        # bottom edge. Anything else means a label moved a field.
        misaligned = page.evaluate("""() => {
          const bad = [];
          for (const grid of document.querySelectorAll('#settings-groups .set-grid')) {
            const rows = new Map();
            for (const cell of grid.children) {
              const f = cell.querySelector('input,select');
              if (!f) continue;
              const key = Math.round(cell.getBoundingClientRect().top / 4);
              (rows.get(key) || rows.set(key, []).get(key))
                .push({ id: f.id, bottom: f.getBoundingClientRect().bottom });
            }
            for (const [, fields] of rows) {
              if (fields.length < 2) continue;
              const base = fields[0].bottom;
              for (const f of fields) {
                if (Math.abs(f.bottom - base) > 2) bad.push(f.id);
              }
            }
          }
          return bad;
        }""")
        check("no field is knocked out of line by a wrapped label",
              misaligned == [], misaligned)
        labels = page.eval_on_selector_all(
            "#settings-groups label",
            "els => els.map(e => getComputedStyle(e).fontFamily)")
        check("field labels use the technical face, like the rest of the product",
              labels and all("JetBrains" in f or "mono" in f.lower() for f in labels),
              sorted(set(labels))[:3])

        print("\n[6] notices")
        page.click("#tabs button[data-tab=notices]")
        page.wait_for_selector("#notice-form", timeout=15000)
        note_text = " ".join(page.inner_text("[data-panel=notices] .note").split())
        check("the UI is honest that nothing is emailed",
              "no email address" in note_text and "nothing is sent anywhere" in note_text,
              note_text[:250])
        page.fill("#notice-form [name=subject]", "Maintenance window")
        page.fill("#notice-form [name=body]", "buc-01 reboots at 02:00 UTC.")
        page.click("#notice-form button[type=submit]")
        page.wait_for_function(
            "() => document.querySelector('#notice-list').innerText.includes('Maintenance window')",
            timeout=15000)
        st, mine = H.call("GET", "/api/v1/notices", headers={"X-Account-Token": tok})
        check("the customer receives the notice",
              any(n["subject"] == "Maintenance window" for n in mine), mine)

        print("\n[7] payments and audit")
        page.click("#tabs button[data-tab=payments]")
        page.wait_for_selector("#pay-health table", timeout=15000)
        check("payment health renders",
              "provider" in page.inner_text("#pay-health").lower(),
              page.inner_text("#pay-health")[:200])
        # replaceChildren() stringifies whatever it is handed, so the null
        # standing in for "no missing settings" printed the word null on the
        # page — on the correctly-configured path, which is the normal one.
        check("and prints no literal null under the table",
              "null" not in page.inner_text("#pay-health"),
              page.inner_text("#pay-health")[:300])
        page.click("#tabs button[data-tab=audit]")
        page.wait_for_selector("#audit-list table", timeout=15000)
        audit_text = page.inner_text("#audit-list")
        for want in ("account.ban", "node.add", "settings.update", "notice.create"):
            check(f"audit shows {want}", want in audit_text, audit_text[:400])
        check("the audit log does not display secret values",
              "sk_live_supersecret" not in audit_text)

        print("\n[7b] operational events")
        page.click("#tabs button[data-tab=events]")
        page.wait_for_selector("#events-list", timeout=15000)
        ev_text = page.inner_text("#events-list")
        check("the events panel renders", bool(ev_text.strip()), ev_text[:200])
        # An operator with no webhook configured should be told that, not left
        # assuming these reach them somehow.
        check("it says whether alerts are being pushed anywhere",
              "webhook" in page.inner_text("#events-webhook").lower(),
              page.inner_text("#events-webhook"))
        check("the tab exists next to the audit log",
              page.is_visible("#tabs button[data-tab=events]"))

        print("\n[7c] layout")
        # Each child of a flex container is its own item, so the leading space
        # of the " — secret" marker collapsed and labels read "API KEY— secret".
        page.click("#tabs button[data-tab=settings]")
        page.wait_for_selector("#settings-groups label", timeout=15000)
        # Measured, not read off a property — getComputedStyle().columnGap
        # comes back as the empty string in some headless builds, which is not
        # in ("normal", "0px") and so passed with the rule deleted.
        #
        # Two clones of the same label, laid out side by side at max-content
        # inside the real .set-grid (the rule is a descendant selector, so a
        # clone parked anywhere else is not styled at all), one with the gap
        # zeroed. The difference IS the separation. Nothing here depends on
        # where a line happens to break, which is what made the first version
        # of this check report 0px on a loaded runner and 3.47px locally.
        gap = page.eval_on_selector("#settings-groups label:has(.dim)", """
            e => {
              const grid = e.closest('.set-grid');
              if (!grid) return null;
              const probe = document.createElement('div');
              probe.style.cssText =
                  'position:absolute;left:-9999px;top:0;display:block';
              const a = e.cloneNode(true), b = e.cloneNode(true);
              for (const c of [a, b]) { c.style.width = 'max-content'; }
              b.style.columnGap = '0px'; b.style.rowGap = '0px';
              probe.appendChild(a); probe.appendChild(b);
              grid.appendChild(probe);
              const w = a.getBoundingClientRect().width -
                        b.getBoundingClientRect().width;
              probe.remove();
              return Math.round(w * 100) / 100;
            }""")
        check("a secret marker is separated from its label",
              gap is not None and gap >= 2,
              f"{gap}px of separation the gap rule is responsible for")
        # A grid item's automatic minimum is its min-content, so a card holding
        # a table refused to shrink and pushed the page sideways at phone width.
        # The tables scroll inside .table-wrap; the page must not.
        page.set_viewport_size({"width": 400, "height": 900})
        for tab in ("overview", "accounts", "nodes", "payments",
                    "notices", "settings", "events", "audit"):
            page.click(f"#tabs button[data-tab={tab}]")
            page.wait_for_timeout(400)
            sw, cw = page.evaluate(
                "[document.documentElement.scrollWidth,"
                " document.documentElement.clientWidth]")
            check(f"{tab} does not scroll sideways on a phone", sw <= cw + 1,
                  f"scrollWidth {sw} > clientWidth {cw}")
        page.set_viewport_size({"width": 1280, "height": 900})

        print("\n[8] session")
        check("no JS errors anywhere in the session", not errors, errors[:3])
        page.click("#logout")
        page.wait_for_selector("#gate:not(.hidden)", timeout=20000)
        check("signing out returns to the gate", True)
        check("and now shows the login form, not setup",
              page.is_visible("#login-form"), "expected login form")
        page.fill("#li-user", "ops")
        page.fill("#li-pass", PASSWORD)
        page.click("#login-form button[type=submit]")
        page.wait_for_selector("#app:not(.hidden)", timeout=25000)
        check("signing back in works", True)
finally:
    if browser:
        try: browser.close()
        except Exception: pass
    srv.shutdown(); H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
