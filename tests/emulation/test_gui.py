#!/usr/bin/env python3
"""
The desktop GUI in a real browser.

Launches the compiled `0trust gui` against a live control plane and drives it
with Chromium: claim a free trial, connect, manage devices, remove one. The
GUI is the surface most users touch and none of it is covered by the CLI
tests, so this is where its wiring gets proven.

Skips (77) without Playwright or a browser.
"""
import glob, os, re, shutil, signal, socket, sqlite3, subprocess, sys, time
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

GUI_PORT = 51827
EMU = os.path.dirname(os.path.abspath(__file__))
TMP = H.tempdir("0trust-gui-")
DB = os.path.join(TMP, "0trust.db")
HOME = os.path.join(TMP, "home"); os.makedirs(HOME)
BIN = os.path.join(TMP, "0trust")

os.environ["ZTV_DB_PATH"] = DB
os.environ["ZTV_TRIAL_SECRET"] = "gui-test-secret"
os.environ["ZTV_TRIAL_POW_BITS"] = "14"
os.environ["ZTV_TRIAL_MAX_DEVICES"] = "2"
sys.path.insert(0, os.path.join(H.REPO, "api"))
import main as api_main; api_main.init_db()
H.seed_nodes(DB)

subprocess.run(["go", "build", "-o", BIN, "./cmd/0trust"],
               cwd=os.path.join(H.REPO, "client"), check=True,
               env={**os.environ, "CGO_ENABLED": "0"})
H.boot(DB, workers=2)

GUI_ENV = {
    **os.environ,
    "HOME": HOME,
    "XDG_CONFIG_HOME": os.path.join(HOME, ".config"),
    "ZTV_API_BASE": H.API,
    "PATH": os.path.join(EMU, "bin") + ":" + os.environ["PATH"],
    "STUB_LOG": f"{TMP}/stub.log", "STUB_STATE": TMP, "WG_CONFIG_DIR": TMP,
}


def wait_port(port, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


# The GUI's listen address is fixed, so this module cannot pick a free port
# the way the rest of the suite does. Say so plainly when something already
# holds it: `0trust gui` now hands a second launch the running instance rather
# than erroring, which is right for a user double-clicking the Start Menu
# shortcut and wrong for a test — it would silently drive somebody else's GUI.
with socket.socket() as _probe:
    if _probe.connect_ex(("127.0.0.1", GUI_PORT)) == 0:
        raise SystemExit(
            f"port {GUI_PORT} is already in use — a stale `0trust gui` from an "
            "earlier run, most likely. Kill it and re-run:\n"
            f"    pkill -f '0trust gui'")

# wg-quick needs root, and so does the GUI's connect handler. Which half of
# this module can run is decided by that, not by anything about the browser.
IS_ROOT = os.geteuid() == 0
CONNECTED = False

gui = subprocess.Popen([BIN, "gui", "--no-browser"], env=GUI_ENV,
                       stdout=open(f"{TMP}/gui.log", "w"), stderr=subprocess.STDOUT)
browser = None
try:
    if not wait_port(GUI_PORT):
        print(open(f"{TMP}/gui.log").read()); raise SystemExit("gui did not start")

    with sync_playwright() as pw:
        try:
            browser = H.launch_chromium(pw)
        except H.SkipModule as e:
            print(f"  SKIP  {e}")
            sys.exit(77)

        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        # Console errors as well as uncaught exceptions. A failed fetch never
        # reaches pageerror, so a request that 401s on every cold start was
        # invisible to this module for its whole life — and console noise is
        # what hides the errors worth seeing.
        console_errors = []
        page.on("console",
                lambda m: m.type == "error" and console_errors.append(m.text))
        requests = []
        page.on("requestfinished",
                lambda r: requests.append((r.method, r.url)))
        page.goto(f"http://127.0.0.1:{GUI_PORT}/", timeout=30000)
        page.wait_for_selector("#view-login:not(.hidden)", timeout=20000)

        # ------------------------------------------------------------------
        # Every <input> carries a type, because the stylesheet keys on it.
        #
        # app.css styles `input[type="text"]`, and an attribute selector does
        # not match an element that lacks the attribute. The top-up address
        # field had no type: it behaved as text and rendered as the browser
        # default — a cramped white-bordered box in the middle of a dark card,
        # holding the one string in the payment flow a customer has to read
        # exactly. Nothing caught it because nobody had looked at that panel.
        # ------------------------------------------------------------------
        # The window this GUI serves is a browser tab, and it had no icon:
        # the browser asked for /favicon.ico, got a 404, and showed the
        # generic blank-page glyph on the one window that is the product.
        # Both names are asserted directly rather than inferred from the
        # console — with the <link> tag present a browser never falls back to
        # /favicon.ico, so a broken .ico route is invisible from the page.
        print("[0b] the tab has the brand mark")
        for path in ("/favicon.png", "/favicon.ico"):
            resp = page.request.get(f"http://127.0.0.1:{GUI_PORT}{path}")
            check(f"{path} is served",
                  resp.status == 200
                  and resp.headers.get("content-type", "").startswith("image/"),
                  f"{resp.status} {resp.headers.get('content-type')}")
            check(f"{path} is a real PNG, not an empty file",
                  resp.body()[:8] == b"\x89PNG\r\n\x1a\n" and len(resp.body()) > 200,
                  f"{len(resp.body())} bytes")
        check("and the document declares it",
              'rel="icon"' in page.content(),
              "without the link the browser only tries /favicon.ico")

        print("[0a] no input falls out of the stylesheet")
        untyped = page.eval_on_selector_all(
            "input",
            "els => els.filter(e => !e.getAttribute('type'))"
            "        .map(e => e.id || e.className || e.outerHTML.slice(0,60))")
        styled_selector_covers_them = "input:not([type])" in open(
            os.path.join(H.REPO, "client", "internal", "gui", "assets",
                         "app.css")).read()
        check("either every input is typed, or the stylesheet covers untyped ones",
              not untyped or styled_selector_covers_them,
              f"untyped inputs: {untyped} — and app.css only styles "
              f"input[type=\"text\"], so these render as browser defaults")

        print("[0] a cold, signed-out load is quiet")
        page.wait_for_timeout(1500)
        check("nothing errors in the console before anyone signs in",
              not console_errors,
              f"{console_errors} — this was a 401 from /api/notices, asked "
              f"for while logged out on every single start")
        asked = [u for m, u in requests if u.endswith("/api/notices")]
        check("and notices are not requested while signed out",
              not asked,
              "there is no token to send and nowhere to show the result")

        print("[1] logged-out view offers the free trial")
        check("login view shown", page.is_visible("#view-login"))
        check("trial card present", page.is_visible("#trial-card"))
        txt = " ".join(page.inner_text("#trial-card").split())
        check("trial copy says no email or card",
              "No email, no card" in txt, txt[:200])
        label = api_main.duration_label(api_main.TRIAL_DAYS_DEFAULT)
        check(f"trial copy states the configured length ({label})",
              label in txt, txt[:200])

        print("\n[2] claiming the trial signs you in")
        page.click("#trial-btn")
        page.wait_for_selector("#view-main:not(.hidden)", timeout=90000)
        check("main view appears after the trial", page.is_visible("#view-main"))
        sub = page.inner_text("#kv-sub").strip()
        check("subscription row marks it a trial", "trial" in sub.lower(), sub)
        dev = page.inner_text("#kv-dev").strip()
        check("device cap shows the trial limit of 2", dev.endswith("/ 2"), dev)
        check("no JS errors so far", not errors, errors)
        check("and none in the console either", not console_errors,
              console_errors)

        # refreshNotices' own comment: "this banner is the only way a renewal
        # warning reaches anyone. If it is not rendered here, it is not
        # delivered at all." The only fetch used to happen at boot, while
        # logged out, where it 401'd — after that the next attempt was 120
        # seconds away, so signing in, reading your expiry and closing the
        # window inside two minutes showed you nothing.
        page.wait_for_timeout(1200)
        after = [u for m, u in requests if u.endswith("/api/notices")]
        check("signing in fetches notices immediately, not in two minutes",
              after,
              "sweep.py posts the renewal warning and this banner is the only "
              "surface that shows it")

        print("\n[3] connect through the GUI")
        # Bringing a tunnel up needs root — wg-quick writes routes — and the
        # GUI refuses without it rather than pretending. So there are two
        # correct outcomes here, and this module used to assert only the one
        # it happened to get on a developer's root shell: run unprivileged, it
        # sat waiting 45 seconds for a status change that was never coming and
        # failed with a bare Playwright timeout that explained nothing.
        #
        # Unprivileged is also what most people will hit first, so the message
        # they get is worth an assertion of its own.
        # Blank any toast still on screen from the trial step, or the wait
        # below matches that one and asserts nothing about this click.
        page.evaluate("() => { const t = document.getElementById('toast');"
                      "        t.textContent = ''; t.classList.add('hidden'); }")
        page.click("#toggle-btn")
        if IS_ROOT:
            page.wait_for_function(
                "() => document.getElementById('status-text').textContent.trim() !== 'Disconnected'",
                timeout=45000)
            st = page.inner_text("#status-text").strip()
            check("status leaves Disconnected", st != "Disconnected", st)
            check("device count rose to 1",
                  page.inner_text("#kv-dev").strip().startswith("1"),
                  page.inner_text("#kv-dev"))
            CONNECTED = True
        else:
            page.wait_for_function(
                "() => { const t = document.getElementById('toast');"
                "        return t && !t.classList.contains('hidden')"
                "               && t.textContent.trim().length > 0; }",
                timeout=20000)
            msg = page.inner_text("#toast").strip()
            check("without root the GUI says why, rather than doing nothing",
                  "root" in msg.lower() or "sudo" in msg.lower(), msg)
            check("and the status stays honest about being disconnected",
                  page.inner_text("#status-text").strip() == "Disconnected",
                  page.inner_text("#status-text"))
            print("      (not root: the tunnel path is exercised when this "
                  "module runs as root)")

        print("\n[3b] the kill switch is reachable without the CLI")
        # A safety control that only exists as a command-line flag is one most
        # customers will never turn on.
        check("kill-switch toggle is present", page.is_visible("#ks-toggle"))
        check("it starts off", page.is_checked("#ks-toggle") is False)
        hint = page.inner_text("#ks-hint")
        check("the off state says what that means",
              "falls back" in hint or "not available" in hint.lower(), hint)
        if not page.is_disabled("#ks-toggle"):
            page.check("#ks-toggle")
            page.wait_for_function(
                "() => document.getElementById('ks-label').textContent === 'on'",
                timeout=8000)
            check("turning it on sticks", page.is_checked("#ks-toggle"))
            # The rules are wg-quick PostUp/PreDown, so they land on the next
            # connect. Tearing a live tunnel down under someone who ticked a
            # box would be a worse surprise than the delay.
            if CONNECTED:
                check("and it says the running tunnel is not covered yet",
                      "next time you connect" in page.inner_text("#ks-hint"),
                      page.inner_text("#ks-hint"))
                # The message has to survive the 3s poll repainting the panel.
                page.wait_for_timeout(3500)
                check("and keeps saying so after the next poll",
                      "next time you connect" in page.inner_text("#ks-hint"),
                      page.inner_text("#ks-hint"))
            else:
                # Nothing is running, so nothing is uncovered. Saying a change
                # is "not in force yet" with no tunnel up would be the same
                # kind of lie in the other direction.
                check("with no tunnel it does not claim something is pending",
                      "next time you connect" not in page.inner_text("#ks-hint"),
                      page.inner_text("#ks-hint"))
            page.uncheck("#ks-toggle")
            page.wait_for_function(
                "() => document.getElementById('ks-label').textContent === 'off'",
                timeout=8000)
            check("and off again", page.is_checked("#ks-toggle") is False)

        print("\n[3c] the window has no browser-default chrome left in it")
        # The kill switch shipped as a raw <input type=checkbox>: a white
        # square, the one control in a warm-dark window that looked like it
        # came from somewhere else — on the one setting where a customer needs
        # to be certain which state they are in.
        appearance = page.eval_on_selector(
            "#ks-toggle",
            "e => getComputedStyle(e).appearance || getComputedStyle(e).webkitAppearance")
        check("the kill switch is a styled control, not an OS checkbox",
              appearance == "none", appearance)
        # Region labels ran under the dropdown chevron once we drew our own.
        clipped = page.eval_on_selector_all(
            "select",
            "els => els.filter(e => e.scrollWidth > e.clientWidth + 1)"
            ".map(e => e.id || e.name)")
        check("no select clips its own text", clipped == [], clipped)
        # Every interactive control needs a visible focus state or the window
        # is unusable from the keyboard. It has to be reached BY keyboard:
        # :focus-visible deliberately does not fire for a programmatic focus()
        # or a mouse click, which is the whole point of using it.
        page.click("body")
        reached = False
        for _ in range(40):
            page.keyboard.press("Tab")
            if page.evaluate("() => document.activeElement && document.activeElement.id") \
                    == "ks-toggle":
                reached = True
                break
        check("the kill switch is reachable by keyboard", reached)
        if reached:
            ring = page.evaluate(
                "() => getComputedStyle(document.activeElement).boxShadow")
            check("and shows a focus ring when it is",
                  ring not in ("none", "", None), ring)

        print("\n[3d] the window survives being made small, and the toast "
              "does not sit on the buttons")
        # This is a browser window: people narrow it and half-tile it. Each
        # of these was found by photographing the real GUI, not by reading it.

        # 1. The toast is fixed to the viewport. At bottom:24px it landed
        #    exactly on the account card's button row — it covered "Add mobile
        #    device" and "Sign out", and carrying a z-index they do not, it
        #    swallowed their clicks as well.
        page.evaluate("""() => { const t = document.querySelector('#toast');
            t.textContent = 'probe'; t.classList.remove('hidden'); }""")
        page.wait_for_timeout(120)
        pe = page.eval_on_selector("#toast", "e => getComputedStyle(e).pointerEvents")
        check("the toast is never a click target", pe == "none", pe)
        for sel in ("#export-btn", "#logout-btn", "#devices-btn"):
            hit = page.evaluate("""(s) => {
                const A = document.querySelector('#toast'), B = document.querySelector(s);
                if (!A || !B) return null;
                const a = A.getBoundingClientRect(), b = B.getBoundingClientRect();
                return !(a.right <= b.left || a.left >= b.right ||
                         a.bottom <= b.top || a.top >= b.bottom);
            }""", sel)
            check(f"the toast does not cover {sel}", hit is False, hit)
        page.evaluate("() => document.querySelector('#toast').classList.add('hidden')")

        # 2. Nothing may leave the window sideways. Measured before the fix:
        #    clean to 400px, and at 360 the Connect button reached 392px in a
        #    360px viewport because .status-block's grid could not shrink it.
        for w in (1100, 760, 480, 400, 360, 320):
            page.set_viewport_size({"width": w, "height": 820})
            page.wait_for_timeout(250)
            over = page.evaluate("""() => {
                const d = document.documentElement;
                const bad = [];
                document.querySelectorAll('button,select,input,.card,.kv-row').forEach(e => {
                    const b = e.getBoundingClientRect();
                    if (b.width > 0 && (b.right > d.clientWidth + 0.5 || b.left < -0.5))
                        bad.push((e.id || e.className) + '@' + Math.round(b.right));
                });
                return {scroll: d.scrollWidth > d.clientWidth, bad: bad.slice(0, 3)};
            }""")
            check(f"nothing overflows the window at {w}px",
                  not over["scroll"] and not over["bad"], over)
        page.set_viewport_size({"width": 1100, "height": 820})

        print("\n[4] device manager lists and removes")
        page.click("#devices-btn")
        page.wait_for_selector("#devices-modal:not(.hidden)", timeout=15000)
        page.wait_for_function(
            "() => !document.getElementById('devices-list').textContent.includes('Loading')",
            timeout=20000)
        listed = page.inner_text("#devices-list")
        if CONNECTED:
            check("this device is listed", "this device" in listed, listed[:300])
        else:
            # The keypair is created by connect, so there is genuinely nothing
            # here yet — and an empty list has to say so rather than looking
            # like a failed load.
            check("an account with no devices says so plainly",
                  "no devices" in listed.lower(), listed[:300])
        count = page.inner_text("#devices-count")
        check("slot count reflects the trial cap", "of 2 slots" in count, count)

        # Register a second device out of band so there is one safe to remove.
        other = H.genkey()
        tok = None
        import sqlite3, json as _json
        state_path = os.path.join(HOME, ".config", "0trust", "state.json")
        tok = _json.load(open(state_path))["token"]
        st2, _ = H.call("POST", "/api/v1/wg/register",
                        {"pubkey": other, "device_name": "sidecar", "region": "rey"},
                        headers={"X-Account-Token": tok})
        check("second device registered out of band", st2 == 200, st2)

        page.click("#devices-close")
        page.click("#devices-btn")
        try:
            page.wait_for_function(
                "() => document.getElementById('devices-list').textContent.toLowerCase().includes('sidecar')",
                timeout=15000)
        except Exception:
            pass
        listed2 = page.inner_text("#devices-list")
        err_txt = page.inner_text("#devices-err")
        check("new device appears in the list", "sidecar" in listed2.lower(),
              f"list={listed2!r} err={err_txt!r}")
        check("device names are not uppercased by CSS", "sidecar" in listed2,
              f"rendered as {[l for l in listed2.splitlines() if 'idecar' in l.lower()]}")

        page.on("dialog", lambda d: d.accept())
        rows = page.query_selector_all("#devices-list .device-row")
        target = None
        for row in rows:
            if "sidecar" in row.inner_text().lower():
                target = row
                break
        check("found the sidecar row", target is not None)
        if target:
            target.query_selector("button").click()
            page.wait_for_function(
                "() => !document.getElementById('devices-list').textContent.toLowerCase().includes('sidecar')",
                timeout=20000)
            check("sidecar removed from the list", True)
            st3, devs = H.call("GET", "/api/v1/devices",
                               headers={"X-Account-Token": tok})
            check("control plane agrees it is gone",
                  all(d["pubkey"] != other for d in devs), devs)

        print("\n[5] removing THIS device tears the tunnel down")
        if not CONNECTED:
            print("      (needs a tunnel, which needs root — skipped here)")
        else:
            # The wait above only established that "sidecar" is gone, and an
            # EMPTY list satisfies that too: loadDevices() writes "Loading…"
            # into #devices-list before it awaits the API, so there is a window
            # after every delete where the list has no .device-row at all.
            # Sampling straight after the delete lands in that window roughly
            # at random — which is how this section failed on a loaded runner
            # and passed on the next run with nothing to explain it. Wait for
            # the state the assertion needs, then read it.
            page.wait_for_function(
                "() => { const l = document.getElementById('devices-list');"
                " return l.querySelectorAll('.device-row').length > 0"
                " && l.textContent.toLowerCase().includes('this device'); }",
                timeout=20000)
        rows = page.query_selector_all("#devices-list .device-row") if CONNECTED else []
        this_row = None
        for row in rows:
            if "this device" in row.inner_text().lower():
                this_row = row
                break
        if CONNECTED:
            check("found this device's row", this_row is not None)
        if this_row:
            this_row.query_selector("button").click()
            page.wait_for_function(
                "() => document.getElementById('devices-list').textContent.includes('No devices')",
                timeout=25000)
            check("device list is now empty", True)
            page.click("#devices-close")
            page.wait_for_function(
                "() => document.getElementById('status-text').textContent.trim() === 'Disconnected'",
                timeout=25000)
            check("tunnel shows disconnected after removing self", True)

        print("\n[6] a second launch hands over the running instance")
        # The Start Menu shortcut, the desktop icon and the Windows autostart
        # entry all run the same `0trust gui`. A user who clicks one while it
        # is already running used to get a listen(): address already in use.
        second = subprocess.run([BIN, "gui", "--no-browser"], env=GUI_ENV,
                                capture_output=True, text=True, timeout=30)
        check("the second `0trust gui` exits cleanly", second.returncode == 0,
              (second.stdout + second.stderr)[-300:])
        check("and says the GUI is already running",
              "already running" in second.stdout, second.stdout[-200:])
        check("without taking the port from the first",
              wait_port(GUI_PORT, timeout=5))
        page.reload()
        page.wait_for_selector("#view-main:not(.hidden)", timeout=20000)
        check("the original instance is still serving", True)

        print("\n[5b] the window does not claim privacy the deployment lacks")
        # On a single-VPS test deployment the control plane resolves entry and
        # exit to the same machine and returns same_host. The CLI and both
        # mobile apps already refused to print the multi-hop privacy claim
        # there; the window was the one surface that went on making it.
        honest = page.evaluate("""() => {
            const before = document.querySelector('#route-hint').textContent;
            const saved = state.same_host;
            // Multi-hop selected, on a deployment that cannot deliver it.
            document.querySelector('#exit-select').value = 'rey';
            state.same_host = true;
            updateRouteHint();
            const withFlag = document.querySelector('#route-hint').textContent;
            state.same_host = false;
            updateRouteHint();
            const withoutFlag = document.querySelector('#route-hint').textContent;
            state.same_host = saved;
            return {before, withFlag, withoutFlag};
        }""")
        check("a real mesh still gets the multi-hop claim",
              "never sees your IP" in honest["withoutFlag"], honest)
        check("a one-box deployment does NOT",
              "never sees your IP" not in honest["withFlag"], honest)
        check("and is told plainly that nothing is hidden",
              "SAME machine" in honest["withFlag"]
              and "nothing is hidden" in honest["withFlag"], honest)

        print("\n[6a] a message from the service reaches the window")
        # No email address exists for this account, so this banner is the only
        # delivery this product has. The feature was write-only before: an
        # operator could broadcast and nothing anywhere rendered it.
        import sqlite3 as _sq
        nc = _sq.connect(DB)
        acct = nc.execute(
            "SELECT id FROM accounts ORDER BY id DESC LIMIT 1").fetchone()[0]
        nc.execute("""INSERT INTO notices
                      (account_id, severity, subject, body, created_at,
                       expires_at, created_by)
                      VALUES (?, 'urgent', 'Your subscription has ended',
                              'Top up and the same token works again.',
                              ?, 0, 'sweeper:expired')""",
                   (acct, int(time.time())))
        nc.commit(); nc.close()

        page.evaluate("() => refreshNotices()")
        page.wait_for_selector("#notices .notice", timeout=15000)
        text = page.inner_text("#notices")
        check("the notice is rendered", "subscription has ended" in text, text)
        check("with its body", "same token works again" in text, text)
        sev = page.eval_on_selector("#notices .notice", "e => e.className")
        check("and carries its severity", "urgent" in sev, sev)
        check("the banner is visible, not just present",
              page.is_visible("#notices"))

        page.click("#notices .dismiss")
        page.wait_for_timeout(1200)
        check("dismissing clears it",
              page.eval_on_selector_all("#notices .notice", "e => e.length") == 0,
              page.inner_text("#notices"))
        check("and the banner hides itself again",
              not page.is_visible("#notices"))

        print("\n[6c] the customer can act on the renewal notice")
        # [6a] proved the warning ARRIVES. It said "top up", and the window
        # offered no way to. A notice a customer cannot act on from the
        # surface it appears on is half a feature.
        page.click("#topup-btn")
        page.wait_for_selector("#topup-panel:not(.hidden)", timeout=15000)
        terms = page.inner_text("#topup-terms")
        # inner_text returns what is RENDERED, and the stylesheet uppercases
        # buttons — so this compares case-insensitively rather than against
        # the case in the source.
        check("the terms on offer are shown",
              "month" in terms.lower() and "$" in terms, terms)
        # They must come from PRICING, not from a constant in the page. Read
        # the live config and require every term to appear.
        import json as _json, urllib.request as _u
        cfg = _json.loads(_u.urlopen(H.API + "/api/v1/config", timeout=10).read())
        pricing = cfg.get("pricing") or []
        check("the control plane publishes its pricing", bool(pricing), cfg.keys())
        missing = [p for p in pricing
                   if f"${p['usd']:g}" not in terms.replace(".00", "")]
        check("every term the API sells is offered, at the API's price",
              not missing,
              f"{missing} absent from {terms!r} — a price written into a "
              "client is bug class #11, and here it is money")

        n_before = int(sqlite3.connect(DB).execute(
            "SELECT COUNT(*) FROM invoices").fetchone()[0])
        page.click("#topup-terms button")
        page.wait_for_selector("#topup-detail:not(.hidden)", timeout=20000)
        addr = page.input_value("#topup-address")
        check("an address to pay is shown", len(addr) > 10, addr)
        check("with the amount to send", "$" in page.inner_text("#topup-amount"),
              page.inner_text("#topup-amount"))
        n_after = int(sqlite3.connect(DB).execute(
            "SELECT COUNT(*) FROM invoices").fetchone()[0])
        check("exactly one invoice was opened", n_after == n_before + 1,
              f"{n_before} -> {n_after}")

        # Closing must not cancel a payment in flight, and the panel must say
        # so — somebody who sent coins and closed the window has still paid.
        check("the panel says closing does not cancel the payment",
              "does not cancel" in page.inner_text("#topup-note"),
              page.inner_text("#topup-note"))
        page.click("#topup-close")
        page.wait_for_timeout(500)
        check("closing hides the panel", not page.is_visible("#topup-panel"))
        n_end = int(sqlite3.connect(DB).execute(
            "SELECT COUNT(*) FROM invoices").fetchone()[0])
        check("and opens no further invoice", n_end == n_after,
              f"{n_after} -> {n_end}")

        print("\n[6b] every dialog is actually a dialog")
        # The Devices dialog was marked up as .modal-box and the stylesheet
        # only ever defined .modal-inner, so it rendered as bare text floating
        # on the backdrop: no panel, no border, no width cap. Nothing caught
        # it because the other checks only assert on content. A dialog has to
        # LOOK like one, so assert on the painted result.
        for mid, opener, closer in (("#devices-modal", "#devices-btn", "#devices-close"),
                                    ("#export-modal", "#export-btn", "#export-close")):
            page.click(opener)
            page.wait_for_selector(f"{mid}:not(.hidden)", timeout=15000)
            page.wait_for_timeout(350)
            panel = page.evaluate("""(m) => {
                const p = document.querySelector(m).firstElementChild;
                const c = getComputedStyle(p);
                const r = p.getBoundingClientRect();
                const transparent = c.backgroundColor === 'transparent' ||
                                    /rgba\(0,\s*0,\s*0,\s*0\)/.test(c.backgroundColor);
                return {cls: p.className, bg: c.backgroundColor, transparent,
                        border: c.borderTopWidth, width: r.width,
                        capped: r.width <= 520};
            }""", mid)
            check(f"{mid} paints a panel behind its content",
                  not panel["transparent"], panel)
            check(f"{mid} has a border", panel["border"] != "0px", panel)
            check(f"{mid} is a dialog, not the full window width",
                  panel["capped"], panel)
            page.click(closer)
            page.wait_for_timeout(250)

        print("\n[7] the QR dialog in a short window")
        # Last, because creating an export consumes a device slot and the
        # trial cap is 2 — run earlier it starves the device-manager tests.
        page.set_viewport_size({"width": 1100, "height": 600})
        page.click("#export-btn")
        page.wait_for_selector("#export-modal:not(.hidden)", timeout=15000)
        page.click("#export-go")
        page.wait_for_selector("#export-step2:not(.hidden)", timeout=30000)
        page.wait_for_timeout(600)
        box = page.evaluate("""() => {
            const m = document.querySelector('#export-modal .modal-inner');
            const r = m.getBoundingClientRect();
            return {top: r.top, bottom: r.bottom, vh: window.innerHeight,
                    fits: r.top >= -0.5 && r.bottom <= window.innerHeight + 0.5};
        }""")
        check("the QR dialog fits a 600px-tall window", box["fits"], box)
        # Fitting is not enough: the whole point of the dialog is the QR and
        # the fallback copy button, and both have to be on screen without
        # hunting for a scrollbar. This is the mobile-onboarding flow.
        seen = page.evaluate("""() => {
            const out = {};
            for (const s of ['#export-qr', '#export-copy']) {
                const b = document.querySelector(s).getBoundingClientRect();
                out[s] = b.top >= -0.5 && b.bottom <= window.innerHeight + 0.5;
            }
            return out;
        }""")
        check("the QR itself is fully visible there", seen["#export-qr"], seen)
        check("and so is the copy-config fallback", seen["#export-copy"], seen)
        page.click("#export-close")
        page.set_viewport_size({"width": 1100, "height": 820})
        page.wait_for_timeout(300)

        check("no JS errors across the whole session", not errors, errors)
    print("\n[offline] the window renders without the internet")
    # index.html linked fonts.googleapis.com. In a desktop app that is wrong
    # twice: the window cannot render properly without a connection —
    # including while the tunnel it exists to manage is down, which is exactly
    # when somebody opens it — and a VPN client calling Google on every launch
    # is the opposite of the product. The faces are embedded in the binary now.
    src = open(os.path.join(H.REPO, "client", "internal", "gui",
                            "assets", "index.html"), encoding="utf-8").read()
    check("the GUI asks for no external origin",
          "fonts.googleapis" not in src and "fonts.gstatic" not in src,
          [l for l in src.splitlines() if "http" in l and "//" in l][:3])
    check("and links the embedded faces instead",
          "/fonts/faces.css" in src, src[:400])

    gui_go = open(os.path.join(H.REPO, "client", "internal", "gui", "gui.go"),
                  encoding="utf-8").read()
    check("the fonts are embedded in the binary",
          "//go:embed assets/fonts" in gui_go, "nothing embeds them")
    check("and served on /fonts/", '"/fonts/"' in gui_go, "no route serves them")

    fdir = os.path.join(H.REPO, "client", "internal", "gui", "assets", "fonts")
    check("the face files are committed", os.path.isdir(fdir))
    if os.path.isdir(fdir):
        faces = os.path.join(fdir, "faces.css")
        check("faces.css is there", os.path.exists(faces))
        if os.path.exists(faces):
            css = open(faces, encoding="utf-8").read()
            check("it points only at local files", "https://" not in css,
                  [l for l in css.splitlines() if "https://" in l][:2])
            missing = [u for u in re.findall(r'url\(/fonts/([^)]+)\)', css)
                       if not os.path.exists(os.path.join(fdir, u))]
            check("every face it names is committed", not missing, missing[:4])

finally:
    if browser:
        try: browser.close()
        except Exception: pass
    if gui.poll() is None:
        gui.send_signal(signal.SIGTERM)
        try: gui.wait(timeout=8)
        except Exception: gui.kill()
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
