#!/usr/bin/env python3
"""
The desktop GUI in a real browser.

Launches the compiled `0trust gui` against a live control plane and drives it
with Chromium: claim a free trial, connect, manage devices, remove one. The
GUI is the surface most users touch and none of it is covered by the CLI
tests, so this is where its wiring gets proven.

Skips (77) without Playwright or a browser.
"""
import glob, os, re, shutil, signal, socket, subprocess, sys, tempfile, time
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
TMP = tempfile.mkdtemp(prefix="0trust-gui-")
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


gui = subprocess.Popen([BIN, "gui", "--no-browser"], env=GUI_ENV,
                       stdout=open(f"{TMP}/gui.log", "w"), stderr=subprocess.STDOUT)
browser = None
try:
    if not wait_port(GUI_PORT):
        print(open(f"{TMP}/gui.log").read()); raise SystemExit("gui did not start")

    with sync_playwright() as pw:
        launch = {}
        for cand in sorted(glob.glob("/opt/pw-browsers/chromium-*/chrome-linux/chrome")):
            launch["executable_path"] = cand
            break
        try:
            browser = pw.chromium.launch(**launch)
        except Exception as e:
            print(f"  SKIP  chromium unavailable: {e}")
            sys.exit(77)

        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(f"http://127.0.0.1:{GUI_PORT}/", timeout=30000)
        page.wait_for_selector("#view-login:not(.hidden)", timeout=20000)

        print("[1] logged-out view offers the free trial")
        check("login view shown", page.is_visible("#view-login"))
        check("trial card present", page.is_visible("#trial-card"))
        txt = " ".join(page.inner_text("#trial-card").split())
        check("trial copy says no email or card",
              "No email, no card" in txt, txt[:200])
        label = api_main.duration_label(api_main.TRIAL_DAYS)
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

        print("\n[3] connect through the GUI")
        page.click("#toggle-btn")
        page.wait_for_function(
            "() => document.getElementById('status-text').textContent.trim() !== 'Disconnected'",
            timeout=45000)
        st = page.inner_text("#status-text").strip()
        check("status leaves Disconnected", st != "Disconnected", st)
        check("device count rose to 1",
              page.inner_text("#kv-dev").strip().startswith("1"),
              page.inner_text("#kv-dev"))

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
            check("and it says the running tunnel is not covered yet",
                  "next time you connect" in page.inner_text("#ks-hint"),
                  page.inner_text("#ks-hint"))
            # The message has to survive the 3s poll repainting the panel.
            page.wait_for_timeout(3500)
            check("and keeps saying so after the next poll",
                  "next time you connect" in page.inner_text("#ks-hint"),
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

        print("\n[4] device manager lists and removes")
        page.click("#devices-btn")
        page.wait_for_selector("#devices-modal:not(.hidden)", timeout=15000)
        page.wait_for_function(
            "() => !document.getElementById('devices-list').textContent.includes('Loading')",
            timeout=20000)
        listed = page.inner_text("#devices-list")
        check("this device is listed", "this device" in listed, listed[:300])
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
        rows = page.query_selector_all("#devices-list .device-row")
        this_row = None
        for row in rows:
            if "this device" in row.inner_text().lower():
                this_row = row
                break
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

        check("no JS errors across the whole session", not errors, errors)
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
