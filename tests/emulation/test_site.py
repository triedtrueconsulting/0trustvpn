#!/usr/bin/env python3
"""
The website as a whole: do its links resolve, and do its claims match the code?

The landing page shipped with "47 mesh nodes across 32 countries" against a
locked three-node design, a port-forwarding feature that does not exist, and
currencies that were dropped. Marketing copy drifts from the product silently
because nothing executes it. This module executes it.
"""
import glob, http.server, functools, os, re, shutil, sys, tempfile, threading, urllib.error, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

WEB = os.path.join(H.REPO, "web")
PORT = H.pick_port()
TMP = tempfile.mkdtemp(prefix="0trust-site-")
DB = os.path.join(TMP, "0trust.db")
os.environ["ZTV_DB_PATH"] = DB
os.environ["ZTV_TRIAL_SECRET"] = "site-secret"
os.environ["ZTV_TRIAL_POW_BITS"] = "10"
sys.path.insert(0, os.path.join(H.REPO, "api"))
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=2)


class Site(http.server.SimpleHTTPRequestHandler):
    """web/ plus the nginx path rewrites, so /trial and /privacy resolve."""
    ROUTES = {"/trial": "/trial.html", "/status": "/status.html",
              "/download": "/download.html", "/help": "/help.html",
              "/privacy": "/privacy.html", "/terms": "/terms.html",
              "/audit": "/audit.html", "/security-policy": "/security-policy.html"}

    def log_message(self, *a): pass

    def do_GET(self):
        path = self.path.split("?")[0].split("#")[0]
        if path.startswith("/api/"):
            try:
                with urllib.request.urlopen(H.API + self.path, timeout=15) as r:
                    data, status = r.read(), r.status
            except urllib.error.HTTPError as e:
                data, status = e.read(), e.code
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers(); self.wfile.write(data); return
        if path == "/surf":
            # Served by the separate proxy service in production; nginx routes
            # it there. Stub a 200 so link checking is meaningful here.
            body = b"<html><body>surf</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body); return
        self.path = self.ROUTES.get(path, self.path)
        return super().do_GET()


srv = http.server.ThreadingHTTPServer(
    ("127.0.0.1", PORT), functools.partial(Site, directory=WEB))
threading.Thread(target=srv.serve_forever, daemon=True).start()


def get(path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=15) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return 0, str(e)


try:
    pages = sorted(os.path.basename(f) for f in glob.glob(os.path.join(WEB, "*.html")))
    print(f"[1] every page loads ({len(pages)} pages)")
    for pg in pages:
        st, _ = get("/" + pg)
        check(f"{pg} loads", st == 200, st)

    print("\n[2] internal links resolve")
    seen, broken = set(), []
    for pg in pages:
        _, body = get("/" + pg)
        for href in re.findall(r'href="([^"#][^"]*)"', body):
            if href.startswith(("http://", "https://", "mailto:", "data:", "//")):
                continue
            # Not static files in web/: release artifacts appear when a
            # release is cut, /.well-known/* and the canary are served by
            # nginx from elsewhere (the canary is regenerated weekly).
            if href.startswith(("/releases/", "/.well-known/", "releases/",
                                "/canary.txt", "/canary/", "/pubkey.asc")):
                continue
            target = href if href.startswith("/") else "/" + href
            if target in seen:
                continue
            seen.add(target)
            st, _ = get(target)
            if st != 200:
                broken.append(f"{pg} -> {href} ({st})")
    check(f"no broken internal links ({len(seen)} checked)", not broken, "\n          ".join(broken))

    print("\n[3] the funnel has a door")
    _, index = get("/index.html")
    check("landing page links to the free trial", "/trial" in index)
    check("landing page links to /surf", "/surf" in index)
    check("trial page reachable", get("/trial")[0] == 200)

    print("\n[4] claims match the code")
    _, raw_idx = get("/index.html")
    # Strip HTML and script comments: a number inside a code comment that
    # explains a past mistake is not a claim made to a visitor.
    idx = re.sub(r"<!--.*?-->", "", raw_idx, flags=re.S)
    idx = re.sub(r"^\s*//.*$", "", idx, flags=re.M)
    # Derived from the code, not a hardcoded list — the supported set has
    # changed twice now, and a test that names currencies by hand goes stale
    # silently the moment it changes again.
    from payments import CURRENCIES
    NAMES = {"BTC": "Bitcoin", "ETH": "Ethereum", "XMR": "Monero",
             "ZEC": "Zcash", "LTC": "Litecoin"}
    for cur in CURRENCIES:
        check(f"{cur} is advertised", cur in idx)
    for code, name in NAMES.items():
        if code in CURRENCIES:
            continue
        check(f"unsupported currency not advertised: {name}",
              name not in idx and f" {code} " not in idx,
              [l.strip() for l in idx.splitlines()
               if name in l or f" {code} " in l][:2])

    # Nothing implements these; AllowedIPs is always 0.0.0.0/0.
    for claim in ("Port forwarding", "split tunnel", "CASH BY", "Cash by mail"):
        check(f"unbacked claim absent: {claim!r}", claim.lower() not in idx.lower(),
              [l.strip() for l in idx.splitlines() if claim.lower() in l.lower()][:2])

    # Node counts must not contradict the locked three-jurisdiction design.
    inflated = re.findall(r'\b(\d{2,})\s*(?:mesh )?nodes?\b', idx, re.I)
    check("no inflated node count in the copy", not inflated, inflated)
    countries = re.findall(r'\b(\d{2,})\s*countries\b', idx, re.I)
    check("no inflated country count in the copy", not countries, countries)

    print("\n[5] the device cap the site advertises matches the API")
    st, s = H.call("GET", "/api/v1/status/public")
    check("status endpoint serves the site", st == 200, s)
    m = re.search(r'Up to (\d+) simultaneous devices', idx)
    if m:
        check("advertised device cap matches MAX_DEVICES_PER_ACCOUNT",
              int(m.group(1)) == api_main.MAX_DEVICES_PER_ACCOUNT,
              f"site says {m.group(1)}, API cap is {api_main.MAX_DEVICES_PER_ACCOUNT}")

    print("\n[5b] the help page describes features that exist")
    _, helpp = get("/help")
    # This page once advertised `0trust connect --port 443`, a flag the client
    # has never had. Anything it tells a customer to type has to be real.
    # Prose wraps, so compare against whitespace-normalised text rather than
    # the raw bytes — otherwise a line break silently defeats the assertion.
    flat = " ".join(helpp.split())
    src = open(os.path.join(H.REPO, "client", "cmd", "0trust", "main.go")).read()
    for flag in ("--kill-switch", "--no-kill-switch", "--exit"):
        if flag in helpp:
            check(f"help mentions {flag}, and the client implements it",
                  f'"{flag}"' in src, f"{flag} is documented but not in main.go")
    check("help does not advertise the --port flag we never built",
          "--port" not in helpp, "help.html still mentions --port")
    check("help explains the no-handshake failure",
          "NOT carrying traffic" in flat, flat[:300])
    check("help is honest that macOS has no kill switch",
          "macOS" in flat and "do not have one" in flat, flat[:300])
    check("help explains that v6 is carried where the node supports it",
          "depends on the exit node" in flat, flat[:300])
    check("and that the failure mode is never a leak",
          "never IPv6 leaking" in flat, flat[:300])
    check("and that v6 is masqueraded, not a per-customer prefix",
          "tracking identifier" in flat, flat[:300])
    check("help warns the kill switch blocks the local network too",
          "local network" in flat, flat[:300])

    print("\n[6] the trial page's promises match the API's")
    _, trial = get("/trial")
    check("trial page's served fallback states the real duration",
          f'data-trial="days">{api_main.TRIAL_DAYS}<' in trial,
          f"TRIAL_DAYS={api_main.TRIAL_DAYS}")
    st, cfg = H.call("GET", "/api/v1/config")
    check("the API publishes the offer for pages to render", st == 200, cfg)
    check("published trial length matches the control plane",
          cfg["trial"]["days"] == api_main.TRIAL_DAYS, cfg)
    check("published trial label is phrased for copy",
          cfg["trial"]["label"] == api_main.duration_label(api_main.TRIAL_DAYS), cfg)
    _, home = get("/")
    check("landing page's served fallback states the real duration",
          f'data-trial="days">{api_main.TRIAL_DAYS}<' in home,
          f"TRIAL_DAYS={api_main.TRIAL_DAYS}")
    check("trial page says no email", "No email" in trial)
    check("trial page distinguishes itself from /surf", "surf" in trial.lower())
finally:
    srv.shutdown(); H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
