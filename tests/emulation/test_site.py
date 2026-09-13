#!/usr/bin/env python3
"""
The website as a whole: do its links resolve, and do its claims match the code?

The landing page shipped with "47 mesh nodes across 32 countries" against a
locked three-node design, a port-forwarding feature that does not exist, and
currencies that were dropped. Marketing copy drifts from the product silently
because nothing executes it. This module executes it.
"""
import glob, http.server, functools, os, re, shutil, sys, threading, urllib.error, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

WEB = os.path.join(H.REPO, "web")
PORT = H.pick_port()
TMP = H.tempdir("0trust-site-")
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
    ROUTES = {"/trial": "/trial.html", "/renew": "/renew.html",
              "/status": "/status.html",
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
    #
    # Derived from the right thing, too. This used to assert every code in
    # payments.CURRENCIES appeared on the page, which is how the page came to
    # advertise four coins: CURRENCIES is what the SOFTWARE can handle, and
    # what a DEPLOYMENT can take is currencies_for(provider). Under the
    # installer default those differ by three, and the test was enforcing the
    # overstatement rather than catching it.
    import payments as _pay
    # The floor: what a deployment with nothing but WALLET_BTC can take. That
    # is what the static copy is written for, because it is the state a fresh
    # install launches in. currencies_for() used to be a constant; it now
    # reads the deployment's own configuration, so the floor has to be set up
    # rather than assumed.
    _floor_env = {"ZTV_PAYMENT_PROVIDER": "watch",
                  "WALLET_BTC": "zpub-placeholder-not-parsed-here"}
    _saved = {k: os.environ.get(k) for k in
              ("WALLET_BTC", "WALLET_ZEC", "MONERO_WALLET_RPC",
               "ZTV_PAYMENT_PROVIDER")}
    for k in ("WALLET_ZEC", "MONERO_WALLET_RPC"):
        os.environ.pop(k, None)
    os.environ.update(_floor_env)
    _pay.reset_provider()
    OFFERED = set(_pay.currencies_for("watch"))
    for k, v in _saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    _pay.reset_provider()
    NAMES = {"BTC": "Bitcoin", "ETH": "Ethereum", "XMR": "Monero",
             "ZEC": "Zcash", "LTC": "Litecoin"}
    for cur in sorted(OFFERED):
        check(f"{cur} is advertised", cur in idx)
    for code, name in NAMES.items():
        if code in OFFERED:
            continue
        check(f"currency the default install cannot take is not advertised: {name}",
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

    # The prices on the page and the prices the API invoices. Nothing tied
    # these together, so editing PRICING without editing index.html — or the
    # reverse — would quote a customer one figure and charge another at
    # checkout, with every test still green. The cards carry data-months and
    # data-price, so both sides are machine-readable.
    cards = re.findall(r'data-months="(\d+)"\s+data-price="(\d+)"', idx)
    check("the pricing cards are machine-readable", len(cards) >= 1, idx[:200])
    page_prices = {int(m): int(p) for m, p in cards}
    check("the page offers exactly the terms the API prices",
          set(page_prices) == set(api_main.PRICING),
          f"page {sorted(page_prices)} vs API {sorted(api_main.PRICING)}")
    for months, shown in sorted(page_prices.items()):
        want = api_main.PRICING.get(months)
        check(f"{months}-month price on the page matches the API",
              want is not None and float(shown) == float(want),
              f"page ${shown} vs API ${want}")
    # And the discount arithmetic, which is the figure most likely to go stale
    # when a price changes: it is derived from two others and written by hand.
    monthly = api_main.PRICING.get(1)
    # Scope each search to one card: a plain .*? runs straight past a card
    # with no saving and pairs it with the next card's figure.
    for months, body in re.findall(
            r'data-months="(\d+)"((?:(?!data-months=).)*)', idx, re.S):
        m = re.search(r'save \$(\d+)', body)
        if not m:
            continue
        months, saving = int(months), int(m.group(1))
        want = monthly * months - api_main.PRICING[months]
        check(f"the {months}-month saving is the real difference",
              float(saving) == float(want), f"page ${saving} vs actual ${want:g}")

    print("\n[5] the device cap the site advertises matches the API")
    st, s = H.call("GET", "/api/v1/status/public")
    check("status endpoint serves the site", st == 200, s)
    cap = api_main.MAX_DEVICES_PER_ACCOUNT
    m = re.search(r'Up to (\d+) simultaneous devices', idx)
    if m:
        check("advertised device cap matches MAX_DEVICES_PER_ACCOUNT",
              int(m.group(1)) == cap,
              f"site says {m.group(1)}, API cap is {cap}")

    # The landing page was the only page checked, and it is not the page that
    # matters most: terms.html is the binding document and help.html is what a
    # customer reads when the cap bites. All three state the number in their own
    # words, so an operator who changes the setting has to be made to find all
    # three rather than leaving the legal text asserting a limit the system does
    # not enforce.
    import glob as _glob
    for name in ("terms.html", "help.html", "index.html"):
        src = open(os.path.join(WEB, name)).read()
        stated = set()
        for pat in (r'up to <strong>(\d+) devices</strong>',
                    r'Up to (\d+) simultaneous devices',
                    r'<span>Devices</span><span class="mono">\d+ / (\d+)</span>'):
            stated.update(int(x) for x in re.findall(pat, src, re.I))
        if not stated:
            continue
        check(f"{name} states the real device cap", stated == {cap},
              f"{name} says {sorted(stated)}, the API enforces {cap}")

    print("\n[5b-securitytxt] the file seven pages point at")
    # security-policy, download, privacy, terms §9, help and
    # scripts/verify-release.sh all send people to /.well-known/security.txt.
    # It did not exist. The link checker skips /.well-known/ because nginx
    # serves some of it from elsewhere, so nothing noticed that the one file
    # naming the release fingerprint and the operating entity was a 404.
    stxt = os.path.join(WEB, ".well-known", "security.txt")
    check("security.txt exists", os.path.exists(stxt),
          "terms.html §9 defers naming the operating entity to this file")
    if os.path.exists(stxt):
        raw = open(stxt).read()
        fields = {}
        for line in raw.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            k, _, v = line.partition(":")
            fields.setdefault(k.strip(), []).append(v.strip())
        check("it has a Contact field (RFC 9116 requires one)",
              "Contact" in fields, sorted(fields))
        check("it has exactly one Expires field",
              len(fields.get("Expires", [])) == 1, fields.get("Expires"))
        if len(fields.get("Expires", [])) == 1:
            import datetime as _dt
            exp = _dt.datetime.fromisoformat(
                fields["Expires"][0].replace("Z", "+00:00"))
            check("and it has not passed",
                  exp > _dt.datetime.now(_dt.timezone.utc),
                  f"Expires {exp} — RFC 9116 makes an expired file invalid, "
                  "and researchers' tooling reports it as such")
        # The contact address is a locked decision; a security.txt naming a
        # different inbox sends reports somewhere nobody reads.
        check("it names the project contact address",
              "0trustvpn@proton.me" in raw, "no 0trustvpn@proton.me")
        for page in ("security-policy.html", "privacy.html", "terms.html"):
            src = open(os.path.join(WEB, page)).read()
            if "/.well-known/security.txt" in src:
                check(f"{page} links a file that now exists", True)

    print("\n[5c-vendor] the pinned third-party asset is actually pinned")
    # web/vendor/ exists so no page contacts a CDN, and docs/AUDIT.md claims
    # the files there are SRI-checked. Three things have to agree: the bytes on
    # disk, the hash in MANIFEST.txt, and the integrity= attribute on whatever
    # loads it. Update any one alone and either the claim is stale or the
    # browser silently refuses to run the script and the feature just stops.
    import base64 as _b64, hashlib as _hl
    vendor_dir = os.path.join(WEB, "vendor")
    manifest = ""
    mpath = os.path.join(vendor_dir, "MANIFEST.txt")
    if os.path.exists(mpath):
        manifest = open(mpath).read()
    all_html = "".join(open(os.path.join(WEB, p)).read() for p in pages)
    for fn in sorted(os.listdir(vendor_dir)):
        if fn == "MANIFEST.txt":
            continue
        raw = open(os.path.join(vendor_dir, fn), "rb").read()
        digest = _hl.sha256(raw).digest()
        check(f"{fn} is listed in MANIFEST.txt with its real hash",
              digest.hex() in manifest,
              f"manifest does not carry {digest.hex()}")
        sri = "sha256-" + _b64.b64encode(digest).decode()
        referenced = f"/vendor/{fn}" in all_html
        if referenced:
            check(f"{fn} is loaded with a matching integrity attribute",
                  sri in all_html,
                  f"expected integrity=\"{sri}\" — the page pins a hash that is "
                  "not this file, so the browser will refuse to run it")

    print("\n[5a] every page finishes its own styling")
    # Each page carries its own <style> block. Two of them had no rule for a
    # plain <a>, so every prose link rendered in browser-default blue,
    # underlined, on a warm-dark page — the surest sign of an unfinished site,
    # on the pages a cautious customer reads hardest before trusting anyone
    # with their traffic. A missing rule is invisible to an HTML parser, so
    # check for it directly.
    import re as _re
    public = [f for f in sorted(glob.glob(os.path.join(WEB, "*.html")))
              if os.path.basename(f) != "admin.html"]
    for f in public:
        name = os.path.basename(f)
        src = open(f).read()
        check(f"{name} styles its links",
              _re.search(r"(^|[\s,])a\s*\{[^}]*color", src, _re.M) is not None,
              "no `a { color: ... }` rule — links fall back to browser blue")
        check(f"{name} shows a keyboard focus ring",
              "focus-visible" in src,
              "nothing visible when tabbing through the page")

    # The site's mark is 0trustvpn; 0trust is the CLI's name. Four pages used
    # the wrong one, which on the pages that argue for trustworthiness is a
    # small thing that reads as carelessness.
    brands = {}
    for f in public:
        src = open(f).read()
        m = _re.search(r'class="(?:sitenav-)?brand"[^>]*>\s*(?:<span[^>]*>0</span>)?\s*<span[^>]*>([a-z]+)</span>', src)
        if m:
            brands.setdefault(m.group(1), []).append(os.path.basename(f))
    check("the brand mark is the same on every page",
          list(brands) in ([], ["trustvpn"]), brands)
    check("every page shows the wordmark", len(brands.get("trustvpn", [])) == len(public),
          "pages with no wordmark: " +
          str(sorted(set(os.path.basename(f) for f in public)
                     - set(brands.get("trustvpn", [])))))

    print("\n[5c] one nav, on every page, going to the same places")
    # Before this, the landing page had a nav bar and every other page had a
    # breadcrumb: once a visitor left the front page the only way onward was
    # the back button. A nav is only "shared" if it is literally one file —
    # nine copies of the same markup is how the copies drift apart. So: check
    # the stylesheet is linked, the markup is present, and the link set is
    # character-for-character identical everywhere.
    st, css = get("/site.css")
    check("the shared stylesheet is served", st == 200, st)
    check("it defines the nav", ".sitenav {" in css)

    navs, missing = {}, []
    for f in public:
        name = os.path.basename(f)
        src = open(f).read()
        if '/site.css' not in src or 'class="sitenav"' not in src:
            missing.append(name)
            continue
        m = _re.search(r'<nav class="sitenav">.*?</nav>', src, _re.S)
        if not m:
            missing.append(name)
            continue
        body = m.group(0)
        # The crumb and the aria-current marker are per-page by design; the
        # destinations are not.
        links = _re.findall(r'<a\s[^>]*href="([^"]+)"[^>]*>(.*?)</a>', body, _re.S)
        navs[name] = [(h, " ".join(_re.sub(r"<[^>]+>", "", t).split())) for h, t in links]
    check("every page carries the shared nav", not missing, missing)

    # Nine tab stops in front of the content on every page is exactly the
    # situation a skip link exists for, and it only works if the target it
    # names is actually on the page.
    noskip = []
    for f in public:
        src = open(f).read()
        if ('href="#content"' not in src) or ('id="content"' not in src):
            noskip.append(os.path.basename(f))
    check("every page offers a working skip-to-content link", not noskip, noskip)

    distinct = {tuple(v) for v in navs.values()}
    check("the nav goes to the same places on every page", len(distinct) <= 1,
          "\n          ".join(f"{n}: {v}" for n, v in sorted(navs.items()))
          if len(distinct) > 1 else "")

    # A nav that links to a page it cannot reach is worse than no nav; [2]
    # already fetches every href, so here just pin the destinations we mean
    # to offer, so silently dropping one from the shared markup is a failure
    # rather than an unnoticed change.
    if distinct:
        hrefs = [h for h, _ in next(iter(distinct))]
        for want in ("/", "/#how", "/#jurisdictions", "/#pricing", "/audit",
                     "/download", "/status", "/help", "/surf", "/trial"):
            check(f"the nav offers {want}", want in hrefs, hrefs)

    # The page you are on should say so, and should not offer to take you
    # to itself as though it were somewhere else.
    for name, links in sorted(navs.items()):
        src = open(os.path.join(WEB, name)).read()
        route = "/" + name[:-len(".html")]
        if route not in [h for h, _ in links]:
            continue
        m = _re.search(r'<a\s[^>]*href="' + _re.escape(route) + r'"([^>]*)>', src)
        check(f"{name} marks itself current in the nav",
              m is not None and 'aria-current="page"' in m.group(1),
              "no aria-current on its own nav link")

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
          f'data-trial="days">{api_main.TRIAL_DAYS_DEFAULT}<' in trial,
          f"TRIAL_DAYS={api_main.TRIAL_DAYS_DEFAULT}")
    st, cfg = H.call("GET", "/api/v1/config")
    check("the API publishes the offer for pages to render", st == 200, cfg)
    check("published trial length matches the control plane",
          cfg["trial"]["days"] == api_main.TRIAL_DAYS_DEFAULT, cfg)
    check("published trial label is phrased for copy",
          cfg["trial"]["label"] == api_main.duration_label(api_main.TRIAL_DAYS_DEFAULT), cfg)
    # The trial's pitch used to say the expiry was the only difference from a
    # paid account. The device cap is lower too, and a customer only found
    # that out after minting the token. Both numbers are now in the pitch, and
    # both are rendered from /config — so the served fallbacks have to be the
    # real ones for the moment before the fetch lands.
    check("published trial device cap matches the control plane",
          cfg["trial"]["max_devices"] == api_main.TRIAL_MAX_DEVICES_DEFAULT, cfg)
    check("published paid device cap matches the control plane",
          cfg["max_devices"] == api_main.MAX_DEVICES_PER_ACCOUNT, cfg)
    check("trial page's served fallback states the real trial device cap",
          f'data-trial="devs">{api_main.TRIAL_MAX_DEVICES_DEFAULT}<' in trial,
          f"TRIAL_MAX_DEVICES={api_main.TRIAL_MAX_DEVICES_DEFAULT}")
    check("trial page's served fallback states the real paid device cap",
          f'data-paid="devs">{api_main.MAX_DEVICES_PER_ACCOUNT}<' in trial,
          f"MAX_DEVICES_PER_ACCOUNT={api_main.MAX_DEVICES_PER_ACCOUNT}")
    check("the trial pitch no longer says the expiry is the only difference",
          "it just expires in" not in trial,
          [l.strip() for l in trial.splitlines() if "just expires" in l][:2])
    _, home = get("/")
    check("landing page's served fallback states the real duration",
          f'data-trial="days">{api_main.TRIAL_DAYS_DEFAULT}<' in home,
          f"TRIAL_DAYS={api_main.TRIAL_DAYS_DEFAULT}")
    check("trial page says no email", "No email" in trial)
    check("trial page distinguishes itself from /surf", "surf" in trial.lower())

    print("\n[pay] the copy names only what a deployment can actually take")
    # The landing page ran a MONERO ACCEPTED ticker and promised four coins in
    # prose; the terms named a different two; and the default provider derives
    # addresses from an xpub, which only Bitcoin's are derivable from. Three
    # claims, none of them what a fresh install can do. The checkout was
    # honest — it replaces its tabs from the invoice's real payment methods —
    # so nobody got a dead address, but everything leading them there was
    # selling a coin we could not take.
    #
    # The rule: static copy has to be true under the MOST restrictive
    # provider, because that is the installer default and the state a
    # deployment launches in. A page may upgrade itself from /api/v1/config
    # when the operator has stood up something that takes more.
    check("a BTC-only deployment offers Bitcoin and nothing else",
          OFFERED == {"BTC"},
          "the static copy is written for this configuration; if it changed, "
          "the copy has to change with it")
    floor = OFFERED

    others = {"Monero": "XMR", "Zcash": "ZEC", "Ethereum": "ETH"}

    def visible(text: str) -> str:
        """Copy a visitor reads. Comments explaining the code are not that.

        Section [4] already strips them for the same reason; this did not,
        and flagged a comment describing how the page upgrades itself as if
        it were an advertisement.
        """
        text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
        return re.sub(r"^\s*//.*$", "", text, flags=re.M)

    for page in ("/", "/terms.html", "/privacy.html", "/help.html"):
        _, raw_body = get(page)
        body = visible(raw_body)
        named = [name for name, code in others.items()
                 if code not in floor and name.lower() in body.lower()]
        check(f"{page} names no coin this deployment cannot take", not named,
              f"{named} — a fresh install can only issue a BTC address")

    # And the page has to be able to say more when there IS more, or the
    # honesty runs the other way the day BTCPay goes up.
    _, home = get("/")
    check("the landing page renders the accepted set from the API",
          'data-pay="codes"' in home and "cfg.currencies" in home,
          "hardcoded copy drifts the moment the provider changes")
    check("and the served fallback is the Bitcoin one",
          "PAID IN BITCOIN" in home, home[:200])

    # privacy.html is where someone decides whether to trust the payment
    # story, so it has to be specific rather than reassuring.
    _, priv = get("/privacy.html")
    check("privacy.html does not call Bitcoin anonymous",
          "pseudonymous, not anonymous" in priv,
          "a privacy product claiming Bitcoin is anonymous is the exact "
          "overstatement this page exists to avoid")
    check("and says the chain is public and permanent",
          "public chain" in priv, priv[:200])
    print("\n[error pages] nginx points at pages that exist")
    # Both configs carried `error_page 404 /404.html` and
    # `error_page 500 502 503 504 /50x.html` while neither file existed, so a
    # mistyped URL got a bare nginx page — and so did a 502, which is exactly
    # what a visitor sees when the control plane is down and the moment a
    # branded, useful message matters most.
    import re as _re
    for conf, label in ((os.path.join(H.REPO, "nginx", "0trustvpn.com.conf"), "production"),
                        (os.path.join(H.REPO, "scripts", "install.sh"), "test mode")):
        text = open(conf, encoding="utf-8").read()
        targets = set(_re.findall(r'error_page\s+[\d\s]+\s+(/\S+?);', text))
        check(f"{label} declares error pages", bool(targets), conf)
        for t in sorted(targets):
            f = os.path.join(H.REPO, "web", t.lstrip("/"))
            check(f"{label}: {t} exists", os.path.exists(f),
                  f"nginx would serve its own default instead of {t}")

    # A 502 page that says "your VPN is down" would be wrong: tunnels are
    # carried by the mesh nodes and do not depend on this box.
    fivex = open(os.path.join(H.REPO, "web", "50x.html"), encoding="utf-8").read()
    check("the 5xx page says the tunnel is unaffected",
          "not affected" in fivex or "unaffected" in fivex,
          "a visitor whose tunnel is fine must not be told the VPN is down")

    print("\n[favicon] the site has one, and every page asks for it")
    # Without it every visit logs a 404 and the tab shows a blank icon.
    for name in ("favicon.svg", "favicon.ico"):
        check(f"web/{name} is committed",
              os.path.exists(os.path.join(H.REPO, "web", name)))
    for f in glob.glob(os.path.join(H.REPO, "web", "*.html")):
        body = open(f, encoding="utf-8").read()
        if os.path.basename(f) == "admin.html":
            continue  # not a public page
        check(f"{os.path.basename(f)} links a favicon",
              'rel="icon"' in body, "browsers request /favicon.ico regardless")

    print("\n[no third parties] every page is served from our own origin")
    # The site linked fonts.googleapis.com and fonts.gstatic.com. privacy.html
    # §5 now says our pages contact no external origin, docs/AUDIT.md §9 says
    # the same, and the nginx CSP no longer whitelists either — so one
    # reintroduced webfont link makes three documents untrue at once. On /surf
    # especially: a page whose pitch is that your visit is not handed to
    # anybody must not hand it to anybody.
    pages = glob.glob(os.path.join(H.REPO, "web", "*.html"))
    check("some pages were found", bool(pages))
    for f in pages:
        body = open(f, encoding="utf-8").read()
        # Only FETCHED subresources matter. A link a human clicks is fine, and
        # so is metadata that is required to be absolute: rel="canonical" and
        # og:url name this page's own URL for a search engine and are never
        # requested by the browser. The first version of this check matched
        # any <link href="https://...">, which made adding a canonical — the
        # single most basic piece of technical SEO — look like reintroducing
        # the Google Fonts leak. Narrowed to the rel values that actually
        # cause a fetch, so it still fails on a stylesheet, an icon, a
        # preconnect or a manifest from somebody else's origin.
        FETCHING = ("stylesheet", "icon", "apple-touch-icon", "manifest",
                    "preload", "prefetch", "preconnect", "dns-prefetch",
                    "modulepreload")
        sub = re.findall(r'<(?:script|img)\b[^>]*\bsrc="(https?://[^"]+)"', body)
        for tag in re.findall(r"<link\b[^>]*>", body):
            href = re.search(r'href="(https?://[^"]+)"', tag)
            rel = re.search(r'rel="([^"]+)"', tag)
            if href and rel and any(r in FETCHING for r in rel.group(1).split()):
                sub.append(href.group(1))
        check(f"{os.path.basename(f)} fetches nothing off-origin", not sub, sub)

    faces = os.path.join(H.REPO, "web", "fonts", "faces.css")
    check("the brand faces are vendored", os.path.exists(faces))
    if os.path.exists(faces):
        css = open(faces, encoding="utf-8").read()
        check("faces.css points only at local files", "https://" not in css,
              [l for l in css.splitlines() if "https://" in l][:3])
        missing = [u for u in re.findall(r'url\(/fonts/([^)]+)\)', css)
                   if not os.path.exists(os.path.join(H.REPO, "web", "fonts", u))]
        check("every face it names is committed", not missing, missing[:5])

    # The DIRECTIVE, not the file: both of these carry comments explaining that
    # the CDNs were removed, and a whole-file grep flags its own explanation.
    ngx = open(os.path.join(H.REPO, "nginx", "0trustvpn.com.conf"),
               encoding="utf-8").read()
    csp = [l for l in ngx.splitlines()
           if "Content-Security-Policy" in l and not l.strip().startswith("#")]
    check("a CSP header is set", bool(csp))
    check("the CSP no longer whitelists the font CDNs",
          not any("fonts.googleapis.com" in l or "fonts.gstatic.com" in l
                  for l in csp),
          "a permission kept after nothing uses it is attack surface for free")

    # The ONION mirror serves the same pages from a config generated by a bash
    # script, which no test read — so it kept whitelisting the font CDNs long
    # after the clearnet config stopped. Same class as install.sh generating
    # its own nginx: a second copy nothing checks. On an onion, whose whole
    # point is that the visit is not handed to anybody, permitting a request
    # to Google is the contradiction at its sharpest.
    onion = open(os.path.join(H.REPO, "tor", "scripts", "bootstrap.sh"),
                 encoding="utf-8").read()
    onion_csp = [l for l in onion.splitlines()
                 if "Content-Security-Policy" in l and not l.strip().startswith("#")]
    check("the onion mirror sets a CSP too", bool(onion_csp), onion)
    check("and it whitelists no third-party origin either",
          not any("fonts.googleapis.com" in l or "fonts.gstatic.com" in l
                  or "http://" in l or "https://" in l for l in onion_csp),
          onion_csp)

    proxy_src = open(os.path.join(H.REPO, "proxy", "server.py"),
                     encoding="utf-8").read()
    fonts_decl = [l for l in proxy_src.splitlines()
                  if l.startswith("FONTS =")]
    check("/surf declares where its fonts come from", bool(fonts_decl))
    check("/surf loads them from our own origin too",
          fonts_decl and "/fonts/faces.css" in fonts_decl[0]
          and "googleapis" not in fonts_decl[0],
          f"the funnel's front door is the page this matters most on: {fonts_decl}")

    print("\n[hero] the first paragraph anyone reads is accurate")
    # The hero is the most-read copy in the product and it carried three
    # things that were not true. Each is the same failure the rest of this
    # file guards against, just on the one page nobody re-reads.
    idx_body = open(os.path.join(H.REPO, "web", "index.html"),
                    encoding="utf-8").read()
    hero = idx_body[idx_body.index('class="hero"'):
                    idx_body.index('class="hero"') + 3000]

    # "A peer-to-peer VPN" — customers connect to nodes the operator runs and
    # never to each other. The word comes from WireGuard calling its
    # endpoints peers, and to a reader it describes a different product.
    check("the hero does not call this peer-to-peer",
          "peer-to-peer" not in idx_body.lower(),
          "customers do not route through each other; nothing here is P2P")

    # "a global mesh" contradicted the jurisdictions section on the same
    # page, which lists fourteen countries there are deliberately no servers
    # in. Three nodes, all in Europe.
    check("and does not call three European nodes global",
          not re.search(r"global(ly)?\s+(mesh|network)", idx_body, re.I),
          [l.strip() for l in idx_body.splitlines()
           if re.search(r"global", l, re.I)][:3])

    # A hardcoded month ages by itself and nothing goes red. It read "May
    # 2026" in September, which on a security product's front page reads as
    # abandoned.
    stale = re.findall(r"(?:January|February|March|April|May|June|July|"
                       r"August|September|October|November|December)\s+20\d\d",
                       hero)
    check("the hero states no date that will go stale on its own", not stale,
          f"{stale} — nothing updates this and nothing notices")

    # The version it does show has to be the version people can download.
    hv = re.search(r'id="hero-version"[^>]*>v?([0-9]+\.[0-9]+)', hero)
    check("the hero names a version", hv is not None, hero[:300])
    dl_ver = re.search(r"/releases/([0-9]+\.[0-9]+)", 
                       open(os.path.join(H.REPO, "web", "download.html"),
                            encoding="utf-8").read())
    if hv and dl_ver:
        check("and it is the one the download page offers",
              hv.group(1) == dl_ver.group(1),
              f"hero v{hv.group(1)} vs downloads {dl_ver.group(1)}")

    # The regions named in the hero must be the regions that exist.
    live_regions = {r["code"] for r in H.call("GET", "/api/v1/regions")[1]["regions"]}
    check("the mesh really is three regions", len(live_regions) == 3, live_regions)
    check("and the hero says three, not some other number",
          "three-country" in idx_body or "3 jurisdictions" in idx_body,
          "the count is stated twice on this page and has to match the API")

    print("\n[links] every internal link and CTA goes somewhere")
    # Found by walking them: index.html's "What that means" link under the
    # payment-privacy panel pointed at /privacy#cards, and privacy.html had
    # no id on any heading at all — one id="content" for the skip link and
    # nothing else. So the CTA landed readers at the top of a 5,000-word
    # policy instead of the paragraph about what a card payment reveals, and
    # nothing on the site could deep-link into any of the long documents.
    WEBD = os.path.join(H.REPO, "web")
    inst_src = open(os.path.join(H.REPO, "scripts", "install.sh")).read()
    exact = set(re.findall(r"location = (/[A-Za-z0-9._/-]*)", inst_src))
    prefixes = set(re.findall(r"location (?:\^~ )?(/[A-Za-z0-9._/-]+)/? \{", inst_src))
    on_disk = {os.path.basename(f) for f in glob.glob(os.path.join(WEBD, "*"))}

    def resolves(path):
        if path in exact or path == "/":
            return True
        if any(path == p_ or path.startswith(p_.rstrip("/") + "/")
               for p_ in prefixes):
            return True
        local = path.lstrip("/")
        return local in on_disk or (local + ".html") in on_disk

    ids_of = {}
    for f in glob.glob(os.path.join(WEBD, "*.html")):
        ids_of[os.path.basename(f)] = set(
            re.findall(r'\bid="([^"]+)"', open(f, encoding="utf-8").read()))

    broken = []
    for f in sorted(glob.glob(os.path.join(WEBD, "*.html"))):
        name = os.path.basename(f)
        body = open(f, encoding="utf-8").read()
        for href in re.findall(r'<a\b[^>]*href="([^"]+)"', body):
            if href.startswith(("mailto:", "http://", "https://", "tel:",
                                "javascript:")):
                continue
            path, _, frag = href.partition("#")
            path = path.split("?")[0]
            if not path:                      # same-page anchor
                if frag and frag not in ids_of[name]:
                    broken.append((name, href, "no such anchor on this page"))
                continue
            if not resolves(path):
                broken.append((name, href, "nothing routes or serves this"))
                continue
            if frag:
                local = path.lstrip("/")
                tgt = local if local in ids_of else local + ".html"
                if tgt in ids_of and frag not in ids_of[tgt]:
                    broken.append((name, href, f"#{frag} is not on {tgt}"))
    check("no internal link is broken", not broken, broken[:6])

    # And the long documents stay linkable. An unanchored policy cannot be
    # cited by a support reply, a search result's jump-to link, or an answer
    # engine quoting one clause.
    for doc, least in (("privacy.html", 10), ("terms.html", 6),
                       ("help.html", 20), ("audit.html", 5)):
        anchored = len(re.findall(r"<h[23][^>]*\bid=", 
                                  open(os.path.join(WEBD, doc), encoding="utf-8").read()))
        check(f"{doc} has section anchors ({anchored})", anchored >= least,
              f"only {anchored}; deep links into it cannot work")

    print("\n[seo] the site is findable, and says the same thing twice")
    # Before this existed the entire public site had no meta description, no
    # canonical, no Open Graph, no structured data, no robots.txt and no
    # sitemap — twelve pages of it. A search result was a bare title and
    # whatever Google chose to quote, a shared link was a naked URL, and an
    # answer engine had nothing machine-readable to work from at all.
    import json as _json, struct as _struct, subprocess as _sub
    WEB = os.path.join(H.REPO, "web")

    sitemap = open(os.path.join(WEB, "sitemap.xml"), encoding="utf-8").read()
    sm_urls = re.findall(r"<loc>([^<]+)</loc>", sitemap)
    check("a sitemap exists and lists pages", len(sm_urls) >= 8, sm_urls)
    check("every sitemap URL is absolute and on the canonical host",
          all(u.startswith("https://0trustvpn.com/") for u in sm_urls), sm_urls)

    # A sitemap entry for a URL nginx does not route sends crawlers to a 404
    # from the file whose whole job is to be the map.
    inst = open(os.path.join(H.REPO, "scripts", "install.sh")).read()
    routed = set(re.findall(r"location = (/[a-z0-9.-]*)", inst)) | {"/"}
    unrouted = [u for u in sm_urls
                if u.replace("https://0trustvpn.com", "") not in routed]
    check("every sitemap URL is a route the installer serves",
          not unrouted, f"{unrouted} not in {sorted(routed)}")

    pages, noindex = {}, set()
    for f in sorted(glob.glob(os.path.join(WEB, "*.html"))):
        name = os.path.basename(f)
        body = open(f, encoding="utf-8").read()
        pages[name] = body
        if re.search(r'name="robots" content="[^"]*noindex', body):
            noindex.add(name)
    check("the error pages and the dashboard are noindex",
          {"404.html", "50x.html", "admin.html"} <= noindex, sorted(noindex))

    # The trial page carried noindex — the single highest-intent page on the
    # site, the one someone searching for a VPN trial without a card would
    # land on, excluded from search entirely.
    check("the trial page is NOT noindex", "trial.html" not in noindex,
          "it is the page whose entire job is a conversion")

    for name, body in pages.items():
        if name in noindex or name == "admin.html":
            continue
        canon = re.search(r'<link rel="canonical" href="([^"]+)"', body)
        desc = re.search(r'<meta name="description" content="([^"]*)"', body)
        check(f"{name} has a canonical", bool(canon), body[:200])
        check(f"{name} has a description", bool(desc))
        if desc:
            n = len(desc.group(1))
            # Google truncates the snippet around 160; longer and the clause
            # carrying the differentiator is the part that gets cut.
            check(f"{name} description fits a snippet ({n} chars)",
                  40 <= n <= 160, desc.group(1))
        if canon:
            check(f"{name} is in the sitemap under its canonical URL",
                  canon.group(1) in sm_urls,
                  f"{canon.group(1)} not among {sm_urls}")
        for tag in ('property="og:title"', 'property="og:description"',
                    'property="og:image"', 'property="og:url"',
                    'name="twitter:card"'):
            check(f"{name} has {tag}", tag in body)
        og_url = re.search(r'property="og:url" content="([^"]+)"', body)
        check(f"{name} og:url agrees with its canonical",
              canon and og_url and og_url.group(1) == canon.group(1),
              f"{og_url.group(1) if og_url else None} vs "
              f"{canon.group(1) if canon else None}")

    # og:image is the difference between a shared link that looks like a
    # product and one that looks like a pasted URL.
    og = os.path.join(WEB, "og.png")
    check("the social card exists", os.path.exists(og))
    if os.path.exists(og):
        d = open(og, "rb").read(33)
        w, h = _struct.unpack(">II", d[16:24])
        check(f"and is the size every platform crops to ({w}x{h})",
              (w, h) == (1200, 630), f"{w}x{h}")
        refs = {re.search(r'property="og:image" content="([^"]+)"', b).group(1)
                for n, b in pages.items() if 'property="og:image"' in b}
        check("every page points at that one file", refs == {"https://0trustvpn.com/og.png"}, refs)

    robots = open(os.path.join(WEB, "robots.txt"), encoding="utf-8").read()
    check("robots.txt advertises the sitemap",
          "Sitemap: https://0trustvpn.com/sitemap.xml" in robots)
    # /surf renders other people's pages under our origin. Indexed, that is
    # third-party duplicate content on our domain.
    check("robots.txt keeps crawlers out of the visitor proxy",
          "Disallow: /surf" in robots, robots[:200])
    check("and out of the operations dashboard", "Disallow: /admin" in robots)
    # Deliberately allowed, and worth asserting so a future "block the AI
    # crawlers" edit is a decision somebody makes rather than one that
    # happens: the questions people ask an assistant about a VPN are the
    # questions this site answers in checkable terms.
    for bot in ("GPTBot", "ClaudeBot", "PerplexityBot", "Google-Extended"):
        check(f"robots.txt lets {bot} read the public pages",
              re.search(rf"User-agent: {bot}\nAllow: /", robots) is not None,
              robots)

    print("\n[seo-schema] structured data says what the pages and the API say")
    graphs = {}
    for name, body in pages.items():
        for blob in re.findall(
                r'(?s)<script type="application/ld\+json">(.*?)</script>', body):
            graphs.setdefault(name, []).extend(_json.loads(blob)["@graph"])
    check("the landing page carries structured data", "index.html" in graphs)
    nodes = graphs.get("index.html", [])
    types = {t for n in nodes
             for t in (n["@type"] if isinstance(n["@type"], list) else [n["@type"]])}
    for want in ("Organization", "WebSite", "Product", "SoftwareApplication"):
        check(f"the landing page declares a {want}", want in types, sorted(types))

    org = next((n for n in nodes if n["@type"] == "Organization"), {})
    # Entity clarity: an answer engine that cannot tell who operates a VPN
    # cannot answer the first question anyone asks about one.
    check("the operating entity is named in the schema",
          org.get("legalName") == "0trust GmbH", org.get("legalName"))
    check("and matches security.txt's entity",
          "0trust GmbH" in open(os.path.join(WEB, ".well-known",
                                             "security.txt")).read())

    prod = next((n for n in nodes if isinstance(n["@type"], list)
                 and "Product" in n["@type"]), {})
    offers = {int(o["name"].split()[0]): float(o["price"])
              for o in prod.get("offers", {}).get("offers", [])}
    check("the schema prices exactly the terms the API sells",
          offers == {int(k): float(v) for k, v in api_main.PRICING.items()},
          f"schema {offers} vs API {api_main.PRICING}")

    faq = next((n for g in graphs.values() for n in g
                if n["@type"] == "FAQPage"), None)
    check("the help page publishes a FAQPage", faq is not None)
    if faq:
        on_page = len(re.findall(r'<div class="q">',
                                 pages["help.html"]))
        check(f"and it carries every question on the page ({on_page})",
              len(faq["mainEntity"]) == on_page,
              f"schema {len(faq['mainEntity'])} vs page {on_page}")
        empty = [q["name"] for q in faq["mainEntity"]
                 if len(q["acceptedAnswer"]["text"]) < 40]
        check("with a real answer on each", not empty, empty)

    # The generators are the only thing keeping all of the above in step, so
    # assert they are still able to say "out of date".
    for script in ("gen-sitemap.py", "gen-seo.py"):
        r = _sub.run([os.path.join(H.REPO, "scripts", script), "--check"],
                     capture_output=True, text=True, cwd=H.REPO)
        check(f"{script} --check passes on this checkout", r.returncode == 0,
              r.stderr[-300:])

    # ---------------------------------------------------------------------------
    # The refund clause is a promise with an operation behind it.
    #
    # terms.html §4 offers a 30-day refund window. Nothing implemented one: the
    # operator sent the coins back by hand — correctly, the control plane holds no
    # keys — and the system knew nothing about it, so the account kept every day
    # the payment had bought. Pay, use it twenty-nine days, ask for the money
    # back, keep the service. Nobody chose that; it is what a contract clause with
    # no code behind it does.
    #
    # The clause also described "our payment processor's dispute flow". The
    # default provider is `watch`: it derives an address from the operator's own
    # extended public key and watches an explorer. There is no processor and no
    # dispute flow — the clause described a mechanism that does not exist, in a
    # binding document.
    # ---------------------------------------------------------------------------
    print("\n[refunds] the clause and the mechanism agree")
    terms_raw = open(os.path.join(H.REPO, "web", "terms.html")).read()
    # Whitespace collapsed before matching. Prose in these pages is hard
    # wrapped, so "no dispute flow to go through" spans a line break and a
    # plain substring check misses it — the same trap that made an iOS check
    # read the wrong answer earlier in this suite.
    terms = " ".join(terms_raw.split())
    admin_src = open(os.path.join(H.REPO, "api", "admin.py")).read()
    pay_src = open(os.path.join(H.REPO, "api", "payments.py")).read()
    adminjs = open(os.path.join(H.REPO, "web", "admin.js")).read()
    adminhtml = open(os.path.join(H.REPO, "web", "admin.html")).read()

    check("terms still offers a refund window", "refund" in terms.lower())
    check("it no longer routes refunds through a processor that does not exist",
          "dispute flow to go through" in terms
          and "through our payment processor's dispute flow" not in terms,
          "the default provider is `watch` — no processor, no dispute flow")
    check("and it says a refund ends the time it paid for",
          "refund ends the time it paid for" in terms,
          "without this the customer keeps the service and the money")

    check("payments defines a refunded invoice state",
          'REFUNDED = "refunded"' in pay_src)
    check("the admin API can record one",
          '@router.post("/invoices/{invoice_id}/refund")' in admin_src,
          "terms promises a refund; an operator needs somewhere to record it")
    check("recording it revokes the days that invoice bought",
          'acct["expires_at"] - bought' in admin_src,
          "marking an invoice refunded without taking the time back leaves the "
          "customer paid up on money they got returned")
    check("and the dashboard exposes it", "Record refund" in adminjs,
          "an endpoint with no control is not a mechanism an operator has")
    check("the dashboard can also list refunded invoices",
          'value="refunded"' in adminhtml,
          "no filter means the operator cannot find what they refunded")

    index_raw = open(os.path.join(H.REPO, "web", "index.html")).read()
    index = " ".join(index_raw.split())
    check("the landing page names what a refund actually requires",
          "invoice ID" in index and "no reason needed" in index,
          "'30-day money-back, no questions' promised less friction than "
          "terms §4 has: the customer must ask, with the invoice id, "
          "because we cannot reach them first")

    # -----------------------------------------------------------------------
    # The checkout says what closing the tab does, and it has to be true.
    #
    # Settlement is 0trust-poll.timer asking an explorer once a minute, server
    # side. The page told the customer "DO NOT CLOSE UNTIL YOU SEE
    # CONFIRMATION", which is false in the direction that costs money: a
    # Monero invoice is ten confirmations away, and someone who closed the tab
    # had every reason to think their payment was lost. The desktop GUI's
    # top-up panel already says the true thing.
    # -----------------------------------------------------------------------
    print("\n[checkout] closing the tab does not cancel the invoice")
    guijs = " ".join(open(os.path.join(
        H.REPO, "client", "internal", "gui", "assets", "index.html")).read().split())
    check("the signup checkout does not tell the customer to keep the tab open",
          "DO NOT CLOSE" not in index.upper(),
          "the invoice is watched server side; the tab does nothing")
    check("it says so explicitly",
          "CLOSING IT DOES NOT CANCEL THE INVOICE" in index.upper(),
          "silence leaves the customer guessing, which is where they pay twice")
    check("and the desktop top-up panel says the same thing",
          "closing this window does not cancel it" in guijs,
          "two surfaces describing one mechanism must not disagree")

    # -----------------------------------------------------------------------
    # Every route the sweeper's renewal notice names has to exist.
    #
    # This is the third time this exact shape has bitten. sweep.py told
    # customers to run `0trust topup` before that command existed; a test
    # asserted the notice CONTAINED the string, so it watched the words and
    # not whether they meant anything. Then it said "or at 0trustvpn.com" —
    # true of the domain, false of any page there: the site's Begin flow opens
    # a NEW account, so a phone-only customer, who has no command line, was
    # told to pay and given nowhere to do it.
    #
    # So this reads the URLs and commands out of the notice text and requires
    # each one to resolve: a page in web/, a route the installer's nginx
    # config serves, and a subcommand the CLI's dispatcher actually has.
    # -----------------------------------------------------------------------
    print("\n[renewal] the expiry notice points at things that exist")
    sweep_src = open(os.path.join(H.REPO, "api", "sweep.py")).read()
    body_m = re.search(r'\("Renew at (.*?)\),\n', sweep_src, re.S)
    notice = " ".join(re.findall(r'"([^"]*)"', body_m.group(0))) if body_m else ""
    notice = " ".join(notice.split())
    check("the renewal notice was found in sweep.py", bool(notice), sweep_src[:200])

    routes = re.findall(r"0trustvpn\.com(/[a-z0-9-]+)", notice)
    check("it names at least one page to renew on", bool(routes), notice)
    installer = open(os.path.join(H.REPO, "scripts", "install.sh")).read()
    for r in set(routes):
        page = os.path.join(H.REPO, "web", r.lstrip("/") + ".html")
        check(f"{r} is a page that exists", os.path.exists(page), page)
        check(f"and nginx serves {r}", f"location = {r} " in installer
              or f"location = {r}\n" in installer or f"location = {r} {{" in installer,
              "the installer GENERATES the nginx config; a page it does not "
              "route is a 404 on a real deployment")

    cmds = set(re.findall(r"`0trust ([a-z]+)`", notice))
    cli_src = open(os.path.join(H.REPO, "client", "cmd", "0trust", "main.go")).read()
    for c in cmds:
        check(f"`0trust {c}` is a command the CLI has",
              f'case "{c}"' in cli_src, "sweep.py told every expiring customer "
              "to run a command that did not exist once already")

    renew_html = open(os.path.join(H.REPO, "web", "renew.html")).read()
    check("the renewal page tops up rather than opening a new account",
          "/api/v1/account/topup" in renew_html
          and "/api/v1/account'" not in renew_html,
          "POST /api/v1/account mints a NEW token; the customer wants theirs "
          "extended")
    check("and it authenticates with the token in a header, never a URL",
          "'X-Account-Token'" in renew_html
          and "account/status?" not in renew_html,
          "the request path is logged; the token is the whole credential")

    # ---------------------------------------------------------------------------
    # The rights section names commands. They have to exist and do what it says.
    #
    # privacy.html had no data-subject-rights section at all, which for a Swiss
    # GmbH selling into the EU is a gap in the one document customers read to
    # decide whether to trust us. Writing it surfaced a contradiction: §8 said
    # flatly that we "cannot perform a per-user data export or deletion on
    # request", and that was wrong. The token IS the identifier — presented with
    # one the operator finds exactly one account and the dashboard deletes it.
    # The true statement is conditional, and a policy that understates what the
    # system can do is how a lawful erasure request gets wrongly refused.
    # ---------------------------------------------------------------------------
    print("\n[rights] the privacy policy's rights section matches the product")
    priv = " ".join(open(os.path.join(H.REPO, "web", "privacy.html")).read().split())
    cli = open(os.path.join(H.REPO, "client", "cmd", "0trust", "main.go")).read()

    check("privacy.html has a data-subject-rights section",
          'id="your-rights"' in priv,
          "FADP art. 25 and GDPR art. 15 give customers rights; a privacy policy "
          "for a privacy product should say what they are")
    check("and a breach section", 'id="if-we-are-breached"' in priv,
          "GDPR art. 33 and FADP art. 24 both require notification")

    # Every command the section tells a customer to run.
    for cmd in ("0trust status", "0trust devices", "0trust notices"):
        check(f"the section tells them to run {cmd!r}, and it exists",
              cmd in priv and f'case "{cmd.split()[1]}":' in cli,
              "copy naming a command the binary does not have is the same defect "
              "as sweep.py telling people to run `0trust topup` before it existed")
    check("`0trust remove` is real too, since deletion is offered through it",
          "0trust remove" in priv and 'case "remove":' in cli)

    check("§8 no longer says deletion on request is impossible",
          "cannot perform a per-user data export or deletion on request" not in priv,
          "with a token it is entirely possible, and the dashboard does it")
    check("§8 says instead that the token is what makes it possible",
          "we can act on a request; if you do not, we cannot" in priv,
          "the honest statement is conditional, not flat")
    check("and it is still honest about the customer who lost their token",
          "lost their token" in priv or "lost your token" in priv,
          "no recovery flow is a deliberate decision and has to be said")

    check("the operator runbook exists",
          os.path.exists(os.path.join(H.REPO, "docs", "REQUESTS.md")),
          "a deadline with no written procedure is improvised under time pressure")
    reqs = open(os.path.join(H.REPO, "docs", "REQUESTS.md")).read()
    for topic in ("Right of access", "Right to erasure", "Record refund",
                  "72 hours", "VAT"):
        check(f"the runbook covers: {topic}", topic in reqs)

finally:
    srv.shutdown(); H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
