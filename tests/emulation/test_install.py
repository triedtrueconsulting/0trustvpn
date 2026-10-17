#!/usr/bin/env python3
"""
The installer, validated by nginx itself.

A bad directive here means a fresh VPS finishes the install with nginx
refusing to start — the worst possible moment to find out. So this asks the
installer for the exact bytes it would write (ZTV_RENDER_TO) and runs
`nginx -t` over them. Reconstructing the config test-side would let the two
drift, which is precisely how the `http2 on;` incompatibility with the
nginx 1.24 that Ubuntu 24.04 ships got through the first time.

Skips (77) if nginx is not installed.
"""
import os, re, shutil, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

if not shutil.which("nginx"):
    print("  SKIP  nginx not installed")
    sys.exit(77)

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

INSTALL = os.path.join(H.REPO, "scripts", "install.sh")
TMP = H.tempdir("0trust-install-")
os.makedirs(f"{TMP}/www", exist_ok=True)
os.makedirs(f"{TMP}/snippets", exist_ok=True)
for snip in ("0trust-proxy.conf", "0trust-surf.conf"):
    shutil.copy(os.path.join(H.REPO, "nginx", snip), f"{TMP}/snippets/{snip}")
subprocess.run(
    ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout",
     f"{TMP}/privkey.pem", "-out", f"{TMP}/fullchain.pem", "-days", "1",
     "-subj", "/CN=example.com"], check=True, capture_output=True)


def run_installer(*args, render_to=None):
    env = {**os.environ, "TERM": "dumb"}
    if render_to:
        env["ZTV_RENDER_TO"] = render_to
    r = subprocess.run(["bash", INSTALL, "--dry-run", *args],
                       capture_output=True, text=True, timeout=180, env=env)
    return r.returncode, r.stdout + r.stderr


def staged_api_files():
    """
    The api/*.py basenames install.sh places in $PREFIX/api/.

    Derived from the script rather than restated, so this cannot drift from
    it — and so a regression from enumerating the directory back to a
    hand-kept list is caught by the import probe instead of by a grep for a
    filename that happens still to be mentioned somewhere.
    """
    import glob as _g
    installer = open(INSTALL).read()
    on_disk = {os.path.basename(f)
               for f in _g.glob(os.path.join(H.REPO, "api", "*.py"))}
    if '"$REPO_DIR"/api/*.py' in installer:
        excluded = set(re.findall(r'basename "\$f"\) == "([^"]+)"', installer))
        return on_disk - excluded
    return set(re.findall(r'\$REPO_DIR/api/([A-Za-z0-9_.-]+\.py)', installer))


def nginx_check(site_path, zones_path, label, port_map):
    """Wrap a rendered site config in a minimal nginx.conf and run nginx -t."""
    site = open(site_path).read()
    for a, b in port_map:
        site = site.replace(a, b)
    # nginx -t actually binds, and CI sandboxes frequently have no IPv6, so a
    # valid `listen [::]:...` fails with EAFNOSUPPORT. Strip those lines: the
    # parser still checks their syntax before the bind is attempted, and the
    # v4 equivalents keep the rest of the config under test.
    site = "\n".join(l for l in site.splitlines() if "listen [::]" not in l)
    # /var/log/nginx is root-owned. `nginx -t` opens the log files for real,
    # so on any unprivileged runner the committed config fails the check with
    # a permission error that says nothing about the config being wrong.
    site = (site.replace("/etc/nginx/snippets/", f"{TMP}/snippets/")
                .replace("/etc/letsencrypt/live/example.com", TMP)
                .replace("/var/log/nginx/", f"{TMP}/")
                .replace("/var/www/0trust", f"{TMP}/www")
                .replace("/var/www/acme", f"{TMP}/www"))
    sp = os.path.join(TMP, f"site-{label}.conf")
    open(sp, "w").write(site)
    conf = os.path.join(TMP, f"nginx-{label}.conf")
    open(conf, "w").write(f"""
events {{ worker_connections 64; }}
error_log {TMP}/error-{label}.log;
pid {TMP}/nginx-{label}.pid;
http {{
  access_log off;
  client_body_temp_path {TMP}/cbt-{label};
  proxy_temp_path {TMP}/pt-{label};
  fastcgi_temp_path {TMP}/ft-{label};
  uwsgi_temp_path {TMP}/ut-{label};
  scgi_temp_path {TMP}/st-{label};
  include {zones_path};
  include {sp};
}}
""")
    r = subprocess.run(["nginx", "-t", "-c", conf], capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout)[-800:], site


try:
    print("[1] flag handling")
    rc, out = run_installer("--mode", "bogus")
    check("unknown mode rejected",
          rc != 0 and "must be test, production or node" in out, out[-200:])
    rc, out = run_installer("--mode", "production")
    check("production without --domain rejected", rc != 0 and "--domain" in out, out[-200:])
    rc, out = run_installer("--mode", "production", "--domain", "x.com")
    check("production without --email rejected", rc != 0 and "--email" in out, out[-200:])
    for bad in ("http://x.com", "x.com/path", "nodot", "has space.com"):
        rc, out = run_installer("--mode", "production", "--domain", bad, "--email", "a@b.c")
        check(f"malformed domain rejected: {bad!r}", rc != 0, out[-160:])

    print("\n[2] dry runs are clean and change nothing")

    def system_state():
        """
        Fingerprint the system paths --dry-run must not touch.

        This asserted `not os.path.exists("/etc/0trust/api.env")`, which is a
        different claim: it says the product was never installed here, not
        that the dry run left it alone. It fails on any box that HAS 0trust —
        including the machine an operator would actually re-run the installer
        on, and including a test box where the suite had just installed it for
        real. Comparing before and after tests the property that matters and
        works anywhere.
        """
        import hashlib
        watched = ["/etc/0trust", "/etc/nginx/sites-enabled",
                   "/etc/systemd/system", "/etc/sysctl.d", "/var/lib/0trust"]
        state = {}
        for root in watched:
            for dirpath, _, names in os.walk(root):
                for n in names:
                    f = os.path.join(dirpath, n)
                    try:
                        st = os.stat(f)
                        with open(f, "rb") as fh:
                            digest = hashlib.sha256(fh.read()).hexdigest()[:16]
                        state[f] = (st.st_mtime_ns, st.st_size, digest)
                    except OSError:
                        state[f] = "unreadable"
        return state

    before = system_state()
    rc, out = run_installer("--mode", "test")
    check("test dry run exits 0", rc == 0, out[-400:])
    check("test mode warns about the missing TLS", "No TLS" in out, out[-500:])
    rc, out = run_installer("--mode", "production", "--domain", "example.com",
                            "--email", "a@b.c")
    check("production dry run exits 0", rc == 0, out[-400:])
    after = system_state()
    changed = sorted(set(before) ^ set(after)) + \
              sorted(f for f in set(before) & set(after) if before[f] != after[f])
    check("dry runs changed nothing under /etc or /var/lib", not changed,
          f"--dry-run touched: {changed[:10]}")

    print("\n[2b] swap: offered on the control plane, refused on a node")
    # A 2GB control-plane VPS runs nginx, uvicorn, the proxy and SQLite, and
    # wants swap. A mesh node must never have it: swap is a persistent file
    # the kernel can page the WireGuard private key into, and privacy.html,
    # audit.html and AUDIT.md 5.3 all tell customers the key never touches
    # persistent storage. The installer has to know the difference.
    rc, out = run_installer("--mode", "production", "--domain", "example.com",
                            "--email", "a@b.c", "--swap", "4G")
    check("production accepts --swap", rc == 0 and "swapfile" in out, out[-300:])
    check("and says it would go in fstab", "fstab" in out, out[-300:])

    rc, out = run_installer("--mode", "node", "--control-url", "https://c.example",
                            "--region", "zur", "--provision-token", "t",
                            "--swap", "4G")
    check("a node refuses --swap", rc != 0, out[-200:])
    check("and explains that swap can page the private key to disk",
          "page the WireGuard" in out or "private key to disk" in out,
          out[-300:])

    for bad in ("4gigs", "4", "big", "-1G"):
        rc, out = run_installer("--mode", "test", "--swap", bad)
        check(f"rejects a bad size: {bad!r}", rc != 0, out[-160:])

    print("\n[3] nginx validates what the installer would actually write")
    for mode, extra, label, ports in (
        ("test", [], "test", [("listen 80 default_server;", "listen 8080 default_server;"),
                              ("listen [::]:80 default_server;", "listen [::]:8080 default_server;")]),
        ("production", ["--domain", "example.com", "--email", "a@b.c"], "prod",
         [("listen 443 ssl http2;", "listen 8443 ssl http2;"),
          ("listen [::]:443 ssl http2;", "listen [::]:8443 ssl http2;"),
          ("listen 80;", "listen 8080;"), ("listen [::]:80;", "listen [::]:8080;")]),
    ):
        d = os.path.join(TMP, f"render-{label}")
        rc, out = run_installer("--mode", mode, *extra, render_to=d)
        check(f"{mode} render succeeded", rc == 0 and os.path.exists(f"{d}/site.conf"),
              out[-300:])
        if os.path.exists(f"{d}/site.conf"):
            good, err, body = nginx_check(f"{d}/site.conf", f"{d}/zones.conf", label, ports)
            check(f"nginx {subprocess.run(['nginx','-v'],capture_output=True,text=True).stderr.strip().split('/')[-1]} accepts the {mode} config",
                  good, err)
            globals()[f"body_{label}"] = body

    # -------------------------------------------------------------------
    # [3b] The privacy claims, checked against the bytes the installer writes.
    #
    # This is the section that should have existed first. The installer
    # generates its own nginx config and has never installed
    # nginx/0trustvpn.com.conf — which is where the anonymizing map, the anon
    # log format and the access_log directive all lived. So a real deployment
    # fell through to nginx's stock `combined` and wrote the full client IP,
    # the User-Agent, the Referer and the complete request line (device
    # pubkey included) to /var/log/nginx/access.log, for the fourteen
    # rotations Ubuntu's logrotate keeps. privacy.html says the IP is
    # truncated to a /24 "before they are written". AUDIT.md §4.1 lists
    # User-Agent and Referer under "what's NOT in the access log".
    #
    # audit-verify.sh could not see it either: its nginx checks looked for
    # /etc/nginx/sites-enabled/0trustvpn.com.conf, a filename the installer
    # never creates, and a missing file exits 77 — which prints SKIP, not
    # FAIL. Section [4] below validated the reference file, which is exactly
    # the file that does not deploy. Everything here reads the rendered
    # output instead.
    # -------------------------------------------------------------------
    print("\n[3b] the deployed config keeps the promises the site makes")
    for label, d in (("test", os.path.join(TMP, "render-test")),
                     ("prod", os.path.join(TMP, "render-prod"))):
        zones = open(f"{d}/zones.conf").read()
        site = open(f"{d}/site.conf").read()

        check(f"{label}: an IP-anonymizing map is defined",
              "map $remote_addr $remote_addr_anon" in zones, zones[:200])
        check(f"{label}: the secret-path map is defined",
              "map $uri $uri_anon" in zones, zones[:200])
        check(f"{label}: a log format that uses both is defined",
              "log_format anon" in zones and "$remote_addr_anon" in zones
              and "$uri_anon" in zones, zones[-400:])
        # The one that makes it real: without this, nginx's own combined log
        # keeps running alongside ours and the anonymised copy is decoration.
        check(f"{label}: the stock combined log is cancelled",
              re.search(r"^access_log off;", zones, re.M) is not None,
              "no http-level `access_log off` — nginx.conf's combined log survives")
        # Scoped to the log_format directive, not the whole file: the
        # anonymizer is `map $remote_addr $remote_addr_anon`, so a check that
        # greps the file for $remote_addr flags the fix as the bug. The
        # question is only ever what the FORMAT interpolates.
        fmt = "".join(re.findall(r"^log_format\s+anon\s+(.*?);\s*$", zones,
                                 re.M | re.S))
        check(f"{label}: the anon format was found to inspect", bool(fmt), zones[-300:])
        for var, why in (("$http_user_agent", "the main re-identification "
                          "vector against an anonymized IP"),
                         ("$http_referer", "AUDIT.md §4.1 says it is not kept"),
                         ("$request'", "carries the raw path, secrets and all"),
                         ("$request ", "carries the raw path, secrets and all"),
                         ("$query_string", "AUDIT.md §4.1 says it is not kept"),
                         ("$remote_addr ", "the un-anonymized address"),
                         ("$remote_addr'", "the un-anonymized address"),
                         ("$uri'", "the un-collapsed path"),
                         ("$uri ", "the un-collapsed path")):
            check(f"{label}: no {var.strip(chr(39))} in the anon log format ({why})",
                  var not in fmt, fmt)

        # Every server block has to opt back in, or `access_log off` above
        # means the operator has no log at all.
        blocks = [b for b in site.split("\nserver {") if b.strip()][1:] or \
                 site.split("\nserver {")[1:]
        check(f"{label}: every server block writes the anon log",
              len(blocks) > 0 and all("access_log /var/log/nginx/0trust-access.log anon"
                                      in b for b in blocks),
              f"{len(blocks)} block(s), "
              f"{sum('0trust-access.log anon' in b for b in blocks)} with the log")
        csp = re.search(r'Content-Security-Policy "([^"]*)"', site)
        check(f"{label}: a CSP is set", csp is not None,
              "docs/README.md claims a strict CSP")
        # Read the match once, and only where there is one: calling .group()
        # on None raises, which aborts the whole module — so removing the CSP
        # header made this file stop testing rather than report a failure.
        policy = csp.group(1) if csp else ""
        check(f"{label}: the CSP allows no third-party origin",
              "default-src 'self'" in policy
              and "http" not in policy.replace("upgrade-insecure-requests", ""),
              policy or "no CSP header to inspect")

        # The canary works by STOPPING. A cached copy served after the
        # operator stops signing suppresses the one signal the document
        # exists to send. The reference config has had this block for a long
        # time; the generated one did not, so the deployed site served
        # /canary.txt as an ordinary static file with default caching.
        canary = re.search(r"location = /canary\.txt \{(.*?)\}", site, re.S)
        check(f"{label}: /canary.txt has its own location block",
              canary is not None,
              "served as a plain static file, with whatever caching nginx defaults to")
        check(f"{label}: and it is served no-store",
              canary is not None and "no-store" in canary.group(1),
              canary.group(1) if canary else "")

        lr = open(f"{d}/logrotate.conf").read()
        check(f"{label}: logrotate keeps two days, daily",
              "daily" in lr and re.search(r"^\s*rotate 2\s*$", lr, re.M),
              "privacy.html and AUDIT.md §4.2 both say 2 days; nginx's stock "
              "logrotate keeps 14 weekly rotations")
        check(f"{label}: logrotate names the file the config writes",
              "/var/log/nginx/0trust-access.log" in lr, lr[:200])

    print("\n[4] the committed production config is valid too")
    src = open(os.path.join(H.REPO, "nginx", "0trustvpn.com.conf")).read()
    src = (src.replace("/etc/nginx/snippets/", f"{TMP}/snippets/")
              .replace("/etc/letsencrypt/live/0trustvpn.com", TMP)
              .replace("/var/www/0trust", f"{TMP}/www")
              .replace("/var/www/acme", f"{TMP}/www")
              .replace("listen 443 ssl http2;", "listen 8443 ssl http2;")
              .replace("listen [::]:443 ssl http2;", "listen [::]:8443 ssl http2;")
              .replace("listen 80;", "listen 8081;")
              .replace("listen [::]:80;", "listen [::]:8081;"))
    zones = [l for l in src.splitlines() if l.startswith(("limit_req_zone", "limit_conn_zone"))]
    body = "\n".join(l for l in src.splitlines()
                     if not l.startswith(("limit_req_zone", "limit_conn_zone")))
    zp, sp2 = os.path.join(TMP, "cz.conf"), os.path.join(TMP, "cs.conf")
    open(zp, "w").write("\n".join(zones)); open(sp2, "w").write(body)
    good, err, _ = nginx_check(sp2, zp, "committed", [])
    check("nginx accepts nginx/0trustvpn.com.conf", good, err)

    # ...and it agrees with the generated one on everything that carries a
    # privacy claim. Two copies of a config is how the logging fix went
    # missing: the reference file had it, the installer did not, and nothing
    # compared them. This does not diff the files — they are legitimately
    # different shapes — only the directives a claim depends on. Adding one
    # to either copy alone is what this is here to catch.
    rendered = open(os.path.join(TMP, "render-prod", "site.conf")).read() + \
               open(os.path.join(TMP, "render-prod", "zones.conf")).read()
    committed = open(os.path.join(H.REPO, "nginx", "0trustvpn.com.conf")).read()
    for directive, claim in (
        ("map $remote_addr $remote_addr_anon", "privacy.html: IPs truncated to a /24"),
        ("map $uri $uri_anon", "AUDIT.md §4.1.1: secret path segments collapsed"),
        ("log_format anon", "AUDIT.md §4: the anon format is what is used"),
        ("$uri_anon", "the format has to USE the map, not just define it"),
        ("add_header Content-Security-Policy", "docs/README.md: strict CSP"),
        ("location = /canary.txt", "the canary must never be cached"),
        ("no-store", "the canary must never be cached"),
    ):
        in_gen, in_ref = directive in rendered, directive in committed
        check(f"both configs carry {directive!r} ({claim})",
              in_gen and in_ref,
              f"generated={in_gen} reference={in_ref} — the copy missing it is "
              f"the one that breaks the claim, and if that is the generated "
              f"config it is the one that deploys")

    print("\n[5] the routes that matter are present in both modes")
    for label in ("test", "prod"):
        body = globals().get(f"body_{label}", "")
        for want, why in (
            ("location = /api/v1/trial", "trial redemption has its own tight limiter"),
            ("location = /api/v1/account {", "signup is an EXACT match, not a prefix"),
            ("location = /api/v1/account/topup", "top-up shares the signup bucket"),
            ("location /api/v1/", "general API"),
            ("location /surf", "visitor proxy"),
            ("proxy_pass http://127.0.0.1:8081", "proxy is a separate upstream"),
            ("limit_conn surfconn", "per-IP connection cap on the proxy"),
            ("0trust-surf.conf", "proxy uses its own snippet, avoiding duplicates"),
            ("location = /trial", "trial page"),
        ):
            check(f"[{label}] {why}", want in body, body[:400])
    check("[prod] HSTS present", "Strict-Transport-Security" in globals().get("body_prod", ""))
    check("[prod] http redirects to https",
          "return 301 https://" in globals().get("body_prod", ""))
    check("[test] no TLS directives leak into test mode",
          "ssl_certificate" not in globals().get("body_test", ""))

    print("\n[4b] the environment the installer writes, on a NEW box and an old one")
    # Two paths write api.env and only one of them is ever exercised by a
    # test rig: the fresh-install branch. The other runs when install.sh is
    # re-run against a deployment that predates a key, appending what is
    # missing — so it is the path that touches a box with paying customers on
    # it, and the one nobody looks at.
    #
    # It appended ZTV_PAYMENT_PROVIDER=btcpay. poll_invoices.py returns
    # immediately unless the provider is `watch`, so an upgraded deployment
    # would go on issuing invoices with addresses derived from the operator's
    # own xpub, take real payments at them, and credit not one — with every
    # health check green and no BTCPay instance anywhere in the picture.
    sys.path.insert(0, os.path.join(H.REPO, "api"))
    import payments as _pay
    inst_txt = open(os.path.join(H.REPO, "scripts", "install.sh")).read()
    written = set(re.findall(r'ZTV_PAYMENT_PROVIDER=([a-z]+)"?\s*(?:;|\\|$)',
                             inst_txt, re.M))
    # Anything the script actually assigns, in either branch.
    assigned = set(re.findall(r"^ZTV_PAYMENT_PROVIDER=([a-z]+)\s*$", inst_txt, re.M)) \
             | set(re.findall(r'"ZTV_PAYMENT_PROVIDER=([a-z]+)"', inst_txt))
    check("every provider the installer writes is the single default",
          assigned and assigned == {_pay.DEFAULT_PROVIDER},
          f"install.sh writes {sorted(assigned)}, "
          f"payments.DEFAULT_PROVIDER is {_pay.DEFAULT_PROVIDER!r}")

    # And the same for the example file an operator might copy.
    ex = open(os.path.join(H.REPO, "systemd", "api.env.example")).read()
    ex_prov = set(re.findall(r"^ZTV_PAYMENT_PROVIDER=([a-z]+)\s*$", ex, re.M))
    check("and so is the one in api.env.example",
          ex_prov == {_pay.DEFAULT_PROVIDER},
          f"{sorted(ex_prov)} vs {_pay.DEFAULT_PROVIDER!r}")

    # CORS was a hardcoded reference domain in api/main.py. Same-origin on a
    # normal deployment so nothing broke, but an operator on their own domain
    # had a control plane naming somebody else's as its only allowed origin.
    main_txt = open(os.path.join(H.REPO, "api", "main.py")).read()
    # The environment READ, not the name in prose. The first version grepped
    # the whole file for "ZTV_ALLOWED_ORIGINS" and stayed green when the code
    # was renamed away, because the comment above it explaining the key still
    # said the words — the check-matches-its-own-comment failure, inside a
    # check written to catch a hardcoded literal.
    check("allowed origins are read from the environment, not hardcoded",
          re.search(r'os\.environ\.get\(\s*"ZTV_ALLOWED_ORIGINS"', main_txt)
          is not None,
          "install.sh takes --domain and api/main.py did not follow it")
    check("and the reference domain is only the fallback",
          re.search(r"ALLOWED_ORIGINS\s*=\s*_origins\s+or\b", main_txt)
          is not None,
          "0trustvpn.com must be what you get when nothing is configured, "
          "not what every deployment gets")
    check("and the installer writes them from --domain",
          "ZTV_ALLOWED_ORIGINS=" in inst_txt and "CORS_ORIGINS" in inst_txt)
    for label, d in (("prod", os.path.join(TMP, "render-prod")),):
        envp = os.path.join(d, "api.env")
        if os.path.exists(envp):
            envtxt = open(envp).read()
            m = re.search(r"^ZTV_ALLOWED_ORIGINS=(.*)$", envtxt, re.M)
            check(f"[{label}] the rendered env names the deployment's own domain",
                  m is not None and "example.com" in (m.group(1) or ""),
                  m.group(1) if m else "key absent")

    print("\n[5b] the routes that were only ever in the reference config")
    # nginx/0trustvpn.com.conf is a reference file the installer has never
    # installed. Six location blocks lived there and nowhere else, so on
    # every real deployment they did not exist. The worst one is not a 404
    # page — it is that /.well-known/security.txt was UNREACHABLE.
    for label in ("test", "prod"):
        body = globals().get(f"body_{label}", "")
        for want, why in (
            ("location = /security-policy",
             "security.txt names /security-policy as both Contact and Policy; "
             "without this block a researcher following RFC 9116 to report a "
             "vulnerability lands on a dead URL, and so does the footer link "
             "on every page"),
            ("location ^~ /.well-known/",
             "the server ends in `location ~ /\\. { deny all; }` and an nginx "
             "REGEX location beats a plain prefix one, so /.well-known/ "
             "matched the dotfile deny and 403ed — taking RFC 9116 discovery "
             "and the WKD key path down with it. ^~ outranks the regex"),
            ("location /releases/",
             "the download page links these directly"),
            ("location = /verify-release.sh",
             "download.html tells people to fetch and read it"),
            ("location /fonts/", "the brand faces are three quarters of the "
                                 "landing page's bytes and had no cache policy"),
            ("location = /robots.txt", "crawler directives"),
            ("location = /sitemap.xml", "the sitemap robots.txt advertises"),
        ):
            check(f"[{label}] {why[:60]}", want in body, why)

        # The precedence argument above is the whole reason ^~ is there, so
        # assert the shape rather than just the string: a plain-prefix
        # .well-known block next to that regex is the bug all over again.
        has_deny = "location ~ /\\. { deny all; }" in body or \
                   "location ~ /\\." in body
        caret = "location ^~ /.well-known/" in body
        plain = "\n    location /.well-known/ " in body
        check(f"[{label}] .well-known outranks the dotfile deny",
              (not has_deny) or (caret and not plain),
              "with `location ~ /\\.` present, .well-known must be ^~ or =")

    # A soft 404 is worse than a 404: try_files ... /index.html answered every
    # unknown URL with the landing page and a 200, so the branded error page
    # could never appear and a crawler could mint unlimited duplicate
    # homepages from typos.
    for label in ("test", "prod"):
        body = globals().get(f"body_{label}", "")
        check(f"[{label}] an unknown URL 404s instead of serving the homepage",
              "try_files $uri $uri/ =404;" in body
              and "try_files $uri $uri/ /index.html;" not in body,
              [l for l in body.splitlines() if "try_files $uri" in l])
        check(f"[{label}] and the branded error pages are still wired",
              "error_page 404 /404.html;" in body
              and "error_page 500 502 503 504 /50x.html;" in body)

    print("\n[5c] the same routes, asked for over HTTP by a real nginx")
    # [5b] asserts strings. This section makes the requests, because the claim
    # being made is about nginx LOCATION PRECEDENCE — that `^~` outranks the
    # `~ /\.` dotfile deny — and a grep cannot check a precedence rule. The
    # bug it is guarding was invisible to every string check in this file for
    # exactly that reason: the .well-known files were present, the deny was
    # correct, and the combination returned 403.
    import socket as _sock, time as _time
    def _free_port():
        s_ = _sock.socket(); s_.bind(("127.0.0.1", 0))
        port = s_.getsockname()[1]; s_.close(); return port

    def serve_and_probe(site_text, port):
        """Run nginx on `port` with this config and return {path: status}."""
        root = os.path.join(TMP, f"probe-www-{port}")
        os.makedirs(os.path.join(root, ".well-known", "openpgpkey", "hu"),
                    exist_ok=True)
        os.makedirs(os.path.join(root, "releases", "0.1.0"), exist_ok=True)
        for rel, body in (
            (".well-known/security.txt", "Contact: mailto:x@y.z\n"),
            (".well-known/openpgpkey/hu/abc", "key\n"),
            ("security-policy.html", "<html>policy</html>"),
            ("robots.txt", "User-agent: *\n"),
            ("sitemap.xml", "<urlset/>"),
            ("index.html", "<html>home</html>"),
            ("404.html", "<html>not found</html>"),
            ("verify-release.sh", "#!/bin/sh\n"),
            ("releases/0.1.0/0trust-linux-amd64", "ELF"),
            (".env", "SECRET=1"),
        ):
            with open(os.path.join(root, rel), "w") as fh:
                fh.write(body)

        text = site_text
        for a, b in (("listen 443 ssl http2;", f"listen {port};"),
                     ("listen 80 default_server;", f"listen {port};"),
                     ("listen 80;", f"listen {port};")):
            text = text.replace(a, b)
        text = "\n".join(l for l in text.splitlines()
                          if "listen [::]" not in l and "ssl_" not in l)
        text = (text.replace("/etc/nginx/snippets/", f"{TMP}/snippets/")
                    .replace("/var/log/nginx/", f"{TMP}/"))
        # Every root, not the first one: the config has a server block per
        # scheme and pointing only one of them at the fixture serves the
        # other from nginx's compiled-in prefix, which 404s everything and
        # looks exactly like the bug under test.
        text = re.sub(r"^(\s*)root .*$", f"\\1root {root};", text, flags=re.M)
        conf = os.path.join(TMP, f"probe-{port}.conf")
        pid = os.path.join(TMP, f"probe-{port}.pid")
        # nginx's master runs as whoever started it and its workers drop to
        # an unprivileged user. TMP comes from mkdtemp at 0700, so those
        # workers cannot traverse it and every file answers 403 — the same
        # status the dotfile deny returns, which would make this whole
        # section pass or fail for the wrong reason.
        as_user = "user root;" if os.geteuid() == 0 else ""
        open(conf, "w").write(f"""
{as_user}
events {{ worker_connections 32; }}
error_log {TMP}/probe-{port}-err.log;
pid {pid};
daemon on;
http {{
  access_log off;
  client_body_temp_path {TMP}/probe-body-{port};
  proxy_temp_path {TMP}/probe-proxy-{port};
  fastcgi_temp_path {TMP}/probe-fcgi-{port};
  uwsgi_temp_path {TMP}/probe-uwsgi-{port};
  scgi_temp_path {TMP}/probe-scgi-{port};
  include {TMP}/zones-probe.conf;
{text}
}}
""")
        r = subprocess.run(["nginx", "-c", conf, "-p", TMP],
                           capture_output=True, text=True)
        if r.returncode != 0:
            return None, r.stderr[-500:]
        try:
            for _ in range(50):
                try:
                    _sock.create_connection(("127.0.0.1", port), 0.2).close()
                    break
                except OSError:
                    _time.sleep(0.1)
            out = {}
            for path in ("/.well-known/security.txt",
                         "/.well-known/openpgpkey/hu/abc",
                         "/security-policy", "/robots.txt", "/sitemap.xml",
                         "/verify-release.sh",
                         "/releases/0.1.0/0trust-linux-amd64",
                         "/", "/no-such-page-here", "/.env"):
                c = subprocess.run(
                    ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                     "--max-time", "5", f"http://127.0.0.1:{port}{path}"],
                    capture_output=True, text=True)
                out[path] = c.stdout.strip()
            return out, ""
        finally:
            if os.path.exists(pid):
                subprocess.run(["nginx", "-c", conf, "-p", TMP, "-s", "quit"],
                               capture_output=True)
                _time.sleep(0.4)

    open(os.path.join(TMP, "zones-probe.conf"), "w").write(
        open(os.path.join(TMP, "render-test", "zones.conf")).read())
    site_src = open(os.path.join(TMP, "render-test", "site.conf")).read()
    port = _free_port()
    codes, err = serve_and_probe(site_src, port)
    check("a real nginx serves the generated config", codes is not None, err)
    if codes:
        for path, want, why in (
            ("/.well-known/security.txt", "200",
             "RFC 9116 discovery — 403 here and researchers have nowhere to "
             "send a vulnerability report"),
            ("/.well-known/openpgpkey/hu/abc", "200",
             "WKD — the key security.txt says to encrypt reports to"),
            ("/security-policy", "200", "the URL security.txt names twice"),
            ("/robots.txt", "200", "crawler directives"),
            ("/sitemap.xml", "200", "the sitemap robots.txt advertises"),
            ("/verify-release.sh", "200", "download.html links it"),
            ("/releases/0.1.0/0trust-linux-amd64", "200", "a release artifact"),
            ("/", "200", "the landing page"),
            ("/no-such-page-here", "404",
             "a soft 200 here is a duplicate homepage for every typo"),
            ("/.env", "403", "the dotfile deny still has to work"),
        ):
            check(f"GET {path} -> {want} ({why[:44]})",
                  codes.get(path) == want, f"got {codes.get(path)}")

    # The mutation, in the same run: put the .well-known block back to a
    # plain prefix and confirm the dotfile deny takes it. If this does NOT
    # 403, the ^~ above is decoration and [5b] is testing nothing.
    broken = site_src.replace("location ^~ /.well-known/ {",
                              "location /.well-known/ {")
    check("the ^~ is load-bearing, not decoration",
          broken != site_src, "no ^~ /.well-known/ block to weaken")
    if broken != site_src:
        bport = _free_port()
        bcodes, berr = serve_and_probe(broken, bport)
        # The WKD path, NOT security.txt. Measured, because the first version
        # of this probe asked about security.txt and passed either way: a
        # nested `location = ...` is promoted into nginx's exact-match tree
        # and wins before regexes are consulted, so that one file is rescued
        # with or without ^~ on the parent. The nested `^~ .../openpgpkey/`
        # is an ordinary nested prefix and gets no such promotion, so it is
        # the path where the parent's ^~ is the difference between 200 and
        # 403 — verified both ways against a running nginx 1.24.
        probe = "/.well-known/openpgpkey/hu/abc"
        check("without ^~, WKD really is denied by the dotfile rule",
              bcodes is not None and bcodes.get(probe) == "403",
              f"got {bcodes.get(probe) if bcodes else berr} — expected 403, "
              "which is what every deployment was returning for the key "
              "security.txt tells reporters to encrypt to")

    print("\n[6] the rendered config is not corrupted by shell expansion")
    # Backticks inside install.sh's unquoted heredocs are command substitution,
    # not quoting — they silently blank the text they wrap. Caught once; this
    # keeps it caught.
    for label in ("test", "prod"):
        body = globals().get(f"body_{label}", "")
        check(f"[{label}] no empty-comment artefacts from backtick expansion",
              "# , " not in body and "#  —" not in body,
              [l for l in body.splitlines() if "# , " in l or "#  —" in l][:3])
        check(f"[{label}] no unexpanded shell variables left in the config",
              "$DOMAIN" not in body and "$WEBROOT" not in body and "$MODE" not in body,
              [l for l in body.splitlines() if "$DOMAIN" in l or "$WEBROOT" in l][:3])
    check("[prod] the domain was substituted",
          "example.com" in globals().get("body_prod", ""))
    print("\n[7] test mode stands up a real mesh on the same box")
    # The point of --mode test is that one VPS is the whole product, VPN
    # included. Everything below is a file the installer would write onto a
    # real box; nft and the parsers here are the same ones that would reject
    # it there, at a much more expensive moment.
    d = os.path.join(TMP, "render-test")
    # `nft -c` parses without loading, but it still opens a netlink socket to
    # build its cache, so without CAP_NET_ADMIN it fails with "Operation not
    # permitted" — nothing to do with the ruleset. Probe once with a ruleset
    # known to be good, and treat a permission failure as "cannot check here"
    # rather than as a broken ruleset.
    have_nft = shutil.which("nft") is not None
    if have_nft:
        _probe = subprocess.run(
            ["nft", "-c", "-f", "-"], capture_output=True, text=True,
            input="table inet ztv_probe {\n  chain c {\n    type filter hook forward priority 0;\n  }\n}\n")
        if _probe.returncode != 0:
            have_nft = False
            print(f"  SKIP  nft cannot run here ({(_probe.stderr or '').strip()[:60]})")

    for iface, node, port, gw in (("wg0", "zur-01", "51820", "10.64.0.1"),
                                  ("wg1", "rey-01", "51821", "10.64.0.2"),
                                  ("wg2", "buc-01", "51822", "10.64.0.3")):
        envp = f"{d}/meshd-{iface}.env"
        check(f"meshd env rendered for {node}", os.path.exists(envp))
        if not os.path.exists(envp):
            continue
        kv = dict(l.split("=", 1) for l in open(envp).read().splitlines()
                  if "=" in l and not l.startswith("#"))
        check(f"{node}: bound to {iface}", kv.get("WG_IFACE") == iface, kv)
        check(f"{node}: listens on {port}", kv.get("WG_PORT") == port, kv)
        check(f"{node}: is both entry and exit", kv.get("NODE_ROLE") == "both", kv)
        # Three meshd processes sharing one nftables table would each wipe the
        # other two's DNAT rules every poll, and multi-hop would work only for
        # whichever polled last.
        check(f"{node}: has its own nftables table",
              kv.get("ZTV_NFT_TABLE") == f"ztv_fwd_{iface}", kv)
        # A /10 on three interfaces gives the kernel three equally good routes
        # to every client; meshd's per-peer /32s are what disambiguate.
        check(f"{node}: gateway is a /32, not the whole mesh",
              kv.get("MESH_GATEWAY") == f"{gw}/32", kv)

    tables = set()
    for iface in ("wg0", "wg1", "wg2"):
        envp = f"{d}/meshd-{iface}.env"
        if os.path.exists(envp):
            for l in open(envp):
                if l.startswith("ZTV_NFT_TABLE="):
                    tables.add(l.strip().split("=", 1)[1])
    check("the three nodes' nftables tables are all distinct", len(tables) == 3, tables)

    for name, why in (("nat.nft", "masquerade"), ("egress.nft", "abuse filter")):
        fp = f"{d}/{name}"
        check(f"{why} ruleset rendered", os.path.exists(fp))
    if os.path.exists(f"{d}/nat.nft") and os.path.exists(f"{d}/egress.nft"):
        nat, eg = open(f"{d}/nat.nft").read(), open(f"{d}/egress.nft").read()
        check("masquerade covers the mesh network", "10.64.0.0/10 masquerade" in nat, nat)
        check("egress filter blocks outbound mail", "25, 465, 587" in eg, eg[:300])
        check("egress filter blocks pivoting into private ranges",
              "169.254.0.0/16" in eg and "192.168.0.0/16" in eg, eg[:300])
        if have_nft:
            r = subprocess.run(["nft", "-c", "-f", "-"], input=nat + eg,
                               capture_output=True, text=True)
            # This is the check that would have caught the table name starting
            # with a digit, which nft rejects outright — so neither the exit
            # masquerade nor the abuse filter was ever in force on any node.
            check("nft accepts the rulesets the installer writes", r.returncode == 0,
                  (r.stderr or r.stdout)[-400:])
        else:
            print("  SKIP  nft accepts the rulesets the installer writes")

    # meshd's own DNAT ruleset, generated the way a node would generate it.
    # Generating and inspecting it needs no privileges; only handing it to nft
    # does, so the generation checks run everywhere and only the parse is gated.
    import importlib.util
    os.environ["ZTV_NFT_TABLE"] = "ztv_fwd_wg0"
    os.environ.setdefault("CONTROL_URL", "http://127.0.0.1:8080")
    os.environ.setdefault("NODE_API_PSK", "x")
    os.environ.setdefault("NODE_ID", "zur-01")
    spec = importlib.util.spec_from_file_location(
        "meshd", os.path.join(H.REPO, "wireguard", "0trust-meshd.py"))
    meshd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(meshd)
    rules = meshd.build_nft_ruleset([
        {"entry_port": 52001, "exit_endpoint": "203.0.113.5:51821"},
        {"entry_port": 52002, "exit_endpoint": "[2001:db8::1]:51822"},
    ])
    check("meshd honours a per-node table name",
          "table inet ztv_fwd_wg0" in rules, rules[:120])
    # An inet table serves both families, so nft refuses a bare `dnat to`.
    check("DNAT is family-qualified for both v4 and v6",
          "dnat ip to 203.0.113.5:51821" in rules
          and "dnat ip6 to [2001:db8::1]:51822" in rules, rules)
    # Routes: three interfaces in one /10 need per-peer /32s to be
    # unambiguous, and the daemon must never delete a route it did not add.
    check("meshd keeps peer routes inside the mesh network",
          meshd._in_mesh("10.64.0.5/32") and not meshd._in_mesh("8.8.8.8/32"))
    check("meshd only manages its own routes", meshd.ROUTE_PROTO == "static")

    if have_nft:
        r = subprocess.run(["nft", "-c", "-f", "-"], input=rules,
                           capture_output=True, text=True)
        check("nft accepts meshd's multi-hop DNAT ruleset", r.returncode == 0,
              (r.stderr or r.stdout)[-400:])
    else:
        print("  SKIP  nft accepts meshd's multi-hop DNAT ruleset")

    # The resolver. Clients are handed DNS = the mesh gateway; until this
    # existed nothing listened there and a connected customer resolved nothing.
    dnsp = f"{d}/dnsmasq.conf"
    check("resolver config rendered", os.path.exists(dnsp))
    if os.path.exists(dnsp):
        dns = open(dnsp).read()
        check("resolver answers on the gateway the API hands out",
              "listen-address=10.64.0.1" in dns, dns[:200])
        # Without this dnsmasq also answers on the public address, which is an
        # open resolver: free DNS amplification and an abuse report by morning.
        check("resolver is not open to the internet", "bind-interfaces" in dns, dns[:300])
        check("resolver ignores the host's own resolv.conf", "no-resolv" in dns)
        check("resolver does not log customer queries",
              not re.search(r"^\s*log-queries", dns, re.M), dns[:400])

    if shutil.which("dnsmasq") and os.path.exists(dnsp):
        r = subprocess.run(["dnsmasq", "--test", f"--conf-file={dnsp}"],
                           capture_output=True, text=True)
        check("dnsmasq accepts the rendered config", r.returncode == 0,
              (r.stderr or r.stdout)[-300:])

    print("\n[7c] payments can be made to work on a box with nothing else")
    # The whole claim of the watch-only provider is that a fresh VPS can take
    # money with no account signed up for anywhere. The installer has to
    # actually ship it and say how.
    rc, out = run_installer("--mode", "test")
    check("the summary says what paid signup needs", "xpub" in out.lower(), out[-900:])
    check("and does not still claim payments are simply unconfigured",
          "Payments are unconfigured" not in out, out[-900:])
    installer_src = open(INSTALL).read()
    for want, why in (
        ("0trust-poll.timer", "the settlement poller is installed"),
        # chainwatch.py / poll_invoices.py used to be grepped for by name
        # here. They moved into the staged-set check just below, because a
        # name appearing in the script is not the same claim as the file
        # reaching the box — and the difference is what hid monerowatch.py.
        ("ZTV_PAYMENT_PROVIDER=watch", "watch-only is the default provider"),
        ("WALLET_BTC", "the wallet key is in the generated env file"),
    ):
        check(why, want in installer_src, f"{want} missing from install.sh")

    staged = staged_api_files()
    for name, why in (("chainwatch.py", "address derivation reaches the box"),
                      ("poll_invoices.py", "the settlement poller reaches the box"),
                      ("monerowatch.py", "the Monero watcher reaches the box"),
                      ("payments.py", "the provider layer reaches the box")):
        check(why, name in staged,
              f"install.sh never places api/{name} in $PREFIX/api/")

    print("\n[8] the summary tells the truth about a one-box deployment")
    rc, out = run_installer("--mode", "test")
    for want, why in (
        ("No TLS", "says there is no TLS"),
        ("one jurisdiction", "says three regions are one machine"),
        ("Multi-hop does not hide you here", "says multi-hop proves nothing here"),
        ("--mode node", "points at the real, separate-node path"),
    ):
        check(f"test summary {why}", want in out, out[-800:])
    rc, out = run_installer("--mode", "test", "--no-vpn")
    check("--no-vpn exits 0", rc == 0, out[-300:])
    check("--no-vpn admits the tunnels are fake",
          "placeholder" in out and "cannot" in out, out[-700:])
    check("--no-vpn does not claim the VPN works", "The VPN works" not in out)

    print("\n[1c] the host is checked before anything is changed")
    # Every one of these used to surface part-way through: an unresolvable
    # domain at certbot, with packages, the service user, secrets, the
    # database and nginx already written; a busy port 80 at `nginx -t`. A
    # failure that costs five seconds and changes nothing is a different
    # thing from one that leaves a half-built box behind.
    # A dry run reports and continues — there is no state to protect, and an
    # operator rendering configs on a laptop should not be blocked by that
    # laptop. What matters is that the diagnostic appears, and that it says a
    # real install would stop.
    rc, out = run_installer("--mode", "production",
                            "--domain", "nope.invalid", "--email", "a@b.c")
    check("an unresolvable domain is reported", "does not resolve" in out,
          out[-400:])
    check("and the dry run says a real install would stop",
          "a real install would stop here" in out, out[-400:])
    check("preflight does not then claim to have passed",
          "host preflight passed" not in out,
          "saying 'passed' under 'would stop here' is a contradiction")
    # The bug this check itself had: getent exits 2 for a name that does not
    # resolve, `set -o pipefail` propagates that out of the command
    # substitution, and `set -e` then killed the installer with a bare exit 2
    # and no message at all — on precisely the input the check exists to
    # report.
    check("the failure is reported, not a silent non-zero exit",
          "[!]" in out, f"exit {rc} with no diagnostic:\n{out[-300:]}")

    # A name that resolves SOMEWHERE ELSE. This used to use example.com and
    # so needed working external DNS: on an air-gapped runner the name did
    # not resolve, the installer took the "does not resolve" branch instead,
    # and both assertions below failed for a reason that had nothing to do
    # with the product. A hosts entry makes getent — which is what the
    # installer actually calls — return a controlled answer with no network
    # and no third-party domain.
    #
    # 198.51.100.9 is TEST-NET-2 (RFC 5737), reserved for documentation, so
    # it cannot be an address this box holds and cannot route anywhere.
    HOSTS, STUB = "/etc/hosts", "ztv-elsewhere.test"
    _hosts_before = None
    try:
        try:
            _hosts_before = open(HOSTS).read()
            with open(HOSTS, "a") as fh:
                fh.write(f"\n198.51.100.9 {STUB}\n")
            _resolvable = subprocess.run(["getent", "ahostsv4", STUB],
                                         capture_output=True).returncode == 0
        except OSError:
            _resolvable = False

        if _resolvable:
            rc, out = run_installer("--mode", "production", "--domain", STUB,
                                    "--email", "a@b.c")
            check("a domain resolving elsewhere warns but proceeds", rc == 0,
                  "behind NAT or a proxy this is legitimate; refusing would "
                  "be wrong")
            check("and prints both sides so the operator can compare",
                  "resolves to" in out and "this box has" in out, out[-400:])
        else:
            # Honest about what did not run. Saying PASS here would be the
            # SKIP-standing-in-for-a-pass failure this repo keeps finding.
            print("  SKIP  a domain resolving elsewhere warns but proceeds"
                  "  <- cannot write /etc/hosts to stage a resolvable name")
            print("  SKIP  and prints both sides so the operator can compare"
                  "  <- same")
    finally:
        if _hosts_before is not None:
            try:
                open(HOSTS, "w").write(_hosts_before)
            except OSError:
                pass

    rc, out = run_installer("--skip-preflight", "--mode", "production",
                            "--domain", "nope.invalid", "--email", "a@b.c")
    check("--skip-preflight is an escape hatch that works", rc == 0, out[-300:])
    check("and it really skips", "does not resolve" not in out, out[-300:])

    src_pf = open(INSTALL).read()
    for want, why in (("df -Pm", "disk space is checked"),
                      ("ss -lntpH", "a busy port 80/443 is caught early"),
                      ("getent ahostsv4", "DNS is checked before certbot runs"),
                      ("type wireguard", "kernel WireGuard support is probed")):
        check(why, want in src_pf, f"{want!r} missing from install.sh")

    print("\n[6a] a host with no IPv6 can still be installed")
    # Three separate aborts, all the same assumption: that every Ubuntu 24.04
    # box has an IPv6 stack. Plenty do not, and each failure landed part-way
    # through — after packages, the service user, secrets and the database.
    #
    # Found by running the installer for real rather than by reading it, and
    # the emulation suite had actually WORKED AROUND the first one (nginx -t
    # binds, so nginx_check wraps it), which is how a green test sat on top of
    # a broken install for so long.
    for want6 in ("0", "1"):
        out = os.path.join(TMP, f"render-v6-{want6}")
        os.makedirs(out, exist_ok=True)
        env = {**os.environ, "TERM": "dumb", "ZTV_RENDER_TO": out,
               "ZTV_NGINX_IPV6": want6}
        r = subprocess.run(["bash", INSTALL, "--dry-run", "--mode", "test"],
                           capture_output=True, text=True, timeout=180, env=env)
        site = os.path.join(out, "site.conf")
        check(f"dry run renders with ZTV_NGINX_IPV6={want6}",
              r.returncode == 0 and os.path.exists(site),
              (r.stdout + r.stderr)[-400:])
        if os.path.exists(site):
            conf = open(site).read()
            has6 = "listen [::]" in conf
            check(f"IPv6 listeners are {'present' if want6=='1' else 'absent'} "
                  f"when the host {'has' if want6=='1' else 'has no'} IPv6",
                  has6 == (want6 == "1"),
                  "nginx -t BINDS every listener, so a stray `listen [::]` is "
                  "not a cosmetic issue — it aborts the install with "
                  "'Address family not supported by protocol'")
            check(f"IPv4 listeners are always present (v6={want6})",
                  "listen 80" in conf, conf[:300])

    # The sysctl file goes to /etc/sysctl.d, so a key the kernel does not have
    # fails `sysctl -p` at install time AND on every boot afterwards.
    runtime = os.path.join(H.REPO, "scripts", "node-runtime.sh")
    for want6 in ("0", "1"):
        r = subprocess.run(["bash", "-c", f"source {runtime!r}; ztv_sysctl_conf"],
                           capture_output=True, text=True, timeout=60,
                           env={**os.environ, "ZTV_HAS_IPV6": want6})
        body = r.stdout
        active6 = any(l.strip().startswith("net.ipv6.")
                      for l in body.splitlines())
        check(f"sysctl conf sets ipv6 forwarding only with IPv6 (v6={want6})",
              active6 == (want6 == "1"),
              f"emitted:\n{body}")
        check(f"sysctl conf always sets ipv4 forwarding (v6={want6})",
              "net.ipv4.ip_forward=1" in body, body)

    print("\n[6d] the installer proves the control plane before claiming it")
    # Same non-evidence as the VPN claim: `systemctl enable --now` returning 0
    # means systemd accepted the unit, not that uvicorn bound a port or that
    # main.py imported. This printed a green line and then a list of URLs
    # regardless, so an operator whose API died on a bad env file or a missing
    # module got cheerful links to nothing.
    src_v = open(INSTALL).read()
    check("the install curls the API before saying it is up",
          "/api/v1/status/public" in src_v and "API_OK" in src_v,
          "nothing verifies that 0trust-api actually answers")
    check("and curls the site through nginx",
          "WEB_OK" in src_v, "nothing verifies nginx serves anything")
    check("a failure is reported with the command to diagnose it",
          "journalctl -u 0trust-api" in src_v, src_v[-200:])
    check("the summary tells the operator when something did not come up",
          "INSTALL_DEGRADED" in src_v and "Not everything came up" in src_v,
          "a degraded install must not read like a clean one")
    check("INSTALL_DEGRADED is initialised before use",
          re.search(r'^INSTALL_DEGRADED=0', src_v, re.M) is not None,
          "set -u would abort on an unset flag in the summary")
    check("and it says a re-run is safe, because it is",
          "idempotent" in src_v, "the operator needs to know nothing needs undoing")

    print("\n[6c] the installer proves the VPN before claiming it")
    # It printed a green "The VPN works" unconditionally. `systemctl enable
    # --now` succeeding says nothing about whether meshd created an interface,
    # and on a kernel without WireGuard — ordinary on LXC and OpenVZ VPSes —
    # it creates none. The operator was told three tunnels were carrying
    # traffic on a box that could not make one. `0trust connect` already holds
    # itself to the opposite standard, waiting for a handshake before it
    # claims anything.
    src = open(INSTALL).read()
    check("the mesh step probes for the interface it just asked for",
          "ip link show" in src,
          "nothing checks that meshd actually created wg0")
    check("the summary is conditional on that probe",
          "VPN_BROKEN" in src and "$DO_VPN -eq 1 && $VPN_BROKEN -eq 1" in src,
          "'The VPN works' is printed without consulting the probe")
    check("and the failure path names the usual cause",
          "type wireguard" in src and ("LXC" in src or "OpenVZ" in src),
          "an operator on a container VPS needs to be told why, not just that")
    check("VPN_BROKEN is initialised before use",
          re.search(r'^VPN_BROKEN=0', src, re.M) is not None,
          "set -u would abort on an unset flag in the summary")

    print("\n[6b] the api tree the installer places can actually import")
    # The suite runs the control plane out of the source checkout, where every
    # module is present by definition. The installer copied a hand-kept list,
    # and the list was short by two:
    #
    #   api/monerowatch.py       imported unconditionally at the top of
    #                            payments.py, so the INSTALLED tree could not
    #                            import payments at all. The API did not start
    #                            — on every provider, whether or not the
    #                            operator wanted Monero — and no test noticed
    #                            because no test ever imported what was
    #                            installed rather than what was committed.
    #   api/mint-provision-token.py   named by this script's own closing
    #                            instructions at a path it never created.
    #
    # So: work out what the installer places, stage exactly that, and import
    # it with nothing else on the path.
    api_src = os.path.join(H.REPO, "api")
    staged = staged_api_files()
    check("the installer places api modules", bool(staged), sorted(staged))

    stage = os.path.join(TMP, "prefix-api")
    os.makedirs(stage, exist_ok=True)
    for name in staged:
        src = os.path.join(api_src, name)
        if os.path.exists(src):
            shutil.copy(src, stage)
    missing = sorted(n for n in staged if not os.path.exists(os.path.join(api_src, n)))
    check("every file the installer names exists in the repo", not missing,
          f"install would abort on: {missing}")

    # Import in a subprocess with ONLY the staged directory on the path, so a
    # module that happens to be importable from the checkout cannot mask a
    # file the installer forgot.
    # Run FROM the staged directory with PYTHONPATH cleared, which is the
    # path the service itself gets: the staged modules, the stdlib and the
    # venv, and nothing from the source checkout.
    probe = ("import payments, main, admin, poll_invoices, sweep, chainwatch\n"
             "print('ok')")
    probe_env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    probe_env["ZTV_DB_PATH"] = os.path.join(TMP, "probe.db")
    r = subprocess.run([sys.executable, "-c", probe], capture_output=True,
                       text=True, timeout=180, cwd=stage, env=probe_env)
    check("the installed tree imports the whole control plane",
          r.returncode == 0 and "ok" in r.stdout,
          (r.stdout + r.stderr)[-500:])

    # And the operator tools the script tells you to run must be there too.
    closing = re.findall(r'\$PREFIX/api/([A-Za-z0-9_.-]+\.py)',
                         open(INSTALL).read())
    for name in sorted(set(closing)):
        check(f"install.sh's own instructions can run {name}",
              name in staged,
              f"the summary points at $PREFIX/api/{name}, which nothing installs")

    print("\n[7] every systemd unit's dependencies are actually installed")
    # A unit that references a script or env file nothing places is a timer
    # that fails nightly on a real box and never in a test. Both the backup
    # script and its env file went missing this way.
    import glob as _glob
    installer = open(INSTALL).read()
    # canary/systemd/ too. Globbing systemd/ alone is how this check missed
    # 0trust-canary-check.service, whose ExecStart pointed at
    # $PREFIX/canary/scripts/check.sh while every canary script lived only in
    # the source checkout — 203/EXEC nightly, under an active timer, guarding
    # the warrant canary.
    units = sorted(_glob.glob(os.path.join(H.REPO, "systemd", "*.service"))
                   + _glob.glob(os.path.join(H.REPO, "canary", "systemd",
                                             "*.service")))
    check("systemd units found", bool(units))

    # And the unit FILE itself has to be installed, not just the script it
    # runs. That distinction is the whole of this bug: the canary scripts
    # were placed at $PREFIX/canary/scripts (a hole found and fixed once
    # already), and the timer that runs them was never copied to
    # /etc/systemd/system at all — because the loop that installs units read
    # systemd/ and the canary's units live under canary/systemd/. So the
    # freshness alarm had never run on any deployment: the check above passed
    # the whole time, because it only ever asked about ExecStart.
    #
    # That alarm is what tells an operator they missed a signing deadline, on
    # the one document written to be relied on when it stops appearing.
    all_units = sorted(
        _glob.glob(os.path.join(H.REPO, "systemd", "*.service"))
        + _glob.glob(os.path.join(H.REPO, "systemd", "*.timer"))
        + _glob.glob(os.path.join(H.REPO, "canary", "systemd", "*.service"))
        + _glob.glob(os.path.join(H.REPO, "canary", "systemd", "*.timer")))
    def _code(text):
        """Shell with whole-line comments removed.

        The first version of this searched the raw file, and install.sh
        happens to NAME 0trust-canary-check.service in a comment explaining
        the previous bug in that unit. So deleting the line that installs it
        left the check green — a check matching its own explanatory prose,
        inside a check written to catch a unit nobody installs."""
        return "\n".join(l for l in text.splitlines()
                          if not l.lstrip().startswith("#"))

    def _placing_lines(text):
        """Only the lines that actually put a unit somewhere.

        `systemctl enable --now 0trust-canary-check.timer` names a unit
        without installing it, and matching the whole file meant the timer
        passed on that line alone while its install had been deleted. A unit
        is installed by an `install` command, or by being listed in the
        `for unit in ...` loop that runs one; nothing else counts."""
        out = []
        for line in _code(text).splitlines():
            st = line.strip()
            # The verbs that actually place a file in this tree: install,
            # `run install` (the dry-run wrapper), and cp in
            # bootstrap-node.sh. Continuation lines come along with them.
            placing = (st.startswith("install ") or st.startswith("run install ")
                       or st.startswith("cp ") or st.startswith("for unit in"))
            if placing or (out and out[-1].endswith("\\")):
                out.append(st)
        return "\n".join(out)

    installer_code = _placing_lines(installer)
    node_bootstrap = ""
    nb = os.path.join(H.REPO, "scripts", "bootstrap-node.sh")
    if os.path.exists(nb):
        node_bootstrap = _placing_lines(open(nb).read())
    for unit_path in all_units:
        unit = os.path.basename(unit_path)
        placed = unit in installer_code or unit in node_bootstrap
        check(f"something installs {unit}", placed,
              f"{unit} exists in the tree and no deploy step copies it to "
              f"/etc/systemd/system — it can never run")

    for unit_path in units:
        unit = os.path.basename(unit_path)
        text = open(unit_path).read()

        # Every EnvironmentFile needs a committed .example next to it.
        for ef in re.findall(r"EnvironmentFile=-?(\S+)", text):
            # A templated unit names its env file after the instance
            # (meshd-%i.env); the example is the un-instanced one.
            name = os.path.basename(ef).replace("-%i", "").replace(".env", ".env.example")
            check(f"{unit}: {os.path.basename(ef)} has an example",
                  os.path.exists(os.path.join(H.REPO, "systemd", name)),
                  f"expected systemd/{name}")

        # Every executable it runs from /opt must be something we install.
        for exe in re.findall(r"ExecStart=(\S+)", text):
            if not exe.startswith("/opt/0trust"):
                continue
            rel = exe.replace("/opt/0trust/", "")
            if rel.startswith("api/.venv/"):
                continue  # created by the venv step
            check(f"{unit}: installer places {rel}",
                  os.path.basename(rel) in installer,
                  f"{exe} is run by the unit but never installed")

    # Units the installer knows about should exist in the repo. The character
    # class has to include the hyphen: it did not, so every multi-word unit
    # name — 0trust-node-enroll.service among them — was silently exempt from
    # this check, which is exactly where a typo'd filename would hide.
    # Units live in systemd/ except the canary's, which ship beside the canary
    # scripts they run.
    UNIT_DIRS = ("systemd", os.path.join("canary", "systemd"))
    for unit in sorted(set(
            re.findall(r"(0trust-[a-z-]+@?\.(?:service|timer))", installer))):
        check(f"installer references a real unit: {unit}",
              any(os.path.exists(os.path.join(H.REPO, d, unit))
                  for d in UNIT_DIRS),
              f"{unit} is named in install.sh but exists in none of "
              + ", ".join(UNIT_DIRS))

    print("\n[3c] fail2ban, and the jail we deliberately do NOT ship")
    import configparser
    jail_src = os.path.join(H.REPO, "config", "fail2ban", "0trust.local")
    check("the jail file exists", os.path.exists(jail_src),
          "install.sh added the fail2ban PACKAGE to the control plane and "
          "wrote no configuration at all, so what protected the box was "
          "whatever the distro enabled by default")
    if os.path.exists(jail_src):
        cp = configparser.ConfigParser()
        cp.read(jail_src)
        check("it parses as fail2ban configuration", "sshd" in cp.sections(),
              cp.sections())
        check("the sshd jail is enabled",
              cp["sshd"].get("enabled") == "true", dict(cp["sshd"]))
        # Ubuntu 24.04 ships no rsyslog by default and a node's journald is
        # volatile on purpose. A jail pointed at /var/log/auth.log would find
        # nothing and report itself healthy.
        check("and reads the journal, not a log file that may not exist",
              cp["sshd"].get("backend") == "systemd", dict(cp["sshd"]))
        check("the mesh cannot lock the box out of its own network",
              "10.64.0.0/10" in cp["DEFAULT"].get("ignoreip", ""),
              cp["DEFAULT"].get("ignoreip"))

    inst = open(os.path.join(H.REPO, "scripts", "install.sh")).read()
    check("nodes get fail2ban, not just the control plane",
          "NODE_PACKAGES+=(ufw fail2ban)" in inst,
          "every node runs `ufw allow 22/tcp`; they had the open port and "
          "none of the protection")
    check("and ssh hardening runs on nodes too",
          'harden_sshd "node"' in inst,
          "it was production-only, so password auth stayed open on the boxes "
          "that carry customer traffic and have nobody watching them")
    check("the installer checks the jail actually LOADED",
          "fail2ban-client status sshd" in inst,
          "systemctl reporting active says nothing about whether the jail "
          "parsed — bug class #16")

    # The finding this file has to protect, because the obvious next commit
    # is somebody adding an nginx jail.
    jail_txt = open(jail_src).read() if os.path.exists(jail_src) else ""
    check("no jail is pointed at the nginx access log",
          "0trust-access.log" not in jail_txt.split("# Anyone tempted")[0],
          "our access log records the client address truncated to a /24, so a "
          "jail fed by it can only ban 254 uninvolved people alongside the "
          "attacker")
    check("and the file explains why, where someone would look",
          "/24" in jail_txt and "limit_req_zone" in jail_txt,
          "the reason has to sit next to the thing, or the next person adds "
          "the jail that looks missing")
    # And the premise of that reasoning has to stay true. Read the bytes the
    # installer would write, not the reference file it has never installed.
    f2b_out = os.path.join(TMP, "render-f2b"); os.makedirs(f2b_out, exist_ok=True)
    subprocess.run(["bash", INSTALL, "--dry-run", "--mode", "test"],
                   capture_output=True, text=True, timeout=180,
                   env={**os.environ, "TERM": "dumb", "ZTV_RENDER_TO": f2b_out})
    zones_p = os.path.join(f2b_out, "zones.conf")
    zones = open(zones_p).read() if os.path.exists(zones_p) else ""
    fmt = [l for l in zones.splitlines() if "log_format anon" in l]
    check("the premise holds: the access log really is anonymized",
          bool(fmt) and "$remote_addr_anon" in fmt[0],
          f"{fmt or zones[:200]!r} — if this ever logs the full address, the "
          "jail decision above is worth revisiting")

    print("\n[3d] the installer asks for what it was not given")
    # The interactive path is the one an operator actually meets on a fresh
    # VPS, and until now nothing had executed a single line of it. ZTV_INTERACTIVE
    # is the seam that makes it drivable with a pipe — without it this would
    # be the part of the installer that only ever runs on somebody's real box
    # at the worst possible moment, which is bug class #14.
    def interactive(answers, *args, env=None):
        return subprocess.run(
            ["bash", INSTALL, "--dry-run", *args],
            input="".join(a + "\n" for a in answers),
            capture_output=True, text=True, timeout=300,
            env={**os.environ, "TERM": "dumb", "ZTV_INTERACTIVE": "always",
                 **(env or {})})

    # THE ONE THAT MATTERS MOST: no terminal must mean no questions. cloud-init
    # and CI run this with stdin closed, and a read() there either takes an
    # empty answer or blocks the boot forever. Both are worse than the error.
    r = subprocess.run(["bash", INSTALL, "--dry-run"], stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=120,
                       env={**os.environ, "TERM": "dumb"})
    out = r.stdout + r.stderr
    check("with no terminal it does not ask, it says which flag is missing",
          "--mode must be" in out and "not a terminal" in out,
          out[-400:] + "\n  a prompt here blocks a cloud-init boot forever")
    check("and it terminates rather than waiting", r.returncode != 0, r.returncode)

    r = subprocess.run(["bash", INSTALL, "--dry-run", "--non-interactive"],
                       input="node\n", capture_output=True, text=True, timeout=120,
                       env={**os.environ, "TERM": "dumb", "ZTV_INTERACTIVE": "always"})
    check("--non-interactive overrides the seam and refuses to ask",
          "--mode must be" in (r.stdout + r.stderr),
          (r.stdout + r.stderr)[-300:])

    # A whole node, entirely from answers, with every default taken.
    r = interactive(["node", "", "", "ztvp-abcdefghijklmnop", "", "", "", "y", "y", "y"])
    out = r.stdout + r.stderr
    check("a node can be configured entirely by answering questions",
          "about to install" in out and "region/role   zur / both" in out,
          out[-600:])
    check("and the port it recommends is the port it defaults to",
          "wireguard     udp 443" in out,
          "the help text says 443 is recommended; offering 51820 as the "
          "default is how an operator takes the default and gets the thing "
          "the text told them not to")
    check("the relay is offered by default, so nodes actually carry it",
          "DPI relay     udp 8443" in out, out[-400:])

    # Every validator must refuse and re-ask rather than accept.
    r = interactive(["banana", "node", "not-a-url", "https://cp.example.com",
                     "ZUR!!", "rey", "short", "ztvp-abcdefghijklmnop",
                     "both", "443", "443", "8443", "y", "y", "y"])
    out = r.stdout + r.stderr
    for needle, what in (
        ("must be: test, production or node", "a bad mode"),
        ("a URL, e.g.", "a bad control-plane URL"),
        ("a short lowercase code", "a bad region"),
        ("not a provisioning token", "a bad token"),
        ("that is the WireGuard port", "a relay port colliding with WireGuard"),
    ):
        check(f"it refuses and re-asks: {what}", needle in out, out[-500:])
    # ...and having refused them all, still reaches a correct plan.
    check("and still arrives at a valid plan afterwards",
          "region/role   rey / both" in out and "DPI relay     udp 8443" in out,
          out[-500:])

    # Production, with the wallet deferred — an install that works before the
    # operator has decided how to take money.
    r = interactive(["production", "vpn.example.com", "ops@example.com",
                     "later", "none", "y", "y", "y"])
    out = r.stdout + r.stderr
    check("production can be configured by answering questions",
          "domain        vpn.example.com" in out, out[-600:])
    check("and deferring the wallet says what that costs",
          "not configured — free trial only" in out, out[-400:])

    # Declining the confirmation must change nothing at all.
    r = interactive(["node", "", "", "ztvp-abcdefghijklmnop", "", "", "", "y", "y", "n"])
    out = r.stdout + r.stderr
    check("answering no to the summary stops without touching anything",
          "nothing was changed" in out and "Installing packages" not in out,
          out[-400:])

    # Backups. The database is the only record of what each customer paid
    # for, and the timer shipped installed-and-disabled because there was no
    # key to encrypt to and nothing ever asked for one.
    AGEPUB = "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj"
    r = interactive(["production", "vpn.example.com", "ops@example.com",
                     "later", AGEPUB, "none", "y", "y", "y"])
    out = r.stdout + r.stderr
    check("a backup key is asked for", "age public key" in out, out[-500:])
    check("and giving one turns nightly backups on",
          "nightly, encrypted to" in out and "would enable 0trust-backup.timer" in out,
          out[-600:])

    # Pasting the SECRET half must be refused, loudly. Whoever takes the
    # server must not be able to read the backups it made, and a private key
    # sitting in /etc is exactly that.
    r = interactive(["production", "vpn.example.com", "ops@example.com", "later",
                     "AGE-SECRET-KEY-1QQQQ", "skip", "none", "y", "y", "y"])
    out = r.stdout + r.stderr
    check("pasting the age PRIVATE key is refused and explained",
          "that is the PRIVATE key" in out, out[-500:])
    check("and skipping says plainly that nothing is backed up",
          "backups       OFF" in out, out[-500:])
    # The summary line is not the behaviour. What matters is that no key
    # means no ENABLED timer: a unit that fails every night looks like
    # backups exist, which is worse than none at all. The first version of
    # this check read only the summary and stayed green when the timer was
    # enabled regardless.
    check("and no key means the timer is NOT enabled",
          "would enable 0trust-backup.timer" not in out,
          out[-600:] + "\n  a nightly-failing unit is worse than off")
    check("with the reason said out loud in the log, not left as a silence",
          "backups are OFF" in out and "only record of what each customer" in out,
          out[-500:])

    # A flag already given must not be asked for again.
    r = interactive(["ztvp-abcdefghijklmnop", "", "", "", "y", "y", "y"],
                    "--mode", "node", "--control-url", "https://cp.example.com",
                    "--region", "buc")
    out = r.stdout + r.stderr
    check("values passed as flags are not asked for again",
          "What is this box" not in out and "Control plane URL" not in out
          and "region/role   buc / both" in out,
          out[-600:])

    print("\n[9] the box patches itself, and the token stays out of argv")
    # A mesh node exposes sshd and a WireGuard port to the whole internet and
    # is built to run untouched for months -- the RAM-only design means nobody
    # logs in. Nobody logging in and nobody patching are the same sentence
    # unless something applies updates on its own.
    src = open(INSTALL).read()
    for role, args in (("node", ("--mode", "node", "--control-url", "https://c.example",
                                 "--region", "zur", "--provision-token",
                                 "ztvp-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
                       ("control plane", ("--mode", "production", "--domain",
                                          "example.com", "--email", "a@example.com"))):
        rc, out = run_installer(*args)
        check(f"a {role} install enables unattended security upgrades",
              "unattended security upgrades" in out,
              out[-400:] + "\n  an unpatched box is the ordinary way a fleet gets owned")

    # Security origins only, and no surprise reboot. Upgrading everything on
    # its own means WireGuard or nftables behaviour can change overnight on a
    # box whose correctness rests on both; rebooting on its own drops every
    # tunnel the node was carrying.
    conf = src[src.index("51-0trust-unattended"):src.index("AUEOF")]
    check("only the security pockets are configured",
          "-security" in conf and "Origins-Pattern" in conf, conf[:200])
    check("and nothing reboots itself",
          'Automatic-Reboot "false"' in conf,
          "a node reboot is a rejoin, but it still drops live tunnels")
    check("unused kernels are removed so /boot cannot fill",
          'Remove-Unused-Kernel-Packages "true"' in conf,
          "a full /boot makes apt fail silently for everything else")
    # systemctl enable returning 0 says nothing about whether the config
    # parses -- the standard the rest of this installer is held to.
    # Matched as the CONDITIONAL, not as a bare substring: the first version
    # of this check looked for "unattended-upgrades --dry-run" anywhere, and
    # the note telling the operator what to run when it fails contains that
    # string too. Deleting the real verification left the check green,
    # reading back the help text about itself -- bug class #17, met while
    # writing the guard against it.
    check("the config is proven to parse, not just enabled",
          re.search(r"if\s+unattended-upgrades\s+--dry-run", src) is not None,
          "enabling a unit is not evidence it can do anything")

    # A token in argv is in the shell history afterwards and in `ps` for any
    # local user while the install runs.
    tokfile = os.path.join(TMP, "tok")
    open(tokfile, "w").write("ztvp-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n")
    rc, out = run_installer("--mode", "node", "--control-url", "https://c.example",
                  "--region", "zur", "--provision-token-file", tokfile)
    check("a node can take its token from a file", rc == 0, out[-400:])
    rc, out = run_installer("--mode", "node", "--control-url", "https://c.example",
                  "--region", "zur", "--provision-token-file",
                  os.path.join(TMP, "does-not-exist"))
    check("and an unreadable one is refused rather than ignored",
          rc != 0 and "cannot read" in out, out[-300:])
    env = {**os.environ, "TERM": "dumb",
           "ZTV_PROVISION_TOKEN": "ztvp-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}
    r = subprocess.run(["bash", INSTALL, "--dry-run", "--mode", "node",
                        "--control-url", "https://c.example", "--region", "zur"],
                       capture_output=True, text=True, timeout=180, env=env)
    check("cloud-init can pass it in the environment instead",
          r.returncode == 0, (r.stdout + r.stderr)[-400:])
    rc, out = run_installer("--mode", "node", "--control-url", "https://c.example",
                  "--region", "zur")
    check("and with no token from any source the install still refuses",
          rc != 0 and "provisioning token" in out, out[-300:])


    print("\n[12] the installer does not need iproute2 to tell you it needs it")
    # Found by running --mode test --dry-run on a minimal image. The script
    # exited 127 after writing the plan as far as the mesh step, with no error
    # and no summary, because:
    #
    #   PRIMARY_IF="$(ip -o -4 route show to default | awk ...)"
    #   PRIMARY_IF="${PRIMARY_IF:-eth0}"     <- never reached
    #
    # `ip` absent makes the pipeline exit 127, pipefail carries that out of
    # the command substitution, and `set -e` kills the installer one line
    # before the fallback written for exactly this case. preflight_host had
    # already fixed the same shape twice on its getent/ip pair, with a comment
    # naming it; this was the instance that got missed.
    inst = open(INSTALL).read()
    m = re.search(r'^PRIMARY_IF="\$\(ip .*$', inst, re.M)
    check("[12] the PRIMARY_IF probe cannot abort the install",
          m is not None and "|| true" in m.group(0),
          m.group(0) if m else "PRIMARY_IF assignment not found")

    # The tool the installer reads after this point is named, not assumed.
    # It is Essential on a stock Ubuntu image and absent from minimal bases.
    for label, pat in (("control plane", r"PACKAGES=\((?:[^)]*)\)"),
                       ("node", r"NODE_PACKAGES=\((?:[^)]*)\)")):
        mm = re.search(pat, inst, re.S)
        check(f"[12] iproute2 is in the {label} package list",
              mm is not None and "iproute2" in mm.group(0),
              (mm.group(0)[:160] if mm else "list not found"))

    # Behavioural, not just textual: hide `ip` and require the dry run to
    # finish. A symlink farm rather than trimming /usr/sbin from PATH —
    # merged-usr puts ip in /usr/bin, so the obvious version of this test
    # hides nothing and passes against the unfixed script.
    nobin = os.path.join(TMP, "nobin")
    os.makedirs(nobin, exist_ok=True)
    for d in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        if not os.path.isdir(d):
            continue
        for b in os.listdir(d):
            if b == "ip":
                continue
            dst = os.path.join(nobin, b)
            if not os.path.lexists(dst):
                try:
                    os.symlink(os.path.join(d, b), dst)
                except OSError:
                    pass
    check("[12] the probe environment really does hide ip",
          shutil.which("ip", path=nobin) is None, shutil.which("ip", path=nobin))

    rd = os.path.join(TMP, "render-noip")
    r = subprocess.run(["bash", INSTALL, "--dry-run", "--mode", "test",
                        "--non-interactive"],
                       capture_output=True, text=True, timeout=180,
                       env={"PATH": nobin, "TERM": "dumb", "ZTV_RENDER_TO": rd})
    noip_out = r.stdout + r.stderr
    check("[12] the dry run completes with no iproute2 at all",
          r.returncode == 0, f"rc={r.returncode}\n{noip_out[-500:]}")
    check("[12] and it reaches the end rather than stopping mid-plan",
          "What this box is NOT" in noip_out, noip_out[-300:])

    # The diagnosis has to name the real cause. Both failures land on the same
    # `ip link add` probe, and collapsing them sends an operator whose box is
    # missing a package off to buy a different VPS — on --mode node it is
    # fatal, so that is the whole install.
    check("[12] a missing package is reported as a missing package",
          "iproute2 is not installed" in noip_out
          and "apt-get install -y iproute2" in noip_out, noip_out[:600])
    check("[12] and is NOT misreported as a kernel limitation",
          "cannot create a WireGuard interface" not in noip_out,
          [l for l in noip_out.splitlines() if "WireGuard interface" in l])

    # The masquerade interface is a guess once `ip` is gone, and guessing
    # wrong is the silent failure this product already has an invariant
    # about: traffic enters the tunnel and dies while the node heartbeats on.
    check("[12] the guessed masquerade interface is stated out loud",
          "no default route found" in noip_out,
          [l for l in noip_out.splitlines() if "masquerade" in l][:3])

finally:
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
