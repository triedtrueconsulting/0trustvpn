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
import os, re, shutil, subprocess, sys, tempfile
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
TMP = tempfile.mkdtemp(prefix="0trust-install-")
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
    site = (site.replace("/etc/nginx/snippets/", f"{TMP}/snippets/")
                .replace("/etc/letsencrypt/live/example.com", TMP)
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
    check("unknown mode rejected", rc != 0 and "must be test or production" in out, out[-200:])
    rc, out = run_installer("--mode", "production")
    check("production without --domain rejected", rc != 0 and "--domain" in out, out[-200:])
    rc, out = run_installer("--mode", "production", "--domain", "x.com")
    check("production without --email rejected", rc != 0 and "--email" in out, out[-200:])
    for bad in ("http://x.com", "x.com/path", "nodot", "has space.com"):
        rc, out = run_installer("--mode", "production", "--domain", bad, "--email", "a@b.c")
        check(f"malformed domain rejected: {bad!r}", rc != 0, out[-160:])

    print("\n[2] dry runs are clean and change nothing")
    rc, out = run_installer("--mode", "test")
    check("test dry run exits 0", rc == 0, out[-400:])
    check("test mode warns about the missing TLS", "No TLS" in out, out[-500:])
    rc, out = run_installer("--mode", "production", "--domain", "example.com",
                            "--email", "a@b.c")
    check("production dry run exits 0", rc == 0, out[-400:])
    check("dry run wrote nothing to /etc", not os.path.exists("/etc/0trust/api.env"))

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
    print("\n[7] every systemd unit's dependencies are actually installed")
    # A unit that references a script or env file nothing places is a timer
    # that fails nightly on a real box and never in a test. Both the backup
    # script and its env file went missing this way.
    import glob as _glob
    installer = open(INSTALL).read()
    units = sorted(_glob.glob(os.path.join(H.REPO, "systemd", "*.service")))
    check("systemd units found", bool(units))
    for unit_path in units:
        unit = os.path.basename(unit_path)
        text = open(unit_path).read()

        # Every EnvironmentFile needs a committed .example next to it.
        for ef in re.findall(r"EnvironmentFile=-?(\S+)", text):
            name = os.path.basename(ef).replace(".env", ".env.example")
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

    # Units the installer knows about should exist in the repo.
    for unit in re.findall(r"(0trust-[a-z]+\.(?:service|timer))", installer):
        check(f"installer references a real unit: {unit}",
              os.path.exists(os.path.join(H.REPO, "systemd", unit)),
              f"systemd/{unit} missing")

finally:
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
