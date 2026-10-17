#!/usr/bin/env python3
"""
Proxy guards, with nothing patched.

test_proxy has to carve out the loopback origin to exercise the fetch path;
this module runs the guards exactly as production does, so the blocking
behaviour is proven somewhere the carve-out cannot hide a regression.
"""
import ipaddress, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H
sys.path.insert(0, os.path.join(H.REPO, "proxy"))
from guards import Blocked, _is_public, check_url, content_type_allowed

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"  <- {d}"))

def refuses(url, label=None, blocklist=()):
    label = label or url
    try:
        check_url(url, blocklist); check(f"refuses {label}", False, "was allowed")
    except Blocked:
        check(f"refuses {label}", True)

def allows(url):
    try:
        check_url(url); check(f"allows {url}", True)
    except Blocked as e:
        check(f"allows {url}", False, str(e))

print("[ssrf] loopback, private, metadata, CGNAT, v4-mapped v6")
for u in ("http://127.0.0.1/", "http://localhost/", "http://[::1]/",
          "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/",
          "http://192.168.1.1/", "http://172.16.0.1/", "http://100.64.0.1/",
          "http://0.0.0.0/", "http://[fc00::1]/", "http://[::ffff:127.0.0.1]/"):
    refuses(u)

print("\n[scheme, port, credentials, length]")
refuses("file:///etc/passwd", "file scheme")
refuses("gopher://x/", "gopher scheme")
refuses("ftp://example.com/", "ftp scheme")
refuses("http://example.com:22/", "port 22")
refuses("http://example.com:6379/", "port 6379")
refuses("http://user:pw@example.com/", "embedded credentials")
refuses("", "empty url")
refuses("http://example.com/" + "a" * 3000, "over-long url")

print("\n[blocklist]")
refuses("https://bad.example/", "blocklisted host", ("bad.example",))
refuses("https://deep.sub.bad.example/", "blocklisted subdomain", ("bad.example",))

print("\n[public sites still work]")
# A literal address first, because it needs no resolver. check_url has to
# resolve a hostname to decide whether its address is public, so the two
# cases below are the only assertions in this module that depend on DNS --
# and they FAILED the whole module on an air-gapped runner, which is a test
# that protects nothing in exactly the environment a release is cut in.
# This one proves "a public unicast destination is allowed" with no network
# at all.
allows("https://8.8.8.8/")
allows("http://1.1.1.1:80/path?q=1")

# The hostname path as well, when a resolver exists. Reported as skipped
# rather than passed when it does not: a name that cannot resolve says
# nothing either way about whether the guard would have allowed it.
import socket as _socket
try:
    _socket.getaddrinfo("example.com", None)
    _HAVE_DNS = True
except OSError:
    _HAVE_DNS = False

if _HAVE_DNS:
    allows("https://example.com/")
    allows("http://example.com/path?q=1")
else:
    print("  SKIP  allows https://example.com/  <- no resolver on this host")
    print("  SKIP  allows http://example.com/path?q=1  <- no resolver on this host")

print("\n[_is_public]")
for a, want in (("8.8.8.8", True), ("1.1.1.1", True), ("2606:4700::1111", True),
                ("127.0.0.1", False), ("169.254.169.254", False), ("::1", False),
                ("100.64.0.1", False), ("fc00::1", False), ("224.0.0.1", False),
                ("255.255.255.255", False)):
    check(f"_is_public({a}) == {want}", _is_public(ipaddress.ip_address(a)) == want)

print("\n[content types]")
for ct, want in (("text/html; charset=utf-8", True), ("image/png", True),
                 ("text/css", True), ("application/zip", False),
                 ("application/x-msdownload", False), ("video/mp4", False),
                 ("application/octet-stream", False), ("", True)):
    check(f"content_type_allowed({ct!r}) == {want}",
          content_type_allowed(ct) == want)

print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL: print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
