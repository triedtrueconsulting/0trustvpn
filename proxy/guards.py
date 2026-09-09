"""
Safety rails for the visitor web proxy.

An open web proxy on the same domain as a VPN brand is an abuse magnet, and
the failure modes are not subtle: server-side request forgery into the host's
own network, use as a laundering hop for fraud and spam, and the domain and
egress IP ending up on blocklists that are slow to leave. Everything in this
module exists so the proxy is a *reader of public web pages* and cannot be
turned into a general-purpose relay.

The rules, and why each one is here:

  scheme        http/https only. No file://, gopher://, data: — those are how
                a fetcher gets talked into reading the local disk.
  method        GET and HEAD only. Nothing that writes, so the proxy cannot be
                used to post spam, submit forms, or drive an API.
  destination   Public unicast addresses only. Every resolved IP is checked,
                the check is repeated after each redirect, and the address
                that passed is the address we CONNECT to — see pinned_opener.
                Vetting a name and then handing the name to a fetcher that
                resolves it again is not vetting: the answer can change in
                between, which is the whole DNS-rebinding SSRF.
  ports         80 and 443. Blocks the proxy being used to port-scan.
  size / time   Capped, so one request cannot tie up the service.
  content type  Documents and images. Not archives or executables, which are
                what a malware distributor wants a clean domain for. Checked
                on EVERY response, not only successful ones: an origin that
                attaches its payload to a 404 is the obvious way round a
                check that only runs on 2xx, and for a while it worked.
  credentials   No cookies or auth headers are forwarded upstream, and no
                Set-Cookie is passed back to the visitor.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import urllib.request
from urllib.parse import urlsplit

ALLOWED_SCHEMES = ("http", "https")
ALLOWED_METHODS = ("GET", "HEAD")
ALLOWED_PORTS = (80, 443)

MAX_BODY_BYTES = 5 * 1024 * 1024      # 5 MB
FETCH_TIMEOUT = 12.0                  # seconds
MAX_REDIRECTS = 4

ALLOWED_CONTENT_PREFIXES = (
    "text/html", "text/plain", "text/css", "text/xml",
    "application/xhtml+xml", "application/xml", "application/rss+xml",
    "application/atom+xml", "application/json", "application/javascript",
    "text/javascript",
    "image/",
    "font/", "application/font-woff", "application/font-woff2",
)

# Never proxy these, whatever the content type says. Not a security control on
# its own — it's here so the service isn't trivially useful for the abuse that
# gets a domain blocklisted.
BLOCKED_HOST_SUFFIXES = tuple(
    h.strip().lower()
    for h in (
        # Populated by the operator via ZTV_PROXY_BLOCKLIST; see server.py.
    )
    if h.strip()
)


class Blocked(Exception):
    """Request refused by a guard. The message is safe to show a visitor."""


def _is_public(ip: ipaddress._BaseAddress) -> bool:
    """
    True only for globally routable unicast.

    ipaddress.is_global is close but not sufficient on its own, so the
    individual categories are spelled out — a miss here is an SSRF.
    """
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
        # Carrier-grade NAT and IPv6 unique-local, which is_private misses on
        # some Python versions.
        or (ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"))
        or (ip.version == 6 and ip in ipaddress.ip_network("fc00::/7"))
        # IPv4-mapped IPv6 (::ffff:127.0.0.1) — unwrap and re-check.
        or (ip.version == 6 and ip.ipv4_mapped is not None
            and not _is_public(ip.ipv4_mapped))
    )


def resolve_public(host: str, port: int) -> list[str]:
    """
    Resolve a hostname and return its addresses, or raise Blocked if ANY of
    them is non-public.

    Rejecting on any bad address rather than filtering to the good ones is
    deliberate: a host that answers with both a public and a loopback address
    is either misconfigured or attacking us, and there is no case where we
    want to proceed.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise Blocked(f"Could not resolve {host}") from e
    if not infos:
        raise Blocked(f"Could not resolve {host}")

    addrs = []
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            raise Blocked("Unparseable address from DNS")
        if not _is_public(ip):
            raise Blocked(
                "That address is on a private or reserved network. "
                "The proxy only fetches public sites."
            )
        addrs.append(addr)
    return addrs


def check_url(raw: str, blocklist: tuple[str, ...] = ()) -> str:
    """
    Validate a target URL end to end. Returns the normalized URL, or raises
    Blocked with a message safe to render.
    """
    if not raw or len(raw) > 2048:
        raise Blocked("Missing or over-long URL")

    parts = urlsplit(raw)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise Blocked("Only http and https URLs can be proxied")
    if not parts.hostname:
        raise Blocked("That URL has no hostname")

    # Credentials in the URL (user:pass@host) are a redirect-confusion trick
    # and have no legitimate use here.
    if parts.username or parts.password:
        raise Blocked("URLs with embedded credentials are not proxied")

    port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise Blocked("Only ports 80 and 443 can be proxied")

    host = parts.hostname.lower().rstrip(".")
    for suffix in blocklist:
        if host == suffix or host.endswith("." + suffix):
            raise Blocked("That site is not available through the proxy")

    # Raises if the host resolves anywhere non-public.
    resolve_public(host, port)
    return raw


# ---------------------------------------------------------------------------
# Connection pinning
# ---------------------------------------------------------------------------
#
# resolve_public() vetted the addresses and then threw them away: the caller
# handed the URL to urllib, which resolved the hostname AGAIN. Between those
# two lookups the answer can change, and an attacker who controls DNS for
# their own domain only has to serve a short TTL that alternates — a public
# address for our check, 169.254.169.254 for the fetch. That is the textbook
# SSRF bypass, and on a cloud VPS the second address is the metadata service.
#
# This module's own summary already said a name that resolved publicly once
# can resolve to loopback the next time; it applied that to redirects and not
# to the single request in front of it.
#
# So the address we vetted is the address we connect to. The hostname is kept
# for the Host header and, on TLS, for server_hostname — so certificate
# validation is still against the NAME, and pinning cannot be used to talk to
# one host while trusting another's certificate.


class _PinnedHTTPConnection(http.client.HTTPConnection):
    pinned_ip = None

    def connect(self):
        self.sock = socket.create_connection(
            (self.pinned_ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    pinned_ip = None

    def connect(self):
        sock = socket.create_connection(
            (self.pinned_ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            sock = self.sock
        # server_hostname is the name, never the pinned address.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def pinned_opener(ip: str, *extra_handlers) -> urllib.request.OpenerDirector:
    """An opener whose connections go to `ip` whatever DNS says next."""
    http_cls = type("PinnedHTTP", (_PinnedHTTPConnection,), {"pinned_ip": ip})
    https_cls = type("PinnedHTTPS", (_PinnedHTTPSConnection,), {"pinned_ip": ip})

    class _H(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(http_cls, req)

    class _HS(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(https_cls, req, context=self._context)

    return urllib.request.build_opener(_H(), _HS(), *extra_handlers)


def vet(raw: str, blocklist: tuple[str, ...] = ()) -> tuple[str, list[str]]:
    """check_url, but handing back the addresses it approved.

    Callers that then fetch the URL must connect to one of these rather than
    resolving the name again — see pinned_opener above.
    """
    url = check_url(raw, blocklist)
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    return url, resolve_public(parts.hostname.lower().rstrip("."), port)


def content_type_allowed(content_type: str) -> bool:
    ct = (content_type or "").split(";")[0].strip().lower()
    if not ct:
        return True          # servers that omit it; the size cap still applies
    return any(ct.startswith(p) for p in ALLOWED_CONTENT_PREFIXES)
