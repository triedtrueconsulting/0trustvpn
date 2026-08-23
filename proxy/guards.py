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
                and the check is repeated after each redirect, because a
                hostname that resolved publicly the first time can resolve to
                127.0.0.1 the second (DNS rebinding).
  ports         80 and 443. Blocks the proxy being used to port-scan.
  size / time   Capped, so one request cannot tie up the service.
  content type  Documents and images. Not archives or executables, which are
                what a malware distributor wants a clean domain for.
  credentials   No cookies or auth headers are forwarded upstream, and no
                Set-Cookie is passed back to the visitor.
"""

from __future__ import annotations

import ipaddress
import socket
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


def content_type_allowed(content_type: str) -> bool:
    ct = (content_type or "").split(";")[0].strip().lower()
    if not ct:
        return True          # servers that omit it; the size cap still applies
    return any(ct.startswith(p) for p in ALLOWED_CONTENT_PREFIXES)
