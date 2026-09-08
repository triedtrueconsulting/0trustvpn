#!/usr/bin/env python3
"""
0trust mesh node syncer
========================

Runs on every WireGuard mesh node. Behavior depends on the node's role:

  role = "exit" or "both":
      Poll /api/v1/wg/peers every 30s and reconcile the wg0 peer list with
      `wg syncconf`. These are the nodes that actually terminate client
      WireGuard tunnels and NAT traffic out to the internet.

  role = "entry" or "both":
      Poll /api/v1/wg/forwards?node_id=<id> every 30s and reconcile nftables
      DNAT rules so the right UDP port forwards to the right exit. These
      nodes never see plaintext — they're glorified UDP proxies.

Setting role=both means the same node does both jobs. For real zero-trust
(entry != exit) you want dedicated nodes with role=entry on one box and
role=exit on another, ideally in different jurisdictions.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import os
import random
import base64
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

# --- Config from env ---
CONTROL_URL   = os.environ["CONTROL_URL"]
NODE_PSK      = os.environ["NODE_API_PSK"]
NODE_ID       = os.environ["NODE_ID"]
NODE_ROLE     = os.environ.get("NODE_ROLE", "both")
WG_IFACE      = os.environ.get("WG_IFACE", "wg0")
WG_PRIV       = Path(os.environ.get("WG_PRIVKEY", "/etc/wireguard/wg0.key"))
WG_PORT       = int(os.environ.get("WG_PORT", "51820"))
MESH_GATEWAY  = os.environ.get("MESH_GATEWAY", "10.64.0.1/10")
MESH_NETWORK  = os.environ.get("MESH_NETWORK", "10.64.0.0/10")
MESH_NETWORK6 = os.environ.get("MESH_NETWORK6", "fd0e:5f7a:c21b::/48")
# The v6 side of MESH_GATEWAY, same derivation the control plane uses: the
# gateway's v4 address embedded in the low 32 bits of the ULA prefix.
MESH_GATEWAY6 = os.environ.get("MESH_GATEWAY6", "")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "30"))
# How much to vary that, as a fraction. A node checks in over its own outbound
# HTTPS, so the traffic itself gives nothing away — but a request to the same
# host every 30.00 seconds, forever, is a shape. Anyone watching the node's
# uplink (its hosting provider, most obviously) can pick a metronome out of
# netflow records without reading a single byte, and once picked out it
# identifies the box as part of something coordinated. Jitter costs nothing
# and removes the pattern. Set ZTV_POLL_JITTER=0 for a fixed cadence.
POLL_JITTER = float(os.environ.get("ZTV_POLL_JITTER", "0.35"))

# Route the control channel through a SOCKS5 proxy — in practice a local Tor
# daemon, with CONTROL_URL pointing at the control plane's .onion.
#
# What this is for. Jitter above hides the CADENCE of the check-in; it does
# nothing about the DESTINATION. Every node opens a regular connection to the
# same control-plane address, so anyone who can watch two nodes' uplinks — a
# hosting provider with more than one of them, most obviously — can correlate
# the boxes into one system without decrypting a byte. Sending the check-in
# through Tor removes the shared destination: each node talks to its own guard
# relay and the real endpoint is inside the circuit.
#
# Empty (the default) means direct, exactly as before.
CONTROL_PROXY = os.environ.get("ZTV_CONTROL_PROXY", "").strip()

# NOT "0trust_forward": nftables identifiers cannot start with a digit, and
# nft parses the leading 0 as a number — "syntax error, unexpected number".
# Quoting does not help; the parser rejects a quoted string there too. The
# whole ruleset failed to load, which meant multi-hop DNAT never worked on
# any node. Renaming is the only fix.
# One table per node, because a single-VPS test deployment runs three node
# identities side by side. reconcile_forwards() replaces its table wholesale,
# so three meshd processes sharing one name would each wipe the other two's
# DNAT rules on every poll and multi-hop would work for whichever polled last.
# The default is unchanged, so a normal one-node box is unaffected.
NFT_TABLE = os.environ.get("ZTV_NFT_TABLE", "ztv_forward")

# Tables that predate the rename. Removed on first sync so a node upgrading
# in place does not keep a stale table around forever.
LEGACY_NFT_TABLES = ("0trust_forward",)

log = logging.getLogger("meshd")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ----------------------------------------------------------------------------
# HTTP  (optionally through SOCKS5, for the onion control channel)
# ----------------------------------------------------------------------------

def _socks5_connect(proxy: str, host: str, port: int, timeout: float) -> socket.socket:
    """
    Open a TCP connection to host:port through a SOCKS5 proxy.

    The hostname is sent to the proxy as a DOMAINNAME request rather than
    resolved here — "socks5h" semantics. That is not an optimisation: a .onion
    has no DNS entry at all, so resolving locally would fail, and for a
    clearnet host resolving locally would leak the destination to the node's
    resolver, which is most of what routing through the proxy was meant to
    avoid.

    Deliberately hand-rolled against RFC 1928 rather than adding PySocks: a
    mesh node's dependency list is the attack surface of every box we run, and
    this is forty lines of a fully specified protocol.
    """
    phost, _, pport = proxy.rpartition(":")
    if not phost:
        raise OSError(f"ZTV_CONTROL_PROXY must be host:port, got {proxy!r}")
    s = socket.create_connection((phost, int(pport)), timeout=timeout)
    try:
        # Greeting: version 5, one method, "no authentication".
        s.sendall(b"\x05\x01\x00")
        greet = _recv_exactly(s, 2)
        if greet[0] != 0x05 or greet[1] != 0x00:
            raise OSError("SOCKS5 proxy refused the no-auth method")

        name = host.encode("idna")
        if len(name) > 255:
            raise OSError("hostname too long for SOCKS5")
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name
                  + port.to_bytes(2, "big"))

        reply = _recv_exactly(s, 4)
        if reply[1] != 0x00:
            raise OSError(f"SOCKS5 CONNECT failed (reply code {reply[1]})")
        # Consume the bound address so the socket is positioned at the payload.
        atyp = reply[3]
        if atyp == 0x01:
            _recv_exactly(s, 4)
        elif atyp == 0x04:
            _recv_exactly(s, 16)
        elif atyp == 0x03:
            _recv_exactly(s, _recv_exactly(s, 1)[0])
        else:
            raise OSError(f"SOCKS5 proxy returned an unknown address type {atyp}")
        _recv_exactly(s, 2)
        return s
    except Exception:
        s.close()
        raise


def _recv_exactly(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise OSError("SOCKS5 proxy closed the connection early")
        buf += chunk
    return buf


class _SocksHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = _socks5_connect(CONTROL_PROXY, self.host, self.port,
                                    self.timeout)


class _SocksHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        sock = _socks5_connect(CONTROL_PROXY, self.host, self.port,
                               self.timeout)
        # server_hostname keeps certificate validation against the real host,
        # not the proxy. Routing through Tor must not weaken TLS.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _SocksHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_SocksHTTPConnection, req)


class _SocksHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_SocksHTTPSConnection, req)


def _build_opener() -> urllib.request.OpenerDirector:
    """
    The one opener every control-plane call uses.

    When ZTV_CONTROL_PROXY is set it is the ONLY transport. There is
    deliberately no fall back to a direct connection if the proxy is down: a
    silent downgrade would put the shared-destination signal back on the wire
    at exactly the moment someone was interfering with Tor, and nothing would
    report it. The node keeps serving the tunnels it already has, stops
    getting updates, and the control plane marks it stale — which is visible.
    The upstream DNS resolver on this same box fails closed for the same
    reason.
    """
    if not CONTROL_PROXY:
        return urllib.request.build_opener()
    return urllib.request.build_opener(_SocksHTTPHandler, _SocksHTTPSHandler)


_OPENER = _build_opener()


def _get(path: str) -> dict:
    req = urllib.request.Request(
        f"{CONTROL_URL}{path}",
        headers={"X-Node-Psk": NODE_PSK},
    )
    with _OPENER.open(req, timeout=10) as r:
        return json.loads(r.read())


# ----------------------------------------------------------------------------
# EXIT NODE: sync WireGuard peer list
# ----------------------------------------------------------------------------

def fetch_peers() -> list[dict]:
    # node_id is required: the manifest is scoped to the calling node, and a
    # node authenticating with the shared PSK cannot be identified from the
    # credential alone.
    return _get(f"/api/v1/wg/peers?node_id={NODE_ID}")["peers"]


def _is_wg_key(v: str) -> bool:
    """A base64-encoded 32-byte X25519 point — the shape wg accepts."""
    v = (v or "").strip()
    if len(v) != 44 or "\n" in v or "\r" in v:
        return False
    try:
        return len(base64.b64decode(v, validate=True)) == 32
    except Exception:
        return False


def build_wg_config(peers: list[dict]) -> str:
    priv = WG_PRIV.read_text().strip()
    lines = ["[Interface]", f"PrivateKey = {priv}", f"ListenPort = {WG_PORT}", ""]
    for p in peers:
        # Defence in depth. The control plane validates the key at ingest now,
        # so a malformed one should never arrive — but `wg syncconf` is atomic
        # and run with check=True, so a single bad [Peer] block would fail the
        # sync for EVERY customer on this node. Skip the offender and carry the
        # rest rather than dropping everyone. AllowedIPs is not interpolated
        # blindly either: reconcile_routes only installs prefixes _in_mesh()
        # accepts, so a hostile CIDR here cannot become a real route.
        key = str(p.get("public_key") or "")
        if not _is_wg_key(key):
            log.warning("skipping peer with an invalid public key: %r", key[:16])
            continue
        lines += [
            "[Peer]",
            f"PublicKey = {key}",
            f"AllowedIPs = {p['allowed_ips']}",
            "",
        ]
    return "\n".join(lines)


def reconcile_peers(peers: list[dict]) -> None:
    config = build_wg_config(peers)
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write(config)
        tmp_path = f.name
    try:
        subprocess.run(
            ["wg", "syncconf", WG_IFACE, tmp_path],
            check=True, capture_output=True,
        )
        log.info("synced %d peers to %s", len(peers), WG_IFACE)
    finally:
        os.unlink(tmp_path)


# Routes for the peers we carry.
#
# `wg syncconf` sets AllowedIPs, which decides which peer a packet belongs to
# once it is already on this interface — it does not tell the kernel to send
# anything here in the first place. A normal node gets away with that because
# `ip addr add 10.64.0.1/10` leaves a connected route covering the whole mesh.
# Put three interfaces on one box, as the single-VPS test deployment does, and
# that route exists three times over: return traffic for a client peered on
# wg2 can be handed to wg0, which has no such peer, and the packet dies. A /32
# per peer is more specific than any /10, so the right interface always wins.
#
# Only routes we created are ever removed: they carry proto static, while the
# kernel's connected route carries proto kernel.
ROUTE_PROTO = "static"


def _derive_gateway6() -> str:
    """v6 gateway address, derived from the v4 one unless explicitly set."""
    if MESH_GATEWAY6:
        return MESH_GATEWAY6
    try:
        v4 = ipaddress.IPv4Address(MESH_GATEWAY.split("/")[0])
        net6 = ipaddress.ip_network(MESH_NETWORK6)
        return str(ipaddress.IPv6Address(int(net6.network_address) + int(v4)))
    except ValueError:
        return ""


def _in_mesh(cidr: str) -> bool:
    """Is this prefix one of ours, in either family?"""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    # subnet_of raises TypeError across families, so pick the right mesh
    # network first. Peers now carry a v6 AllowedIP as well as a v4 one, and
    # comparing those against the v4 network would have thrown rather than
    # returned False — taking the whole peer sync down with it.
    mesh = MESH_NETWORK6 if net.version == 6 else MESH_NETWORK
    try:
        return net.subnet_of(ipaddress.ip_network(mesh))
    except (TypeError, ValueError):
        return False


def _ip_cmd(cidr: str) -> list[str]:
    """`ip` or `ip -6`, whichever this prefix needs."""
    return ["ip", "-6"] if ":" in cidr else ["ip"]


def _managed_routes() -> set[str]:
    """Mesh routes on our interface that this daemon put there, both families."""
    found = set()
    for family, hostlen in (("-4", "/32"), ("-6", "/128")):
        r = subprocess.run(["ip", family, "-j", "route", "show", "dev",
                            WG_IFACE, "proto", ROUTE_PROTO],
                           capture_output=True, text=True)
        if r.returncode != 0:
            continue
        try:
            rows = json.loads(r.stdout or "[]")
        except json.JSONDecodeError:
            continue
        for row in rows:
            dst = row.get("dst") or ""
            if not dst or dst == "default":
                continue
            if "/" not in dst:
                dst += hostlen
            if _in_mesh(dst):
                found.add(dst)
    return found


def reconcile_routes(peers: list[dict]) -> None:
    """Make the kernel's routes match the peers we just synced."""
    want = set()
    for p in peers:
        for cidr in str(p.get("allowed_ips") or "").split(","):
            cidr = cidr.strip()
            if not cidr:
                continue
            if "/" not in cidr:
                cidr += "/128" if ":" in cidr else "/32"
            if _in_mesh(cidr):
                want.add(cidr)
    try:
        have = _managed_routes()
    except FileNotFoundError:
        log.warning("no `ip` binary — cannot manage peer routes")
        return
    for dst in sorted(want - have):
        r = subprocess.run(_ip_cmd(dst) + ["route", "replace", dst, "dev",
                                           WG_IFACE, "proto", ROUTE_PROTO],
                           capture_output=True, text=True)
        if r.returncode != 0:
            log.warning("could not add route %s dev %s: %s",
                        dst, WG_IFACE, r.stderr.strip())
    for dst in sorted(have - want):
        subprocess.run(_ip_cmd(dst) + ["route", "del", dst, "dev", WG_IFACE,
                                       "proto", ROUTE_PROTO],
                       capture_output=True)
    if want - have or have - want:
        log.info("routes on %s: +%d -%d", WG_IFACE,
                 len(want - have), len(have - want))


def has_ipv6_egress() -> bool:
    """
    Can this node actually reach the IPv6 internet?

    Reported to the control plane on every heartbeat rather than configured
    centrally, because it is a property of the VPS the operator rented and it
    can change under them — a provider enabling or withdrawing v6 should not
    require a database edit. Customers are only handed a v6 address when their
    exit node says yes here; everywhere else v6 stays blackholed, which is
    what it has always been.

    A default route plus a global address is the honest test. Either alone is
    not: an address with no route goes nowhere, and a route with no global
    address has nothing to send from.
    """
    try:
        routes = subprocess.run(["ip", "-6", "route", "show", "default"],
                                capture_output=True, text=True, timeout=5)
        if routes.returncode != 0 or not routes.stdout.strip():
            return False
        addrs = subprocess.run(["ip", "-6", "-j", "addr", "show", "scope", "global"],
                               capture_output=True, text=True, timeout=5)
        if addrs.returncode != 0:
            return False
        for link in json.loads(addrs.stdout or "[]"):
            if link.get("ifname") == WG_IFACE:
                continue          # our own tunnel address does not count
            for info in link.get("addr_info", []):
                if info.get("family") == "inet6" and info.get("scope") == "global":
                    return True
    except Exception as e:
        log.debug("ipv6 probe failed: %s", e)
    return False


def bootstrap_interface() -> None:
    result = subprocess.run(
        ["ip", "link", "show", WG_IFACE], capture_output=True,
    )
    if result.returncode != 0:
        log.info("creating interface %s", WG_IFACE)
        subprocess.run(["ip", "link", "add", WG_IFACE, "type", "wireguard"], check=True)
        subprocess.run(["ip", "addr", "add", MESH_GATEWAY, "dev", WG_IFACE], check=True)
        subprocess.run(
            ["wg", "set", WG_IFACE,
             "private-key", str(WG_PRIV),
             "listen-port", str(WG_PORT)],
            check=True,
        )
        subprocess.run(["ip", "link", "set", "up", "dev", WG_IFACE], check=True)

    # The v6 gateway address, added whether or not this node has v6 egress.
    # Clients are only *told* about v6 when egress works, but the address has
    # to exist regardless: without a source address on the interface the node
    # cannot even answer a customer's DNS query over v6, and dnsmasq has
    # nothing to bind.
    gw6 = _derive_gateway6()
    if gw6:
        subprocess.run(["ip", "-6", "addr", "replace", f"{gw6}/128",
                        "dev", WG_IFACE], capture_output=True)


# ----------------------------------------------------------------------------
# ENTRY NODE: sync nftables DNAT rules
# ----------------------------------------------------------------------------

def fetch_forwards() -> list[dict]:
    return _get(f"/api/v1/wg/forwards?node_id={NODE_ID}")["forwards"]


def _dnat_family(endpoint: str) -> str:
    """
    "ip" or "ip6" for a host:port endpoint.

    An inet table serves both families, so nft refuses a bare `dnat to` there:
    "specify 'dnat ip' or 'dnat ip6' in inet table to disambiguate". Without
    the qualifier the ruleset does not load at all.
    """
    host = endpoint.rsplit(":", 1)[0]
    return "ip6" if host.startswith("[") or host.count(":") >= 2 else "ip"


def build_nft_ruleset(forwards: list[dict]) -> str:
    """
    Build a complete nftables ruleset. Atomic replacement via nft -f.
    """
    lines = [
        f"table inet {NFT_TABLE} {{",
        "  chain prerouting {",
        "    type nat hook prerouting priority dstnat;",
    ]
    for f in forwards:
        fam = _dnat_family(f["exit_endpoint"])
        lines.append(
            f"    udp dport {f['entry_port']} dnat {fam} to {f['exit_endpoint']}")
    lines += [
        "  }",
        "  chain postrouting {",
        "    type nat hook postrouting priority srcnat;",
        # Masquerade exactly the connections prerouting just DNAT'd.
        #
        # The old rule matched `udp sport 52000-59999`, but by postrouting the
        # source port is the CLIENT's ephemeral port — the 52000-59999 value
        # was the destination port, and DNAT already rewrote it. So the rule
        # almost never matched, and an unmasqueraded packet reaches the exit
        # carrying the client's real source address: the exit replies straight
        # to the client instead of back through the entry (breaking the
        # tunnel), and it learns the client IP the multi-hop design exists to
        # hide from it. `ct status dnat` selects precisely the forwarded
        # flows, whatever ports they landed on.
        "    ct status dnat masquerade",
        "  }",
        "}",
    ]
    return "\n".join(lines)


def reconcile_forwards(forwards: list[dict]) -> None:
    """Atomically replace the DNAT table."""
    new_table = build_nft_ruleset(forwards)
    # If the table doesn't exist yet, plain load. If it does, delete+load.
    check = subprocess.run(
        ["nft", "list", "table", "inet", NFT_TABLE],
        capture_output=True,
    )
    script_parts = []
    if check.returncode == 0:
        script_parts.append(f"delete table inet {NFT_TABLE}")
    # A node upgrading in place may still have a table under the old name.
    # It never loaded successfully, but clear it if it somehow exists.
    for legacy in LEGACY_NFT_TABLES:
        if subprocess.run(["nft", "list", "table", "inet", legacy],
                          capture_output=True).returncode == 0:
            script_parts.append(f"delete table inet {legacy}")
    script_parts.append(new_table)
    script = "\n".join(script_parts)

    with tempfile.NamedTemporaryFile("w", suffix=".nft", delete=False) as f:
        f.write(script)
        tmp = f.name
    try:
        subprocess.run(["nft", "-f", tmp], check=True, capture_output=True)
        log.info("synced %d forwards on %s", len(forwards), NODE_ID)
    finally:
        os.unlink(tmp)


# ----------------------------------------------------------------------------
# MAIN LOOP
# ----------------------------------------------------------------------------

def do_exit_sync(state: dict) -> None:
    peers = fetch_peers()
    h = hash(tuple(sorted((p["public_key"], p["allowed_ips"]) for p in peers)))
    if h != state.get("peers_hash"):
        reconcile_peers(peers)
        reconcile_routes(peers)
        state["peers_hash"] = h


def do_entry_sync(state: dict) -> None:
    forwards = fetch_forwards()
    h = hash(tuple(sorted((f["entry_port"], f["exit_endpoint"]) for f in forwards)))
    if h != state.get("forwards_hash"):
        reconcile_forwards(forwards)
        state["forwards_hash"] = h


def heartbeat() -> None:
    """
    Tell the control plane we're alive. Best-effort; failures don't block sync.

    Always send node_id. An ephemeral node's per-node PSK identifies it on its
    own, but a static node authenticating with the shared NODE_API_PSK has no
    psk_hash row to match, so without the id the control plane cannot tell
    which node just checked in.
    """
    body = json.dumps({"node_id": NODE_ID, "ipv6": has_ipv6_egress()}).encode()
    req = urllib.request.Request(
        f"{CONTROL_URL}/api/v1/node/heartbeat",
        data=body,
        headers={"X-Node-Psk": NODE_PSK, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        _OPENER.open(req, timeout=5).read()
    except Exception as e:
        # Warn, not debug: a heartbeat that never lands means the sweeper
        # eventually marks this node dead and traffic stops being routed here.
        log.warning("heartbeat failed: %s", e)


def next_interval() -> float:
    """
    The next poll delay, jittered around POLL_INTERVAL.

    Never below a second — a jitter fraction someone sets to 1.0 should slow
    the node down, not turn it into a busy loop against the control plane.
    """
    if POLL_JITTER <= 0:
        return float(POLL_INTERVAL)
    spread = POLL_INTERVAL * min(POLL_JITTER, 0.9)
    return max(1.0, POLL_INTERVAL + random.uniform(-spread, spread))


def main():
    role = NODE_ROLE.lower()
    if role not in ("entry", "exit", "both"):
        log.error("Invalid NODE_ROLE=%r, must be entry|exit|both", NODE_ROLE)
        return

    if role in ("exit", "both"):
        bootstrap_interface()

    # Name the transport. An operator who thinks the control channel is going
    # over Tor and is wrong has the exact exposure this setting exists to
    # remove, and nothing else on the box would tell them.
    if CONTROL_PROXY:
        log.info("starting meshd: node=%s role=%s control=via SOCKS5 %s (no direct fallback)",
                 NODE_ID, role, CONTROL_PROXY)
    else:
        log.info("starting meshd: node=%s role=%s control=direct", NODE_ID, role)
    state: dict = {}

    while True:
        try:
            heartbeat()
            if role in ("exit", "both"):
                do_exit_sync(state)
            if role in ("entry", "both"):
                do_entry_sync(state)
        except Exception as e:
            log.error("sync failed: %s", e)
        time.sleep(next_interval())


if __name__ == "__main__":
    main()
