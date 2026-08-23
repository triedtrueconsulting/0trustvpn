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

import ipaddress
import json
import logging
import os
import subprocess
import tempfile
import time
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
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "30"))

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
# HTTP
# ----------------------------------------------------------------------------

def _get(path: str) -> dict:
    req = urllib.request.Request(
        f"{CONTROL_URL}{path}",
        headers={"X-Node-Psk": NODE_PSK},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


# ----------------------------------------------------------------------------
# EXIT NODE: sync WireGuard peer list
# ----------------------------------------------------------------------------

def fetch_peers() -> list[dict]:
    # node_id is required: the manifest is scoped to the calling node, and a
    # node authenticating with the shared PSK cannot be identified from the
    # credential alone.
    return _get(f"/api/v1/wg/peers?node_id={NODE_ID}")["peers"]


def build_wg_config(peers: list[dict]) -> str:
    priv = WG_PRIV.read_text().strip()
    lines = ["[Interface]", f"PrivateKey = {priv}", f"ListenPort = {WG_PORT}", ""]
    for p in peers:
        lines += [
            "[Peer]",
            f"PublicKey = {p['public_key']}",
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


def _in_mesh(cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return net.subnet_of(ipaddress.ip_network(MESH_NETWORK))
    except ValueError:
        return False


def _managed_routes() -> set[str]:
    """Mesh routes on our interface that this daemon put there."""
    r = subprocess.run(["ip", "-j", "route", "show", "dev", WG_IFACE,
                        "proto", ROUTE_PROTO], capture_output=True, text=True)
    if r.returncode != 0:
        return set()
    try:
        rows = json.loads(r.stdout or "[]")
    except json.JSONDecodeError:
        return set()
    found = set()
    for row in rows:
        dst = row.get("dst") or ""
        if not dst or dst == "default":
            continue
        if "/" not in dst:
            dst += "/32"
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
                cidr += "/32"
            if _in_mesh(cidr):
                want.add(cidr)
    try:
        have = _managed_routes()
    except FileNotFoundError:
        log.warning("no `ip` binary — cannot manage peer routes")
        return
    for dst in sorted(want - have):
        r = subprocess.run(["ip", "route", "replace", dst, "dev", WG_IFACE,
                            "proto", ROUTE_PROTO], capture_output=True, text=True)
        if r.returncode != 0:
            log.warning("could not add route %s dev %s: %s",
                        dst, WG_IFACE, r.stderr.strip())
    for dst in sorted(have - want):
        subprocess.run(["ip", "route", "del", dst, "dev", WG_IFACE,
                        "proto", ROUTE_PROTO], capture_output=True)
    if want - have or have - want:
        log.info("routes on %s: +%d -%d", WG_IFACE,
                 len(want - have), len(have - want))


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
    body = json.dumps({"node_id": NODE_ID}).encode()
    req = urllib.request.Request(
        f"{CONTROL_URL}/api/v1/node/heartbeat",
        data=body,
        headers={"X-Node-Psk": NODE_PSK, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=5).read()
    except Exception as e:
        # Warn, not debug: a heartbeat that never lands means the sweeper
        # eventually marks this node dead and traffic stops being routed here.
        log.warning("heartbeat failed: %s", e)


def main():
    role = NODE_ROLE.lower()
    if role not in ("entry", "exit", "both"):
        log.error("Invalid NODE_ROLE=%r, must be entry|exit|both", NODE_ROLE)
        return

    if role in ("exit", "both"):
        bootstrap_interface()

    log.info("starting meshd: node=%s role=%s", NODE_ID, role)
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
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
