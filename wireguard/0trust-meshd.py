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
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "30"))

NFT_TABLE = "0trust_forward"

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
    return _get("/api/v1/wg/peers")["peers"]


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
        lines.append(f"    udp dport {f['entry_port']} dnat to {f['exit_endpoint']}")
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
