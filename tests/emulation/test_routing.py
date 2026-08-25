#!/usr/bin/env python3
"""
Which node a customer is actually routed to, and whether we say so honestly.

This module exists because the suite had 500-odd assertions and none of them
noticed that single-hop handed the client three peers all claiming 0.0.0.0/0.
WireGuard treats AllowedIPs as a routing table, not a list of alternatives:
the last peer to claim a prefix takes it from the others. So two of the three
were inert, there was no failover, the API named a node the client was not
using, and the customer's key sat in three nodes' manifests when one was
routing them. Every one of those is invisible to a test that only asks
"did register return 200".
"""
import os, shutil, sqlite3, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

TMP = H.tempdir("0trust-routing-")
DB = os.path.join(TMP, "0trust.db")
os.environ["ZTV_DB_PATH"] = DB
sys.path.insert(0, os.path.join(H.REPO, "api"))
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=2)


def sql(q, *a):
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    rows = c.execute(q, a).fetchall(); c.commit(); c.close()
    return rows


def connect(token, region="zur", exit_region=None):
    body = {"pubkey": H.genkey(), "device_name": "dev", "region": region}
    if exit_region:
        body["exit_region"] = exit_region
    st, resp = H.call("POST", "/api/v1/wg/register", body,
                      headers={"X-Account-Token": token})
    return st, resp, body["pubkey"]


try:
    print("[1] single-hop hands the client exactly one peer")
    token, _ = H.paid_account(1)
    st, resp, pub = connect(token)
    check("register succeeds", st == 200, f"{st} {resp}")
    peers = resp.get("peers", [])
    # Three peers each claiming the default route is not redundancy; it is one
    # working peer and two the kernel has stripped every prefix from.
    check("exactly one peer", len(peers) == 1, peers)
    check("the peer claims the whole default route",
          peers and set(peers[0]["allowed_ips"]) == {"0.0.0.0/0", "::/0"}, peers)
    check("keepalive is set so the tunnel survives NAT idle timeouts",
          peers and peers[0]["persistent_keepalive"] == 25, peers)
    check("DNS points at the mesh gateway",
          resp.get("dns") == [api_main.MESH_GATEWAY_IP], resp.get("dns"))

    print("\n[2] the node we name is the node the client will use")
    check("entry_node matches the peer in the config",
          resp["entry_node"] == peers[0]["id"], resp)
    check("exit_node matches too", resp["exit_node"] == peers[0]["id"], resp)

    print("\n[3] only the routing node holds the customer's key")
    # The seizure claim in the audit pack rests on this: a node gives up the
    # customers it was itself carrying, and no others.
    holders = [r["node_id"] for r in sql(
        """SELECT node_id FROM device_nodes dn
             JOIN devices d ON d.id = dn.device_id
            WHERE d.pubkey = ?""", pub)]
    check("exactly one node is assigned", len(holders) == 1, holders)
    check("and it is the one in the config", holders == [peers[0]["id"]], holders)
    for node in ("zur-01", "rey-01", "buc-01"):
        st_p, manifest = H.call("GET", f"/api/v1/wg/peers?node_id={node}",
                                headers={"X-Node-Psk": H.NODE_PSK})
        keys = [p["public_key"] for p in manifest.get("peers", [])]
        if node == holders[0]:
            check(f"{node} carries this device", pub in keys, keys)
        else:
            check(f"{node} has never heard of it", pub not in keys, keys)

    print("\n[4] a node that stopped answering is not handed out")
    # Every node stale except rey-01. Region is a preference; liveness wins.
    stale = int(time.time()) - api_main.NODE_STALE_SECS - 60
    sql("UPDATE mesh_nodes SET last_heartbeat = ?", stale)
    sql("UPDATE mesh_nodes SET last_heartbeat = ? WHERE id = 'rey-01'", int(time.time()))
    token2, _ = H.paid_account(1)
    st, resp2, _ = connect(token2, region="zur")
    check("register still succeeds", st == 200, f"{st} {resp2}")
    check("routed to the live node, not the stale in-region one",
          resp2["exit_node"] == "rey-01", resp2)

    print("\n[5] when nothing is live we still serve, rather than 503")
    # A control plane that refuses everything because heartbeats are late has
    # turned a monitoring problem into an outage.
    sql("UPDATE mesh_nodes SET last_heartbeat = ?", stale)
    token3, _ = H.paid_account(1)
    st, resp3, _ = connect(token3, region="zur")
    check("register succeeds with every node stale", st == 200, f"{st} {resp3}")
    check("and prefers the requested region",
          resp3["exit_node"] == "zur-01", resp3)

    print("\n[6] load spreads by room left, not by declared capacity")
    sql("UPDATE mesh_nodes SET last_heartbeat = ?, active = 1", int(time.time()))
    # zur-02 is declared smaller but empty; zur-01 is big and already full.
    sql("""INSERT OR REPLACE INTO mesh_nodes
           (id, hostname, pubkey, endpoint, region, role, public_ip,
            capacity, active, ephemeral, last_heartbeat)
           VALUES ('zur-02','zur-02.test','Ynl0ZXNieXRlc2J5dGVzYnl0ZXNieXRlc2J5dGVzMDA=',
                   '203.0.113.11:51820','zur','both','203.0.113.11',10,1,0,?)""",
        int(time.time()))
    sql("UPDATE mesh_nodes SET capacity = 5 WHERE id = 'zur-01'")
    for _ in range(5):
        t, _ = H.paid_account(1)
        connect(t, region="zur")
    counts = {r["id"]: r["n"] for r in sql(
        """SELECT m.id, (SELECT COUNT(*) FROM device_nodes d WHERE d.node_id = m.id) n
             FROM mesh_nodes m WHERE m.region = 'zur'""")}
    # zur-01 started full-ish with a capacity of 5; zur-02 has 10 free slots,
    # so it should take the newcomers even though it is the smaller node.
    check("the roomier node takes the new devices",
          counts.get("zur-02", 0) > 0, counts)
    check("the fuller node is not the only one used",
          counts.get("zur-02", 0) >= counts.get("zur-01", 0) - 5, counts)

    print("\n[7] multi-hop says when entry and exit are the same machine")
    token4, _ = H.paid_account(1)
    st, mh, _ = connect(token4, region="zur", exit_region="buc")
    check("multi-hop register succeeds", st == 200, f"{st} {mh}")
    check("multi-hop returns one relay peer", len(mh.get("peers", [])) == 1, mh)
    check("distinct hosts are not flagged as same-host",
          mh.get("same_host") is False, mh)
    # One box wearing every region code: point them all at one address, the
    # way scripts/install.sh --mode test does.
    sql("UPDATE mesh_nodes SET public_ip = '203.0.113.10'")
    token5, _ = H.paid_account(1)
    st, mh2, _ = connect(token5, region="zur", exit_region="buc")
    check("one-box multi-hop still routes", st == 200, f"{st} {mh2}")
    # The client prints "exit never sees your IP" on every multi-hop connect.
    # When both ends are one machine that is simply false, and the control
    # plane is the only party that can tell.
    check("same-host multi-hop is flagged so the client stops claiming privacy",
          mh2.get("same_host") is True, mh2)

    print("\n[8] the sweeper retires dead nodes, a heartbeat brings them back")
    sql("UPDATE mesh_nodes SET public_ip = '203.0.113.30' WHERE id = 'buc-01'")
    sql("UPDATE mesh_nodes SET public_ip = '203.0.113.10' WHERE id LIKE 'zur-%'")
    sql("UPDATE mesh_nodes SET last_heartbeat = ? WHERE id = 'buc-01'", stale)
    import subprocess
    r = subprocess.run([sys.executable, os.path.join(H.REPO, "api", "sweep.py")],
                       capture_output=True, text=True,
                       env={**os.environ, "ZTV_DB_PATH": DB})
    check("sweeper ran", r.returncode == 0, (r.stderr or r.stdout)[-300:])
    active = {r["id"]: r["active"] for r in sql("SELECT id, active FROM mesh_nodes")}
    check("the dead node was deactivated", active.get("buc-01") == 0, active)
    check("live nodes were left alone", active.get("zur-01") == 1, active)
    # A node that never checked in at all is not evidence of death — it may be
    # a hand-inserted row on a deployment that runs no meshd.
    sql("""INSERT OR REPLACE INTO mesh_nodes
           (id, hostname, pubkey, endpoint, region, role, public_ip,
            capacity, active, ephemeral, last_heartbeat)
           VALUES ('man-01','man.test','bWFudWFsbWFudWFsbWFudWFsbWFudWFsbWFudWEw',
                   '203.0.113.99:51820','zur','both','203.0.113.99',100,1,0,0)""")
    subprocess.run([sys.executable, os.path.join(H.REPO, "api", "sweep.py")],
                   capture_output=True, text=True,
                   env={**os.environ, "ZTV_DB_PATH": DB})
    never = sql("SELECT active FROM mesh_nodes WHERE id = 'man-01'")[0]["active"]
    check("a node that never heartbeat is left active", never == 1, never)

    st_hb, _ = H.call("POST", "/api/v1/node/heartbeat", {"node_id": "buc-01"},
                      headers={"X-Node-Psk": H.NODE_PSK})
    check("the recovered node can heartbeat", st_hb == 200, st_hb)
    back = sql("SELECT active FROM mesh_nodes WHERE id = 'buc-01'")[0]["active"]
    # Without this a blip removes a node permanently, until a human notices.
    check("and that puts it back in rotation", back == 1, back)

    print("\n[8b] IPv6 inside the tunnel, only where it can actually go")
    sql("UPDATE mesh_nodes SET active = 1, last_heartbeat = ?, ipv6 = 0",
        int(time.time()))
    token6, _ = H.paid_account(1)
    st, r4, _ = connect(token6, region="zur")
    # ::/0 is claimed whether or not we can carry v6. That is what stops v6
    # escaping around the tunnel on a dual-stack network; without an address
    # it is blackholed, which is exactly what it was before this existed.
    check("a node without v6 egress hands out no v6 address",
          r4.get("interface_ip6") is None, r4)
    check("but the peer still claims ::/0, so v6 cannot leak",
          "::/0" in r4["peers"][0]["allowed_ips"], r4)
    check("and DNS stays v4-only", r4["dns"] == [api_main.MESH_GATEWAY_IP], r4)

    sql("UPDATE mesh_nodes SET ipv6 = 1 WHERE region = 'zur'")
    token7, _ = H.paid_account(1)
    st, r6, pub6 = connect(token7, region="zur")
    check("a v6-capable node hands out a v6 address",
          bool(r6.get("interface_ip6")), r6)
    v4addr = r6["interface_ip"].split("/")[0]
    check("the v6 address is derived from the v4 one",
          r6["interface_ip6"] == f"{api_main.mesh_ip6(v4addr)}/128", r6)
    check("it is a /128, not a subnet",
          r6["interface_ip6"].endswith("/128"), r6)
    check("it is inside the ULA prefix, not routable space",
          __import__("ipaddress").ip_address(
              r6["interface_ip6"].split("/")[0]).is_private, r6)
    check("DNS gains the v6 gateway",
          api_main.mesh_gateway6() in r6["dns"], r6)

    # The node has to authorize the v6 half or the packets are dropped on
    # arrival, however well the client is configured.
    holder = r6["exit_node"]
    _, manifest = H.call("GET", f"/api/v1/wg/peers?node_id={holder}",
                         headers={"X-Node-Psk": H.NODE_PSK})
    mine = [p for p in manifest["peers"] if p["public_key"] == pub6]
    check("the node's manifest carries the device", len(mine) == 1, manifest)
    check("and authorizes both families",
          mine and api_main.mesh_ip6(v4addr) + "/128" in mine[0]["allowed_ips"]
          and v4addr + "/32" in mine[0]["allowed_ips"], mine)

    # Three implementations of one derivation: the API, meshd, and the shell
    # library the installer and node bootstrap share. A mismatch hands a
    # client an address its node does not answer on.
    import subprocess as _sp
    shell6 = _sp.run(["bash", "-c",
                      f'source {H.REPO}/scripts/node-runtime.sh; '
                      f'ztv_mesh_ip6 {v4addr}'],
                     capture_output=True, text=True).stdout.strip()
    check("the shell library derives the same address",
          shell6 == api_main.mesh_ip6(v4addr),
          f"shell={shell6} api={api_main.mesh_ip6(v4addr)}")
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location(
        "meshd6", os.path.join(H.REPO, "wireguard", "0trust-meshd.py"))
    _m = _ilu.module_from_spec(_spec)
    os.environ.setdefault("CONTROL_URL", "http://127.0.0.1:1")
    os.environ.setdefault("NODE_API_PSK", "x")
    os.environ.setdefault("NODE_ID", "zur-01")
    _spec.loader.exec_module(_m)
    check("meshd derives the same gateway",
          _m._derive_gateway6() == api_main.mesh_gateway6(),
          f"meshd={_m._derive_gateway6()} api={api_main.mesh_gateway6()}")
    check("meshd recognises a v6 mesh prefix as its own",
          _m._in_mesh(f"{api_main.mesh_ip6(v4addr)}/128"))
    # subnet_of raises across families; a v6 peer used to take the sync down.
    check("and does not throw on a foreign v6 prefix",
          _m._in_mesh("2001:db8::1/128") is False)

    # A node reports its own capability, because it is a property of the VPS
    # the operator rented and can change under them.
    sql("UPDATE mesh_nodes SET ipv6 = 0 WHERE id = 'zur-01'")
    st_hb, _ = H.call("POST", "/api/v1/node/heartbeat",
                      {"node_id": "zur-01", "ipv6": True},
                      headers={"X-Node-Psk": H.NODE_PSK})
    check("a heartbeat can report v6 capability", st_hb == 200, st_hb)
    check("and the control plane records it",
          sql("SELECT ipv6 FROM mesh_nodes WHERE id = 'zur-01'")[0]["ipv6"] == 1)

    print("\n[9] the operator is told, and told only about infrastructure")
    events = sql("SELECT kind, severity, subject, detail FROM ops_events "
                 "ORDER BY id")
    kinds = [e["kind"] for e in events]
    # A node dying used to be entirely silent: the control plane kept routing
    # into it and whether anyone noticed depended on someone opening a page.
    check("a node going dark raises an event", "node.down" in kinds, kinds)
    check("it is critical, not a note", any(
        e["severity"] == "critical" for e in events if e["kind"] == "node.down"), events)
    check("it names the node, not just a count", any(
        e["subject"] == "buc-01" for e in events if e["kind"] == "node.down"), events)
    check("recovery closes the loop", "node.up" in kinds, kinds)
    # Alerting on state rather than transition produces an hourly stream that
    # nobody reads, and silence then means nothing.
    check("a second sweep does not repeat the same alert",
          kinds.count("node.down") == 1, kinds)

    # This table is the only running narrative of the system's own state that
    # the product keeps. An account id in it turns that into an activity log —
    # the record privacy.html says does not exist.
    blob = " ".join(f"{e['subject']} {e['detail']}" for e in events)
    leaked = [t for t in (token, token2, token3, token4, token5) if t in blob]
    check("no account token appears in an event", not leaked, leaked)
    check("no device pubkey appears in an event", pub not in blob, blob[:200])
    cols = [r[1] for r in sql("PRAGMA table_info(ops_events)")]
    check("the table has no account or device column",
          not any(c in cols for c in ("account_id", "device_id", "pubkey",
                                      "token", "mesh_ip", "client_ip")), cols)

    st_ev, ev = H.call("GET", "/api/v1/admin/events")
    check("the events feed needs an operator session", st_ev in (401, 403), st_ev)

finally:
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
