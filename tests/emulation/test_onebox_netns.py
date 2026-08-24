#!/usr/bin/env python3
"""
The single-VPS deployment's packet path, for real, in network namespaces.

`install.sh --mode test` puts all three node identities on one box. That
topology makes three claims nothing else in the suite exercises, and each one
is the kind that reads fine in a config file and fails on the wire:

  1. Multi-hop DNAT still works when the exit is the SAME host as the entry.
     The rule rewrites the destination to a local address, so the packet is
     delivered locally instead of forwarded — a different kernel path from the
     one the three-namespace test covers.

  2. Three meshd processes on one host do not erase each other's rules. Each
     replaces its whole nftables table on every poll, so they must not share
     a table name, and all three DNATs have to be live at once.

  3. Per-peer routes send return traffic to the right interface. Three
     WireGuard interfaces in one /10 give the kernel three equally good
     routes to any client; without a /32 per peer, replies for a client on
     wg2 can be handed to wg0, which has never heard of it.

Skips (77) without root and `ip netns`.
"""
import json, os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

CLIENT_NS, BOX_NS = "ztv-ob-client", "ztv-ob-box"
CLIENT_IP, BOX_IP = "10.78.1.2", "10.78.1.1"
# The three ports the installer gives wg0 / wg1 / wg2.
WG_PORTS = {"wg0": 51820, "wg1": 51821, "wg2": 51822}
# One multi-hop entry port per node, from the 52000-59999 range.
ENTRY_PORTS = {"wg0": 52001, "wg1": 52002, "wg2": 52003}

ECHO = '''
import json, socket, sys
port, timeout = int(sys.argv[1]), float(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port)); s.settimeout(timeout)
try:
    data, addr = s.recvfrom(2048)
    s.sendto(b"pong:" + data, addr)
    print(json.dumps({"ok": True, "port": port, "src": addr[0], "sport": addr[1],
                      "data": data.decode("utf-8", "replace")}))
except Exception as e:
    print(json.dumps({"ok": False, "port": port, "error": str(e)}))
'''

SEND = '''
import json, socket, sys
host, port, timeout, payload = sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), sys.argv[4]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
try:
    s.sendto(payload.encode(), (host, port))
    data, addr = s.recvfrom(2048)
    print(json.dumps({"ok": True, "from": addr[0], "fromport": addr[1],
                      "data": data.decode("utf-8", "replace")}))
except Exception as e:
    print(json.dumps({"ok": False, "error": str(e)}))
'''


def sh(cmd, check_rc=True):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"{cmd}\n{r.stderr or r.stdout}")
    return r


def teardown():
    for n in (CLIENT_NS, BOX_NS, "ztv-ob-routes"):
        subprocess.run(["ip", "netns", "del", n], capture_output=True)


def setup():
    teardown()
    for n in (CLIENT_NS, BOX_NS):
        sh(["ip", "netns", "add", n])
        sh(f"ip netns exec {n} ip link set lo up")
    sh(f"ip link add ztv-obc type veth peer name ztv-obb")
    sh(f"ip link set ztv-obc netns {CLIENT_NS}")
    sh(f"ip link set ztv-obb netns {BOX_NS}")
    sh(f"ip netns exec {CLIENT_NS} ip addr add {CLIENT_IP}/24 dev ztv-obc")
    sh(f"ip netns exec {BOX_NS} ip addr add {BOX_IP}/24 dev ztv-obb")
    sh(f"ip netns exec {CLIENT_NS} ip link set ztv-obc up")
    sh(f"ip netns exec {BOX_NS} ip link set ztv-obb up")


if os.geteuid() != 0 or subprocess.run(["ip", "netns", "list"],
                                       capture_output=True).returncode != 0:
    print("  SKIP  needs root and ip netns")
    sys.exit(77)

TMP = H.tempdir("ztv-onebox-")
ECHO_PY, SEND_PY = os.path.join(TMP, "echo.py"), os.path.join(TMP, "send.py")
open(ECHO_PY, "w").write(ECHO)
open(SEND_PY, "w").write(SEND)

# meshd, loaded the way a node loads it.
import importlib.util
os.environ.setdefault("CONTROL_URL", "http://127.0.0.1:1")
os.environ.setdefault("NODE_API_PSK", "x")
os.environ.setdefault("NODE_ID", "zur-01")
_spec = importlib.util.spec_from_file_location(
    "meshd", os.path.join(H.REPO, "wireguard", "0trust-meshd.py"))
meshd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(meshd)


def ruleset_for(iface: str) -> str:
    """Exactly what meshd on that interface would write, table name included."""
    meshd.NFT_TABLE = f"ztv_fwd_{iface}"
    return meshd.build_nft_ruleset(
        [{"entry_port": ENTRY_PORTS[iface],
          "exit_endpoint": f"{BOX_IP}:{WG_PORTS[iface]}"}])


def probe(entry_port: int, listen_ports, payload, timeout=6.0):
    """Send one packet to an entry port; report which listener caught it."""
    procs = {}
    for lp in listen_ports:
        procs[lp] = subprocess.Popen(
            ["ip", "netns", "exec", BOX_NS, sys.executable, ECHO_PY,
             str(lp), str(timeout)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.7)
    sender = subprocess.run(
        ["ip", "netns", "exec", CLIENT_NS, sys.executable, SEND_PY,
         BOX_IP, str(entry_port), str(timeout), payload],
        capture_output=True, text=True, timeout=timeout + 10)
    got = {}
    for lp, p in procs.items():
        out, err = p.communicate(timeout=timeout + 10)
        try:
            got[lp] = json.loads((out or "").strip().splitlines()[-1])
        except Exception:
            got[lp] = {"ok": False, "error": (out or err)[:200]}
    try:
        client = json.loads(sender.stdout.strip().splitlines()[-1])
    except Exception:
        client = {"ok": False, "error": (sender.stdout or sender.stderr)[:200]}
    return got, client


try:
    try:
        setup()
    except RuntimeError as e:
        print(f"  SKIP  cannot build namespaces here: {e}")
        sys.exit(77)

    print("[1] multi-hop DNAT when entry and exit are the same host")
    rp = os.path.join(TMP, "wg1.nft")
    open(rp, "w").write(ruleset_for("wg1"))
    sh(f"ip netns exec {BOX_NS} nft flush ruleset", check_rc=False)
    loaded = subprocess.run(["ip", "netns", "exec", BOX_NS, "nft", "-f", rp],
                            capture_output=True, text=True)
    check("nft loads the ruleset", loaded.returncode == 0,
          (loaded.stderr or loaded.stdout)[:400])

    got, client = probe(ENTRY_PORTS["wg1"], [WG_PORTS["wg1"]], "hop")
    check("the packet reached the exit port on the same box",
          got[WG_PORTS["wg1"]].get("ok"), got)
    check("the client got a reply", client.get("ok"), client)
    # Without conntrack reversing the DNAT the reply would appear to come from
    # 51821, the client would not recognise it, and the tunnel would never
    # come up even though the packet plainly arrived.
    check("the reply appears to come from the entry port the client used",
          client.get("fromport") == ENTRY_PORTS["wg1"],
          f"client saw port {client.get('fromport')}, "
          f"expected {ENTRY_PORTS['wg1']}")

    print("\n[2] three nodes on one box do not erase each other's rules")
    sh(f"ip netns exec {BOX_NS} nft flush ruleset", check_rc=False)
    for iface in ("wg0", "wg1", "wg2"):
        p = os.path.join(TMP, f"{iface}.nft")
        open(p, "w").write(ruleset_for(iface))
        r = subprocess.run(["ip", "netns", "exec", BOX_NS, "nft", "-f", p],
                           capture_output=True, text=True)
        check(f"{iface}'s table loads alongside the others", r.returncode == 0,
              (r.stderr or r.stdout)[:300])
    listing = sh(f"ip netns exec {BOX_NS} nft list ruleset").stdout
    for iface in ("wg0", "wg1", "wg2"):
        check(f"ztv_fwd_{iface} survived the other two loading",
              f"table inet ztv_fwd_{iface}" in listing, listing[:400])

    # And all three DNATs are actually live, not just present in the listing.
    for iface in ("wg0", "wg1", "wg2"):
        got, client = probe(ENTRY_PORTS[iface], list(WG_PORTS.values()), iface)
        hit = [p for p, v in got.items() if v.get("ok")]
        check(f"entry port {ENTRY_PORTS[iface]} lands on {iface}'s port "
              f"{WG_PORTS[iface]}",
              hit == [WG_PORTS[iface]], f"landed on {hit}")

    print("\n[3] per-peer routes send replies to the right interface")
    # Two stand-in interfaces in one mesh network, exactly the ambiguity three
    # WireGuard interfaces create. No WireGuard needed: the routing decision
    # is the thing under test.
    sh(["ip", "netns", "add", "ztv-ob-routes"])
    script = os.path.join(TMP, "routes.py")
    open(script, "w").write(f'''
import importlib.util, json, os, subprocess, sys
os.environ.update(CONTROL_URL="http://127.0.0.1:1", NODE_API_PSK="x", NODE_ID="n")
def load(iface):
    os.environ["WG_IFACE"] = iface
    spec = importlib.util.spec_from_file_location(
        "meshd_" + iface, {os.path.join(H.REPO, "wireguard", "0trust-meshd.py")!r})
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m

# veth rather than dummy: not every kernel here ships the dummy module, and
# the routing decision under test does not care which link type carries it.
for iface, addr in (("d0", "10.64.0.1"), ("d1", "10.64.0.2")):
    subprocess.run(["ip", "link", "add", iface, "type", "veth",
                    "peer", "name", iface + "p"], check=True)
    subprocess.run(["ip", "addr", "add", addr + "/10", "dev", iface], check=True)
    subprocess.run(["ip", "link", "set", iface, "up"], check=True)
    subprocess.run(["ip", "link", "set", iface + "p", "up"], check=True)

load("d0").reconcile_routes([{{"allowed_ips": "10.64.0.5/32"}}])
load("d1").reconcile_routes([{{"allowed_ips": "10.64.0.6/32"}}])

def dev_for(ip):
    out = subprocess.run(["ip", "-j", "route", "get", ip],
                         capture_output=True, text=True).stdout
    try: return json.loads(out)[0].get("dev")
    except Exception: return None

def managed(iface):
    out = subprocess.run(["ip", "route", "show", "dev", iface, "proto", "static"],
                         capture_output=True, text=True).stdout
    # `ip route show` prints a host route bare, without the /32.
    return sorted((l.split()[0] if "/" in l.split()[0] else l.split()[0] + "/32")
                  for l in out.splitlines() if l.strip())

result = {{"peer5": dev_for("10.64.0.5"), "peer6": dev_for("10.64.0.6"),
          "d0": managed("d0"), "d1": managed("d1")}}

# Removing d0's only peer must take d0's route and nothing else.
load("d0").reconcile_routes([])
result["d0_after"] = managed("d0")
result["d1_after"] = managed("d1")
result["peer6_after"] = dev_for("10.64.0.6")
result["connected_kept"] = "10.64.0.0/10" in subprocess.run(
    ["ip", "route", "show", "dev", "d0"], capture_output=True, text=True).stdout
print(json.dumps(result))
''')
    r = subprocess.run(["ip", "netns", "exec", "ztv-ob-routes",
                        sys.executable, script], capture_output=True, text=True)
    try:
        res = json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        res = {}
        if "Unknown device type" in (r.stdout + r.stderr):
            print("  SKIP  this kernel has no link type to stand in for wg")
        else:
            check("route reconciliation ran", False, (r.stdout + r.stderr)[-600:])
    if res:
        # Both interfaces carry a /10, so without the /32 the kernel could
        # answer with either. That it answers correctly is the whole point.
        check("a peer on d0 is reached via d0", res.get("peer5") == "d0", res)
        check("a peer on d1 is reached via d1", res.get("peer6") == "d1", res)
        check("each interface got exactly its own peer's /32",
              res.get("d0") == ["10.64.0.5/32"] and res.get("d1") == ["10.64.0.6/32"],
              res)
        check("dropping d0's peer removes d0's route",
              res.get("d0_after") == [], res)
        check("and leaves d1's alone",
              res.get("d1_after") == ["10.64.0.6/32"], res)
        check("d1's peer is still reachable afterwards",
              res.get("peer6_after") == "d1", res)
        # The daemon must never delete a route it did not create — the /10 the
        # kernel adds with the interface address is not ours to remove.
        check("the kernel's connected route is left alone",
              res.get("connected_kept") is True, res)

    print("\n[4] IPv6 is forwarded and masqueraded, not just configured")
    # The v6 half of the mesh has to survive the same rules the v4 half does:
    # the egress filter must police client v6 without blocking it outright,
    # and NAT66 must rewrite it. Getting this wrong looks identical to "the
    # customer's ISP has no v6" until someone checks.
    lib = os.path.join(H.REPO, "scripts", "node-runtime.sh")
    nat = subprocess.run(["bash", "-c", f'source "{lib}"; ztv_nat_ruleset eth0'],
                         capture_output=True, text=True).stdout
    egress = subprocess.run(["bash", "-c", f'source "{lib}"; ztv_egress_ruleset'],
                            capture_output=True, text=True).stdout
    check("NAT66 masquerades the v6 mesh prefix",
          "ip6 saddr fd0e:5f7a:c21b::/48 masquerade" in nat, nat)
    check("v4 masquerade is still there", "ip saddr 10.64.0.0/10 masquerade" in nat, nat)
    # An "ip saddr" test cannot be evaluated against a v6 packet, so before
    # the v6 clause every rule below it applied to forwarded v6 traffic
    # whether or not a customer sent it.
    check("client v6 is policed by its own family test",
          "ip6 saddr != fd0e:5f7a:c21b::/48 accept" in egress, egress)
    sh(f"ip netns exec {BOX_NS} nft flush ruleset", check_rc=False)
    both = os.path.join(TMP, "dual.nft")
    open(both, "w").write(nat + egress)
    r = subprocess.run(["ip", "netns", "exec", BOX_NS, "nft", "-f", both],
                       capture_output=True, text=True)
    check("the kernel accepts the dual-stack ruleset", r.returncode == 0,
          (r.stderr or r.stdout)[:500])
    listing = sh(f"ip netns exec {BOX_NS} nft list ruleset").stdout
    check("both masquerade rules are live", listing.count("masquerade") >= 2, listing[:600])
    # fc00::/7 contains our own ULA, so this also isolates customers from each
    # other over v6 — matching what the v4 rule does with 10.0.0.0/8.
    check("customers cannot reach each other over v6",
          "fc00::/7" in listing, listing[:600])

finally:
    teardown()
    import shutil as _sh
    _sh.rmtree(TMP, ignore_errors=True)
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
