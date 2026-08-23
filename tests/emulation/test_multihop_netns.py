#!/usr/bin/env python3
"""
The multi-hop packet path, for real, in network namespaces.

Everything else about multi-hop is tested at the level of "the right rules
were generated". That is not the same as "the packets do what the design
says", and the difference matters: the entry node's masquerade rule was
wrong for the whole life of the project, and no ruleset-text assertion could
have noticed.

Three namespaces wired client -> entry -> exit. The entry loads the ruleset
`meshd.build_nft_ruleset` actually emits, and a UDP packet is pushed through
it. Two things must hold:

  1. it arrives at the exit at all (the tunnel works), and
  2. the exit sees the ENTRY's address, not the client's — which is the whole
     privacy claim of multi-hop, and the thing the old rule silently broke.

WireGuard itself is not involved; this is about the NAT path underneath it.

Skips (77) without CAP_NET_ADMIN or `ip netns`.
"""
import json, os, shutil, socket, subprocess, sys, textwrap, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

NS = ["ztv-client", "ztv-entry", "ztv-exit"]
ENTRY_PORT = 52001
EXIT_PORT = 51820
CLIENT_IP, ENTRY_IN = "10.77.1.2", "10.77.1.1"
ENTRY_OUT, EXIT_IP = "10.77.2.1", "10.77.2.2"


def sh(cmd, check_rc=True, **kw):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True,
                       text=True, **kw)
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"{cmd}\n{r.stderr or r.stdout}")
    return r


def teardown():
    for n in NS:
        subprocess.run(["ip", "netns", "del", n], capture_output=True)


def setup():
    teardown()
    for n in NS:
        sh(["ip", "netns", "add", n])
    # client <-> entry
    sh("ip link add ztv-c type veth peer name ztv-e1")
    sh("ip link set ztv-c netns ztv-client")
    sh("ip link set ztv-e1 netns ztv-entry")
    # entry <-> exit
    sh("ip link add ztv-e2 type veth peer name ztv-x")
    sh("ip link set ztv-e2 netns ztv-entry")
    sh("ip link set ztv-x netns ztv-exit")

    sh(f"ip -n ztv-client addr add {CLIENT_IP}/24 dev ztv-c")
    sh("ip -n ztv-client link set ztv-c up")
    sh("ip -n ztv-client link set lo up")
    sh(f"ip -n ztv-client route add default via {ENTRY_IN}")

    sh(f"ip -n ztv-entry addr add {ENTRY_IN}/24 dev ztv-e1")
    sh(f"ip -n ztv-entry addr add {ENTRY_OUT}/24 dev ztv-e2")
    sh("ip -n ztv-entry link set ztv-e1 up")
    sh("ip -n ztv-entry link set ztv-e2 up")
    sh("ip -n ztv-entry link set lo up")
    sh("ip netns exec ztv-entry sysctl -qw net.ipv4.ip_forward=1")

    sh(f"ip -n ztv-exit addr add {EXIT_IP}/24 dev ztv-x")
    sh("ip -n ztv-exit link set ztv-x up")
    sh("ip -n ztv-exit link set lo up")
    sh(f"ip -n ztv-exit route add default via {ENTRY_OUT}")


ECHO = textwrap.dedent("""
    import socket, sys, json
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(sys.argv[1])))
    s.settimeout(float(sys.argv[2]))
    try:
        data, addr = s.recvfrom(2048)
        s.sendto(b"pong:" + data, addr)          # reply on the return path
        print(json.dumps({"ok": True, "src": addr[0], "sport": addr[1],
                          "data": data.decode(errors="replace")}))
    except socket.timeout:
        print(json.dumps({"ok": False, "error": "timeout"}))
""")

SEND = textwrap.dedent("""
    import socket, sys, json
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sport = int(sys.argv[4])
    if sport:
        s.bind(("0.0.0.0", sport))     # pin it; the old rule keyed on this
    s.settimeout(float(sys.argv[3]))
    s.sendto(b"ping", (sys.argv[1], int(sys.argv[2])))
    try:
        data, addr = s.recvfrom(2048)
        print(json.dumps({"ok": True, "reply": data.decode(errors="replace"),
                          "from": addr[0], "fromport": addr[1]}))
    except socket.timeout:
        print(json.dumps({"ok": False, "error": "no reply"}))
""")


def run_path(ruleset: str, timeout=6.0, client_sport=0):
    """
    Load a ruleset on the entry, push one packet through, return both ends.

    The namespaces are rebuilt first, every time. Flushing the ruleset does
    NOT flush conntrack, so a flow tracked under the previous ruleset stays
    masqueraded after the rules change — which made the "prove the old rule
    is broken" case pass or fail depending on what ran before it. Rebuilding
    costs a fraction of a second and makes each measurement independent.
    """
    setup()
    sh("ip netns exec ztv-entry nft flush ruleset", check_rc=False)
    rp = os.path.join(TMP, "rules.nft")
    open(rp, "w").write(ruleset)
    sh(f"ip netns exec ztv-entry nft -f {rp}")

    ep, sp = os.path.join(TMP, "echo.py"), os.path.join(TMP, "send.py")
    open(ep, "w").write(ECHO); open(sp, "w").write(SEND)

    listener = subprocess.Popen(
        ["ip", "netns", "exec", "ztv-exit", sys.executable, ep,
         str(EXIT_PORT), str(timeout)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.6)
    sender = subprocess.run(
        ["ip", "netns", "exec", "ztv-client", sys.executable, sp,
         ENTRY_IN, str(ENTRY_PORT), str(timeout), str(client_sport)],
        capture_output=True, text=True, timeout=timeout + 10)
    out, err = listener.communicate(timeout=timeout + 10)

    def parse(s):
        try: return json.loads(s.strip().splitlines()[-1])
        except Exception: return {"ok": False, "error": (s or err)[:200]}
    return parse(out), parse(sender.stdout)


if os.geteuid() != 0 or subprocess.run(["ip", "netns", "list"],
                                       capture_output=True).returncode != 0:
    print("  SKIP  needs root and ip netns")
    sys.exit(77)

import tempfile
TMP = tempfile.mkdtemp(prefix="ztv-netns-")
try:
    try:
        setup()
    except RuntimeError as e:
        print(f"  SKIP  cannot build namespaces here: {e}")
        sys.exit(77)

    # The ruleset the product actually generates.
    sys.path.insert(0, os.path.join(H.REPO, "wireguard"))
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "meshd", os.path.join(H.REPO, "wireguard", "0trust-meshd.py"))
    # meshd reads required env at import time.
    os.environ.setdefault("CONTROL_URL", "http://127.0.0.1:1")
    os.environ.setdefault("NODE_API_PSK", "x")
    os.environ.setdefault("NODE_ID", "zur-01")
    meshd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(meshd)

    forwards = [{"entry_port": ENTRY_PORT, "exit_endpoint": f"{EXIT_IP}:{EXIT_PORT}"}]
    shipped = meshd.build_nft_ruleset(forwards)
    print("[1] the ruleset meshd generates is one nft will actually load")
    check("contains the DNAT rule", f"dport {ENTRY_PORT}" in shipped, shipped)
    check("masquerades the DNAT'd flows", "ct status dnat masquerade" in shipped, shipped)

    # The two syntax bugs that meant `nft -f` rejected the whole file, so no
    # entry node ever installed a DNAT rule at all. Neither was visible to a
    # string assertion, which is exactly why this test exists.
    check("table name is a valid nft identifier (cannot start with a digit)",
          not meshd.NFT_TABLE[0].isdigit(), meshd.NFT_TABLE)
    check("DNAT names an address family, required inside an inet table",
          "dnat ip to" in shipped or "dnat ip6 to" in shipped, shipped)

    sh("ip netns exec ztv-entry nft flush ruleset", check_rc=False)
    rp0 = os.path.join(TMP, "shipped.nft")
    open(rp0, "w").write(shipped)
    loaded = subprocess.run(
        ["ip", "netns", "exec", "ztv-entry", "nft", "-f", rp0],
        capture_output=True, text=True)
    check("nft loads the generated ruleset without error",
          loaded.returncode == 0, (loaded.stderr or loaded.stdout)[:600])

    # An IPv6 exit endpoint has to produce a loadable rule too.
    v6 = meshd.build_nft_ruleset(
        [{"entry_port": 52099, "exit_endpoint": "[2001:db8::1]:51820"}])
    rp6 = os.path.join(TMP, "v6.nft")
    open(rp6, "w").write(v6)
    sh("ip netns exec ztv-entry nft flush ruleset", check_rc=False)
    loaded6 = subprocess.run(
        ["ip", "netns", "exec", "ztv-entry", "nft", "-f", rp6],
        capture_output=True, text=True)
    check("an IPv6 exit endpoint also produces a loadable rule",
          loaded6.returncode == 0, (loaded6.stderr or loaded6.stdout)[:400])

    print("\n[2] a packet actually traverses client -> entry -> exit")
    at_exit, at_client = run_path(shipped)
    check("the exit received the packet", at_exit.get("ok"), at_exit)
    check("the client got a reply back through the entry",
          at_client.get("ok"), at_client)
    check("the reply appears to come from the entry, as the client expects",
          at_client.get("from") == ENTRY_IN,
          f"client saw {at_client.get('from')}, expected {ENTRY_IN}")

    print("\n[3] the privacy property: the exit must NOT see the client")
    check("exit sees the entry's address",
          at_exit.get("src") == ENTRY_OUT,
          f"exit saw {at_exit.get('src')}, expected {ENTRY_OUT}")
    check("exit does NOT see the client's address",
          at_exit.get("src") != CLIENT_IP,
          f"exit saw the real client address {CLIENT_IP} — multi-hop leaks the IP")

    print("\n[4] the new rule holds whatever source port the client picks")
    for sport in (40000, 52500):
        at_exit_p, _ = run_path(shipped, client_sport=sport)
        check(f"source port {sport}: exit still sees only the entry",
              at_exit_p.get("src") == ENTRY_OUT,
              f"exit saw {at_exit_p.get('src')}")

    print("\n[5] the old rule is proven broken — and worse, intermittently so")
    # Exactly what shipped before. It matched the SOURCE port range, but by
    # postrouting the source port is the client's ephemeral port, not the
    # entry port DNAT already rewrote. Linux draws ephemeral ports from
    # roughly 32768-60999, so 52000-59999 overlaps it: the rule masqueraded
    # by coincidence maybe a third of the time. An IP leak that only happens
    # on some connections is harder to notice than one that always happens,
    # which is why this is pinned to both sides of the boundary rather than
    # left to chance.
    broken = shipped.replace("ct status dnat masquerade",
                             "udp sport >= 52000 udp sport <= 59999 masquerade")

    leak_exit, leak_client = run_path(broken, client_sport=40000)
    check("source port outside 52000-59999: the client's real IP reaches the exit",
          leak_exit.get("ok") and leak_exit.get("src") == CLIENT_IP,
          f"exit={leak_exit}")
    if leak_exit.get("src") == CLIENT_IP:
        print(f"          confirmed leak: exit saw {CLIENT_IP}, the real client")

    luck_exit, _ = run_path(broken, client_sport=52500)
    check("source port inside 52000-59999: it masqueraded purely by luck",
          luck_exit.get("src") == ENTRY_OUT,
          f"exit={luck_exit}")
    print("          so the old rule leaked or not depending on an ephemeral port")
    print("\n[6] the rules a node actually installs, from the shared library")
    # Same defect, same blast radius: both of these tables were once named
    # 0trust_*, so nft rejected them. The exit node got no masquerade, and the
    # abuse-mitigation egress filter — the thing that stops a customer reaching
    # RFC1918 or sending spam from our IP — was never in force.
    #
    # They now live in scripts/node-runtime.sh, which both bootstrap-node.sh
    # (a real node) and install.sh --mode test (the one-box deployment) source.
    # Rendering them from the library is what keeps those two identical: a test
    # box whose rules differ from production predicts nothing.
    lib = os.path.join(H.REPO, "scripts", "node-runtime.sh")
    check("bootstrap-node.sh sources the shared runtime",
          "node-runtime.sh" in open(
              os.path.join(H.REPO, "scripts", "bootstrap-node.sh")).read())

    def render(fn, *args):
        r = subprocess.run(["bash", "-c",
                            f'source "{lib}"; {fn} ' + " ".join(map(str, args))],
                           capture_output=True, text=True)
        return r.stdout if r.returncode == 0 else ""

    blocks = {"nat": render("ztv_nat_ruleset", "eth0"),
              "egress": render("ztv_egress_ruleset")}
    check("the library renders both rulesets",
          all(blocks.values()), {k: bool(v) for k, v in blocks.items()})

    import re as _re
    for label, rendered in blocks.items():
        if not rendered:
            continue
        name_match = _re.search(r"table\s+\w+\s+(\S+)\s*\{", rendered)
        tname = name_match.group(1) if name_match else "?"
        check(f"node table {tname!r} is a valid nft identifier",
              tname[0].isalpha() or tname[0] == "_", tname)

        sh("ip netns exec ztv-entry nft flush ruleset", check_rc=False)
        bp = os.path.join(TMP, f"node-{label}.nft")
        open(bp, "w").write(rendered)
        r = subprocess.run(["ip", "netns", "exec", "ztv-entry", "nft", "-f", bp],
                           capture_output=True, text=True)
        check(f"nft loads node table {tname!r}", r.returncode == 0,
              (r.stderr or r.stdout)[:500])

    print("\n[7] the egress filter actually blocks what it claims to")
    egress = blocks["egress"]
    check("egress ruleset rendered", bool(egress))
    if egress:
        sh("ip netns exec ztv-entry nft flush ruleset", check_rc=False)
        ep2 = os.path.join(TMP, "egress.nft")
        open(ep2, "w").write(egress)
        sh(f"ip netns exec ztv-entry nft -f {ep2}")
        listing = sh("ip netns exec ztv-entry nft list ruleset").stdout
        check("outbound SMTP is dropped", "25" in listing and "drop" in listing,
              listing[:400])
        check("RFC1918 pivot is dropped", "192.168.0.0/16" in listing, listing[:400])
        check("link-local pivot is dropped", "169.254.0.0/16" in listing, listing[:400])
        check("connection-rate limit present", "limit rate over" in listing,
              listing[:400])
        check("traffic not from the mesh range is left alone",
              "10.64.0.0/10" in listing, listing[:400])

finally:
    teardown()
    shutil.rmtree(TMP, ignore_errors=True)
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
