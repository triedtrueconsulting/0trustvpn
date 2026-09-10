#!/usr/bin/env python3
"""
The obfuscated transport, end to end, with real packets.

`--obfuscate` is a claim: that a network watching this connection cannot tell
it is WireGuard. That claim is worth exactly as much as the code behind it,
and someone choosing a VPN for censorship circumvention is choosing on this
line — so nothing here is checked by reading source. The real 0trust-obfs
binary is started, the real client relay is driven, and a real WireGuard
handshake initiation is pushed through and read back on the other side.

What is checked, and why each one:

  - a node enrols with a relay and the control plane advertises it, with the
    forwarding target naming the port the tunnel ACTUALLY terminates on. On
    multi-hop that is the device's entry port, not 51820; getting it wrong
    gives a customer a tunnel that never handshakes while every health check
    stays green — the same failure shape as a node registered on the wrong
    wg_port.
  - a node without one advertises nothing, and the client is told to connect
    directly rather than being handed a relay that does not exist.
  - the bytes on the wire carry no WireGuard signature.
  - the relay refuses every destination but the node's own loopback ports.
    Every customer on a node holds the same relay key, so this is the only
    thing between us and running an open proxy with a published password.
  - a half-configured relay is refused at the control plane, because a port
    with no key advertises an endpoint whose packets nothing can open.
"""
import base64, json, os, re, socket, sqlite3, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

EMU = os.path.dirname(os.path.abspath(__file__))
TMP = H.tempdir("0trust-obfs-")
DB = os.path.join(TMP, "0trust.db")
sys.path.insert(0, os.path.join(H.REPO, "api"))
os.environ["ZTV_DB_PATH"] = DB
import main as api_main; api_main.init_db()
H.boot(DB)

PROCS = []


k32 = H.genkey


def mint(region="zur", role="both", uses=5):
    import hashlib, secrets
    token = "ztvp-" + secrets.token_urlsafe(18)
    now = int(time.time())
    c = sqlite3.connect(DB, isolation_level=None)
    c.execute("""INSERT INTO provision_tokens
                   (token_hash, region, role, created_at, expires_at, max_uses)
                 VALUES (?,?,?,?,?,?)""",
              (hashlib.sha256(token.encode()).hexdigest(), region, role,
               now, now + 3600, uses))
    c.close()
    return token


def provision(region, ip, wg_port=51820, obfs_port=0, obfs_key="", role="both"):
    body = {"pubkey": k32(), "public_ip": ip, "region": region, "role": role,
            "wg_port": wg_port, "obfs_port": obfs_port, "obfs_key": obfs_key}
    return H.call("POST", "/api/v1/node/provision", body,
                  headers={"X-Provision-Token": mint(region, role)})


def free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wg_echo(port):
    """A stand-in for the node's WireGuard listener: echo with a marker."""
    import threading
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.bind(("127.0.0.1", port))
    def loop():
        while True:
            try:
                d, a = sk.recvfrom(65535)
            except OSError:
                return
            sk.sendto(b"PONG:" + d, a)
    t = threading.Thread(target=loop, daemon=True); t.start()
    return sk


try:
    print("[1] building the two binaries the node and the client actually run")
    dist = os.path.join(TMP, "dist"); os.makedirs(dist)
    env = {**os.environ, "CGO_ENABLED": "0"}
    for pkg, out in (("./cmd/0trust-obfs", "0trust-obfs"), ("./cmd/0trust", "0trust")):
        r = subprocess.run(["go", "build", "-o", os.path.join(dist, out), pkg],
                           cwd=os.path.join(H.REPO, "client"), env=env,
                           capture_output=True, text=True, timeout=300)
        check(f"{out} builds", r.returncode == 0, r.stderr[-500:])
    OBFS = os.path.join(dist, "0trust-obfs")

    print("\n[2] the control plane advertises a relay only where one exists")
    OBFS_KEY = k32()
    st, b = provision("zur", "203.0.113.10", wg_port=51820,
                      obfs_port=443, obfs_key=OBFS_KEY)
    check("a node enrols with a relay", st == 200, (st, b))
    st, b = provision("rey", "203.0.113.20", wg_port=51820)
    check("and one without", st == 200, (st, b))

    tok, _ = H.paid_account(1)
    st, j = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": k32(), "device_name": "laptop", "region": "zur"},
                   headers={"X-Account-Token": tok})
    check("register succeeds", st == 200, (st, j))
    ob = (j or {}).get("obfuscation")
    check("the zur config carries an obfuscation block", bool(ob), j)
    if ob:
        check("it names the relay's endpoint, not the tunnel's",
              ob["endpoint"] == "203.0.113.10:443", ob)
        check("it hands over the node's key", ob["key"] == OBFS_KEY, ob)
        check("the forwarding target is the node's own loopback",
              ob["target"] == "127.0.0.1:51820", ob)
        check("and the MTU is reduced for the 55 bytes the relay adds",
              ob["mtu"] < j["mtu"] and j["mtu"] - ob["mtu"] >= 55,
              f"plain {j['mtu']} vs obfuscated {ob['mtu']}")

    _, j2 = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": k32(), "device_name": "phone", "region": "rey"},
                   headers={"X-Account-Token": tok})
    check("a node with no relay advertises none", j2.get("obfuscation") is None,
          "a client told to use a relay that is not there gets a tunnel that "
          "never handshakes")

    _, j3 = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": k32(), "device_name": "multi", "region": "zur",
                    "exit_region": "rey"},
                   headers={"X-Account-Token": tok})
    ob3 = j3.get("obfuscation")
    entry_port = j3["peers"][0]["endpoint"].rsplit(":", 1)[1]
    check("multi-hop points the relay at the device's ENTRY port",
          bool(ob3) and ob3["target"] == f"127.0.0.1:{entry_port}",
          f"peer {j3['peers'][0]['endpoint']} vs target {ob3 and ob3['target']} "
          "— the relay's allowlist is keyed on exactly this port")

    print("\n[3] a half-configured relay is refused")
    for label, extra in (
        ("a port with no key",   {"obfs_port": 443}),
        ("a key with no port",   {"obfs_key": k32()}),
        ("the WireGuard port",   {"obfs_port": 51820, "obfs_key": k32()}),
        ("a key that is not base64", {"obfs_port": 443, "obfs_key": "!!!!"}),
        ("a 16-byte key", {"obfs_port": 443,
                           "obfs_key": base64.b64encode(os.urandom(16)).decode()}),
    ):
        st, b = provision("buc", "203.0.113.30", **extra)
        check(f"refused: {label}", st in (400, 422), (st, b))

    print("\n[4] real packets through the real relay")
    wg_port = free_udp_port()
    relay_port = free_udp_port()
    echo = wg_echo(wg_port)
    p = subprocess.Popen(
        [OBFS, "--listen", f"127.0.0.1:{relay_port}",
         "--wg-ports", f"{wg_port},52000-52009"],
        env={**os.environ, "ZTV_OBFS_KEY": OBFS_KEY},
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    PROCS.append(p)
    time.sleep(1.0)
    check("the relay is running", p.poll() is None,
          (p.stdout.read() if p.poll() is not None else ""))

    # Drive the client half through a tiny Go program that imports the very
    # package the CLI uses — not a reimplementation of the protocol, which
    # would only prove the test agrees with itself.
    probe_dir = os.path.join(H.REPO, "client", "cmd", "obfsprobe")
    os.makedirs(probe_dir, exist_ok=True)
    open(os.path.join(probe_dir, "main.go"), "w").write('''package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/0trust/cli/internal/obfs"
)

func main() {
	key := os.Getenv("KEY")
	server, target := os.Args[1], os.Args[2]
	tgt := netip.MustParseAddrPort(target)
	r, err := obfs.NewRelay(server, key, tgt)
	if err != nil {
		fmt.Println("ERR", err); os.Exit(1)
	}
	if err := r.Start(); err != nil {
		fmt.Println("ERR", err); os.Exit(1)
	}
	defer r.Close()

	// A WireGuard handshake initiation: type 1, three reserved zero bytes.
	msg := make([]byte, 148)
	msg[0] = 0x01
	copy(msg[4:], []byte("handshake"))

	c, _ := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(r.Local))
	defer c.Close()
	c.Write(msg)
	c.SetReadDeadline(time.Now().Add(6 * time.Second))
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		fmt.Println("NOREPLY", err); os.Exit(1)
	}
	psk, _ := obfs.ParseKey(key)
	wire, _ := obfs.Pack(psk, tgt, msg)
	fmt.Printf("REPLY %d %s\\n", n, hex.EncodeToString(buf[:9]))
	fmt.Printf("WIRE %d %s\\n", len(wire), hex.EncodeToString(wire[:8]))
}
''')
    try:
        pr = subprocess.run(["go", "run", "./cmd/obfsprobe",
                             f"127.0.0.1:{relay_port}", f"127.0.0.1:{wg_port}"],
                            cwd=os.path.join(H.REPO, "client"),
                            env={**env, "KEY": OBFS_KEY},
                            capture_output=True, text=True, timeout=300)
        out = pr.stdout
        check("a WireGuard handshake completes the round trip through the relay",
              "REPLY" in out and "504f4e473a01000000" in out,
              (pr.stdout + pr.stderr)[-400:])
        wire_line = [l for l in out.splitlines() if l.startswith("WIRE")]
        if wire_line:
            size, prefix = wire_line[0].split()[1:]
            check("the relay adds exactly the overhead the MTU is reduced by",
                  int(size) == 148 + 55, f"{size} bytes for a 148-byte packet")
            check("and the WireGuard type byte is gone from the wire",
                  not prefix.startswith("01000000"),
                  f"first 4 bytes on the wire are {prefix[:8]} — "
                  "01000000 is what a DPI signature matches")
    finally:
        import shutil as _sh; _sh.rmtree(probe_dir, ignore_errors=True)

    print("\n[5] the relay is not an open proxy")
    # A second listener the relay was never told about, standing in for "any
    # host on the internet a customer would like us to relay to".
    elsewhere_port = free_udp_port()
    elsewhere = wg_echo(elsewhere_port)
    probe_dir = os.path.join(H.REPO, "client", "cmd", "obfsproxyprobe")
    os.makedirs(probe_dir, exist_ok=True)
    open(os.path.join(probe_dir, "main.go"), "w").write('''package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/0trust/cli/internal/obfs"
)

// send packs one datagram for dst and reports whether anything came back.
func send(server string, psk []byte, dst netip.AddrPort) bool {
	c, err := net.Dial("udp", server)
	if err != nil {
		return false
	}
	defer c.Close()
	pkt, err := obfs.Pack(psk, dst, []byte("probe"))
	if err != nil {
		return false
	}
	c.Write(pkt)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = c.Read(make([]byte, 65535))
	return err == nil
}

func main() {
	psk, _ := obfs.ParseKey(os.Getenv("KEY"))
	server := os.Args[1]
	allowed := netip.MustParseAddrPort(os.Args[2])
	denied := netip.MustParseAddrPort(os.Args[3])
	fmt.Printf("ALLOWED %v\\n", send(server, psk, allowed))
	fmt.Printf("DENIED %v\\n", send(server, psk, denied))
}
''')
    try:
        pr = subprocess.run(["go", "run", "./cmd/obfsproxyprobe",
                             f"127.0.0.1:{relay_port}",
                             f"127.0.0.1:{wg_port}",
                             f"127.0.0.1:{elsewhere_port}"],
                            cwd=os.path.join(H.REPO, "client"),
                            env={**env, "KEY": OBFS_KEY},
                            capture_output=True, text=True, timeout=300)
        out = pr.stdout
        # The allowed leg must work, or the denied leg proves nothing.
        check("the allowlisted destination answers", "ALLOWED true" in out,
              (pr.stdout + pr.stderr)[-300:] + "\n  without this the next "
              "check would pass on a relay that forwards nothing at all")
        check("a destination off the allowlist is dropped in silence",
              "DENIED false" in out,
              (pr.stdout + pr.stderr)[-300:] + "\n  every customer holds this "
              "key — a relay that forwards anywhere is an open proxy")
    finally:
        import shutil as _sh; _sh.rmtree(probe_dir, ignore_errors=True)
        elsewhere.close()

    print("\n[6] a wrong key gets nothing, and says nothing")
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.settimeout(1.5)
    sk.sendto(os.urandom(200), ("127.0.0.1", relay_port))
    try:
        sk.recvfrom(65535)
        answered = True
    except socket.timeout:
        answered = False
    sk.close()
    check("random bytes get no reply at all", not answered,
          "answering an unopenable packet — even with an error — tells a "
          "prober that something speaks here")

    print("\n[7] enrolment writes the relay's environment, and removes it")
    import shutil
    box = os.path.join(TMP, "box"); os.makedirs(box)
    root = os.path.join(box, "root")
    for d in ("etc/wireguard", "etc/0trust", "var/0trust", "etc/dnsmasq.d",
              "etc/nftables.d", "lib"):
        os.makedirs(os.path.join(root, d), exist_ok=True)
    for f in ("node-runtime.sh", "node-runtime-apply.sh"):
        shutil.copy(os.path.join(H.REPO, "scripts", f), os.path.join(root, "lib", f))
    os.chmod(os.path.join(root, "lib", "node-runtime-apply.sh"), 0o755)

    # ONE enrolment token, reused — that is what makes the second call a
    # reboot rejoining as the same node rather than a second box registering
    # at the same address. Minting a fresh token per call tested nothing
    # about turning the relay off, because the old row stayed behind
    # advertising it.
    boot_token = mint("buc", uses=5)

    def run_enroll(obfs_port, wg_port_=51820, ip="203.0.113.99"):
        envf = os.path.join(box, "node.env")
        open(envf, "w").write(
            f"CONTROL_URL={H.API}\nREGION=buc\nNODE_ROLE=both\n"
            f"WG_PORT={wg_port_}\nOBFS_PORT={obfs_port}\n"
            f"ZTV_PROVISION_TOKEN={boot_token}\n")
        return subprocess.run(
            ["bash", os.path.join(H.REPO, "scripts", "node-enroll.sh")],
            capture_output=True, text=True, timeout=180, cwd=root,
            env={**os.environ,
                 "PATH": os.path.join(EMU, "bin") + ":" + os.environ["PATH"],
                 "STUB_LOG": os.path.join(box, "stub.log"), "STUB_STATE": root,
                 "ZTV_ROOT": root, "ZTV_NODE_ENV": envf,
                 "ZTV_LIBDIR": os.path.join(root, "lib"),
                 "ZTV_PUBLIC_IP": ip, "ZTV_NODE_IPV6": "false", "HOME": box})

    obfs_env = os.path.join(root, "etc/0trust/obfs.env")
    r = run_enroll(8443)
    check("enrolment with a relay succeeds", r.returncode == 0,
          (r.stdout + r.stderr)[-600:])
    check("it writes obfs.env", os.path.exists(obfs_env),
          (r.stdout + r.stderr)[-300:])
    if os.path.exists(obfs_env):
        txt = open(obfs_env).read()
        key_line = [l for l in txt.splitlines() if l.startswith("ZTV_OBFS_KEY=")]
        key_val = key_line[0].split("=", 1)[1] if key_line else ""
        check("with a real 32-byte key",
              len(base64.b64decode(key_val or "")) == 32, repr(key_val))
        check("listening on the configured port",
              "ZTV_OBFS_LISTEN=0.0.0.0:8443" in txt, txt)
        check("and an allowlist of this node's own ports only",
              "ZTV_OBFS_WG_PORTS=51820,52000-59999" in txt, txt)
        check("the file is root-only — the key must not be world-readable",
              oct(os.stat(obfs_env).st_mode)[-3:] == "600",
              oct(os.stat(obfs_env).st_mode))
        # The control plane must have been told the same port.
        row = [n for n in
               sqlite3.connect(DB).execute(
                   "SELECT obfs_port, obfs_key FROM mesh_nodes WHERE public_ip='203.0.113.99'")]
        check("and the control plane records the same port and key",
              bool(row) and row[0][0] == 8443 and row[0][1] == key_val,
              f"db={row} file_key={key_val[:12]}...")

    r = run_enroll(0)
    check("re-enrolling with the relay off succeeds", r.returncode == 0,
          (r.stdout + r.stderr)[-600:])
    check("and REMOVES the stale obfs.env", not os.path.exists(obfs_env),
          "the unit's ConditionPathExists keys on this file; leaving it would "
          "restart-loop a relay with a key the control plane no longer knows")
    row = [n for n in sqlite3.connect(DB).execute(
        "SELECT id, obfs_port FROM mesh_nodes WHERE public_ip='203.0.113.99'")]
    check("the reboot rejoined as ONE node, not a second row", len(row) == 1, row)
    check("and the control plane stops advertising the relay",
          len(row) == 1 and row[0][1] == 0,
          f"{row} — a stale advertisement sends every opted-in client to a "
          "port nothing is listening on")

    r = run_enroll(51820)
    check("enrolment refuses a relay port that is the WireGuard port",
          r.returncode != 0 and "WireGuard port" in (r.stdout + r.stderr),
          (r.stdout + r.stderr)[-300:])

    print("\n[8] the claims match what the code does")
    unit_raw = open(os.path.join(H.REPO, "systemd", "0trust-obfs.service")).read()
    # Comments stripped first. The previous version of this check read the
    # whole file and matched CAP_NET_ADMIN inside the comment EXPLAINING why
    # the unit does not have it — the same shape as grepping for
    # '--no-access-log' and finding the sentence above the flag.
    unit = "\n".join(l for l in unit_raw.splitlines()
                     if not l.lstrip().startswith("#"))
    check("the relay runs unprivileged, separately from meshd",
          "DynamicUser=yes" in unit and "CAP_NET_ADMIN" not in unit,
          "this parses bytes from strangers; it must not hold meshd's "
          "privileges over wg, nftables and routing")
    check("and it is given no writable path anywhere",
          "ProtectSystem=strict" in unit and "ReadWritePaths" not in unit,
          "the relay holds no state across a restart and must never record "
          "who talked to it")
    # The flow table's cap and the unit's fd limit are one decision in two
    # files, so they are checked against each other.
    #
    # The reaper evicts idle flows, which bounds the STEADY state and not the
    # peak — its own comment names running out of file descriptors as the
    # failure mode, and a sender doing thousands of packets a second from
    # distinct source ports reaches that inside one 30-second tick. Every
    # customer on a node holds the same pre-shared key, so producing a valid
    # packet is not a high bar, and the source address is not verified before
    # the flow is created.
    #
    # The cap only helps if it binds BEFORE the fd limit does. Below it,
    # net.ListenUDP fails first, which the relay logs per packet — and at
    # that rate the log line is the denial of service.
    relay_src = open(os.path.join(H.REPO, "client", "internal", "obfs",
                                  "relay.go")).read()
    m = re.search(r"^const MaxFlows = (\d+)$", relay_src, re.M)
    check("the relay declares a flow cap", m is not None,
          "without one, a single sender opens a socket and a goroutine per "
          "source port until the node runs out of file descriptors")
    n = re.search(r"^LimitNOFILE=(\d+)$", unit, re.M)
    check("and the unit sets an explicit fd limit", n is not None,
          "otherwise the headroom is systemd's DefaultLimitNOFILE and Go "
          "raising the soft limit at startup, neither of which this "
          "repository controls")
    if m and n:
        check("the fd limit is comfortably above the flow cap",
              int(n.group(1)) >= int(m.group(1)) * 2,
              f"LimitNOFILE={n.group(1)} against MaxFlows={m.group(1)} — the "
              f"cap has to bind first, or ListenUDP fails and the per-packet "
              f"error log becomes the load")

    inst = open(os.path.join(H.REPO, "scripts", "install.sh")).read()
    check("install.sh verifies the relay is LISTENING, not merely started",
          "ss -lunp" in inst and "NOTHING is listening" in inst,
          "systemctl start returning 0 says the unit launched, not that "
          "anything answers — bug class #16")
    pkg = open(os.path.join(H.REPO, "client", "internal", "obfs",
                            "shadowsocks.go")).read()
    for phrase, why in (
        ("It is not authentication", "the key is shared by every customer on the node"),
        ("not protection against traffic analysis", "sizes and timing are unchanged"),
        ("does not survive a block on UDP", "this is UDP in, UDP out"),
    ):
        check(f"the package states plainly: {phrase!r}", phrase in pkg, why)

    print("\n[8b] the real CLI, connecting through the real relay")
    # Everything above tests the halves. This is the whole path a customer
    # takes: `0trust connect --obfuscate` against a node that offers one —
    # register, spawn the relay, rewrite the peer endpoint to loopback, write
    # the config with the reduced MTU. None of it had ever been executed.
    HOME_ = os.path.join(TMP, "home"); os.makedirs(HOME_, exist_ok=True)
    WGDIR = os.path.join(TMP, "wg"); os.makedirs(WGDIR, exist_ok=True)
    CLI = os.path.join(dist, "0trust")
    cli_env = {**os.environ, "HOME": HOME_,
               "XDG_CONFIG_HOME": os.path.join(HOME_, ".config"),
               "ZTV_API_BASE": H.API,
               "PATH": os.path.join(EMU, "bin") + ":" + os.environ["PATH"],
               "STUB_LOG": os.path.join(TMP, "stub.log"), "STUB_STATE": TMP,
               "ZTV_WG_CONFIG_DIR": WGDIR}

    def cli(*a, env=None, stdin=None):
        r = subprocess.run([CLI, *a], env={**cli_env, **(env or {})},
                           capture_output=True, text=True, input=stdin, timeout=120)
        return r.returncode, r.stdout + r.stderr

    conf = os.path.join(WGDIR, "0trust0.conf")
    rc, out = cli("login", stdin=tok + "\n")
    check("the CLI logs in", rc == 0, out)

    if os.geteuid() != 0:
        # connect requires euid 0 and says so. Skipping silently here would
        # be the SKIP-standing-in-for-a-pass shape; say which it is.
        print("      (not root — connect cannot run; the relay halves are "
              "covered above)")
        rc, out = cli("connect", "zur", "--obfuscate")
        check("connect without root refuses rather than half-running",
              rc != 0 and not os.path.exists(conf), out[-300:])
    else:
        rc, out = cli("connect", "zur")
        check("a plain connect succeeds", rc == 0, out[-500:])
        plain = open(conf).read()
        check("and points straight at the node",
              "Endpoint = 203.0.113.10:51820" in plain, plain)
        check("with no MTU override", "MTU =" not in plain or "MTU = 1420" in plain,
              plain)
        check("status calls the transport direct",
              "direct" in cli("status")[1].lower(), cli("status")[1][-400:])

        rc, out = cli("connect", "zur", "--obfuscate")
        check("connect --obfuscate succeeds", rc == 0, out[-600:])
        check("and says obfuscation is ON", "obfuscation ON" in out, out[-400:])
        ob_cfg = open(conf).read()
        m = re.search(r"Endpoint = 127\.0\.0\.1:(\d+)", ob_cfg)
        check("the peer endpoint is now the local relay", bool(m), ob_cfg)
        check("and the MTU dropped for the relay's overhead",
              "MTU = 1360" in ob_cfg,
              ob_cfg + "\n  a handshake fits at any MTU, so getting this "
              "wrong brings the tunnel up healthy and drops full-size packets")

        state = json.load(open(os.path.join(HOME_, ".config", "0trust", "state.json")))
        check("state records a live relay pid", state.get("relay_pid", 0) > 0, state)
        check("and the setting is sticky", state.get("obfuscate") is True, state)
        if m:
            # The relay must really be bound where the config says.
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.settimeout(1)
            try:
                probe.sendto(b"x", ("127.0.0.1", int(m.group(1))))
                bound = True
            except OSError:
                bound = False
            probe.close()
            check("something is actually listening on that loopback port", bound,
                  "the config names a port nothing answers on")

        check("status now calls the transport obfuscated",
              "obfuscated" in cli("status")[1].lower(), cli("status")[1][-400:])

        # A node with no relay must produce a DIRECT tunnel and say so, not a
        # config aimed at a relay that does not exist.
        rc, out = cli("connect", "rey")
        check("a node with no relay connects directly and says so",
              rc == 0 and "does not run a relay" in out, out[-500:])
        rey_cfg = open(conf).read()
        check("its config points at the node, not loopback",
              "127.0.0.1:" not in rey_cfg, rey_cfg)

        rc, out = cli("disconnect")
        state = json.load(open(os.path.join(HOME_, ".config", "0trust", "state.json")))
        check("disconnect clears the relay from state",
              not state.get("relay_active") and not state.get("relay_pid"), state)

    print("\n[9] the Android app's own transport, compiled and run")
    # A second implementation of a wire format is a liability: two
    # implementations can disagree, and a disagreement here is a tunnel that
    # silently will not come up in the one country where the customer needed
    # it. The Android app cannot run the Go binary — wireguard-android brings
    # the tunnel up inside the app process, so the relay has to live there
    # too — so the mitigation is that the Kotlin is tested AGAINST the Go,
    # with real packets, rather than each against itself.
    #
    # This works at all only because ObfsCrypto, ObfsRelay and AllowedIps
    # carry no android.* references. If somebody adds one, this section stops
    # compiling and the check below says why.
    KT = os.path.join(H.REPO, "mobile", "android", "app", "src", "main",
                      "java", "vpn", "zerotrust", "app")
    PURE = ["ObfsCrypto.kt", "ObfsRelay.kt", "AllowedIps.kt"]
    for f in PURE:
        body = open(os.path.join(KT, f)).read()
        code = "\n".join(l for l in body.splitlines()
                         if not l.lstrip().startswith(("*", "//", "/*")))
        check(f"{f} has no android.* reference", "android." not in code,
              "an android import here would stop this file compiling off a "
              "device, and the interop run below is the only thing that ever "
              "executes the app's copy of the transport")

    kt_cache = os.environ.get("KOTLIN_CACHE_DIR") or "/tmp/0trust-kotlinc-2.0.20"
    kotlinc = os.path.join(kt_cache, "kotlin-compiler-2.0.20.jar")
    if not os.path.exists(kotlinc):
        # A genuine "does not apply" only if the compiler cannot be had at
        # all. Say which it is rather than passing quietly.
        r = subprocess.run(["bash", os.path.join(H.REPO, "mobile", "android",
                                                 "syntax-check.sh")],
                           capture_output=True, text=True, timeout=900)
        print(f"      (kotlinc absent and syntax-check.sh returned "
              f"{r.returncode}; the Kotlin transport was NOT executed)")
    else:
        # annotations-13.0 is needed for codegen, not just parsing —
        # syntax-check.sh never reaches codegen so it never noticed.
        ann = os.path.join(kt_cache, "annotations-13.0.jar")
        if not os.path.exists(ann):
            subprocess.run(["curl", "-fsSL", "-o", ann,
                            "https://repo1.maven.org/maven2/org/jetbrains/"
                            "annotations/13.0/annotations-13.0.jar"],
                           capture_output=True, timeout=180)
        work = os.path.join(TMP, "kt"); os.makedirs(work, exist_ok=True)
        stdlib = os.path.join(kt_cache, "kotlin-stdlib-2.0.20.jar")

        # Driver: exercises the complement AND runs the relay against the Go
        # node binary already listening from section [4].
        open(os.path.join(work, "Drive.kt"), "w").write('''
import vpn.zerotrust.app.AllowedIps
import vpn.zerotrust.app.ObfsCrypto
import vpn.zerotrust.app.ObfsRelay
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress

fun ipToLong(s: String): Long {
    val p = s.split(".")
    return (p[0].toLong() shl 24) or (p[1].toLong() shl 16) or
           (p[2].toLong() shl 8) or p[3].toLong()
}

fun complement(): Boolean {
    // The excluded address must be in NO block, the blocks must not overlap,
    // and together they must cover every address but that one. Getting this
    // wrong in the generous direction routes a slice of the internet outside
    // the tunnel with no error anywhere, so it is checked rather than read.
    val cases = listOf("203.0.113.10", "0.0.0.0", "255.255.255.255", "1.2.3.4",
                       "127.0.0.1", "10.64.0.1", "8.8.8.8", "192.168.1.1",
                       "172.16.31.255", "9.255.255.254")
    for (c in cases) {
        val blocks = AllowedIps.excludingV4(c)
        if (blocks.size != 32) { println("COMPLEMENT-FAIL $c size"); return false }
        val target = ipToLong(c)
        var total = 0L
        val seen = ArrayList<Pair<Long, Long>>()
        for (b in blocks) {
            val lo = ipToLong(b.address)
            val size = 1L shl (32 - b.prefix)
            if (lo % size != 0L) { println("COMPLEMENT-FAIL $c align $b"); return false }
            val hi = lo + size - 1
            if (target in lo..hi) { println("COMPLEMENT-FAIL $c covers target"); return false }
            for ((olo, ohi) in seen) if (lo <= ohi && olo <= hi) {
                println("COMPLEMENT-FAIL $c overlap"); return false
            }
            seen.add(lo to hi); total += size
        }
        if (total != (1L shl 32) - 1) { println("COMPLEMENT-FAIL $c total=$total"); return false }
    }
    // ::/0 must survive whole: the tunnel always claims v6 so it cannot leak
    // around us, and without a v6 address that blackholes it.
    if (!AllowedIps.forRelay("203.0.113.10").contains("::/0")) {
        println("COMPLEMENT-FAIL v6 default route dropped"); return false
    }
    if (AllowedIps.supportsExclusion("2001:db8::1")) {
        println("COMPLEMENT-FAIL claims it can exclude a v6 node"); return false
    }
    return true
}

fun main(args: Array<String>) {
    println(if (complement()) "COMPLEMENT-OK" else "COMPLEMENT-BAD")

    val key = System.getenv("KEY")
    val serverPort = args[0].toInt()
    val wgPort = args[1].toInt()
    val lo = InetAddress.getByName("127.0.0.1")
    val target = InetSocketAddress(lo, wgPort)

    val relay = ObfsRelay("127.0.0.1", serverPort, key, target)
    val port = relay.start()

    val msg = ByteArray(148); msg[0] = 1
    "handshake".toByteArray().copyInto(msg, 4)
    val c = DatagramSocket(); c.soTimeout = 8000
    c.send(DatagramPacket(msg, msg.size, InetSocketAddress(lo, port)))
    val buf = ByteArray(65535)
    val reply = DatagramPacket(buf, buf.size)
    try {
        c.receive(reply)
        println("REPLY " + reply.length + " " +
                buf.copyOf(9).joinToString("") { "%02x".format(it) })
    } catch (t: Throwable) { println("NOREPLY $t") }

    val psk = ObfsCrypto.parseKey(key)
    val wire = ObfsCrypto.pack(psk, target, msg)
    println("WIRE " + wire.size + " " +
            wire.copyOf(4).joinToString("") { "%02x".format(it) })
    println("OVERHEAD " + ObfsCrypto.OVERHEAD)

    // A packet the Kotlin side sealed must open on the Kotlin side too, and
    // a wrong key must not open it.
    val back = ObfsCrypto.unpack(psk, wire)
    println("ROUNDTRIP " + (back.payload.contentEquals(msg) &&
                            back.dst.port == wgPort))
    val other = ObfsCrypto.parseKey(
        java.util.Base64.getEncoder().encodeToString(ByteArray(32) { 7 }))
    println("WRONGKEY " + try { ObfsCrypto.unpack(other, wire); false }
                          catch (t: Throwable) { true })

    // A datagram big enough that sealing it overflows the maximum UDP
    // payload, so the upstream send throws — then a normal handshake right
    // after it. DatagramPacket.length is both capacity in and size out and it
    // PERSISTS, so a version that reset it only on the success path would
    // truncate this second packet to whatever the failed one measured, and
    // the tunnel would start corrupting traffic after its first hiccup
    // instead of failing.
    val huge = ByteArray(65500)
    c.send(DatagramPacket(huge, huge.size, InetSocketAddress(lo, port)))
    Thread.sleep(200)
    val again = ByteArray(148); again[0] = 1
    "second".toByteArray().copyInto(again, 4)
    c.send(DatagramPacket(again, again.size, InetSocketAddress(lo, port)))
    try {
        c.receive(reply)
        println("AFTERFAIL " + reply.length)
    } catch (t: Throwable) { println("AFTERFAIL none") }

    relay.stop()
    println("STOPPED " + !relay.isRunning)
    c.close()
}
''')
        srcs = [os.path.join(KT, f) for f in PURE] + [os.path.join(work, "Drive.kt")]
        r = subprocess.run(
            ["java", "-cp", os.path.join(kt_cache, "*"),
             "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler",
             "-cp", stdlib, "-d", os.path.join(work, "out"), "-nowarn"] + srcs,
            capture_output=True, text=True, timeout=900)
        compiled = os.path.isdir(os.path.join(work, "out"))
        check("the app's transport compiles on a plain JVM", compiled,
              (r.stdout + r.stderr)[-600:])

        if compiled:
            # Reuse the Go relay and WireGuard stub from section [4], both
            # still running, so this is Kotlin client -> Go node -> back.
            rk = subprocess.run(
                ["java", "-cp", os.path.join(work, "out") + ":" + stdlib, "DriveKt",
                 str(relay_port), str(wg_port)],
                capture_output=True, text=True, timeout=300,
                env={**os.environ, "KEY": OBFS_KEY})
            out = rk.stdout
            check("the AllowedIPs complement covers everything but the node, "
                  "exactly", "COMPLEMENT-OK" in out,
                  (rk.stdout + rk.stderr)[-500:] + "\n  too little excluded "
                  "loops the tunnel; too much routes traffic outside it with "
                  "no error anywhere")
            check("a WireGuard handshake goes Kotlin -> Go relay -> back",
                  "504f4e473a01000000" in out,
                  (rk.stdout + rk.stderr)[-500:] + "\n  the two implementations "
                  "of the packet format do not agree")
            wire = [l for l in out.splitlines() if l.startswith("WIRE")]
            over = [l for l in out.splitlines() if l.startswith("OVERHEAD")]
            check("and adds exactly the overhead the Go side does",
                  bool(wire) and int(wire[0].split()[1]) == 148 + 55,
                  wire)
            check("with the same Overhead constant, measured not copied",
                  bool(over) and over[0].split()[1] == "55", over)
            check("the WireGuard type byte is gone from the Kotlin wire too",
                  bool(wire) and not wire[0].split()[2].startswith("01000000"),
                  wire)
            check("a Kotlin-sealed packet reopens as itself",
                  "ROUNDTRIP true" in out, out[-300:])
            check("and does not open under a different key",
                  "WRONGKEY true" in out, out[-300:])
            # This was first written as "a packet after a failure is not
            # truncated" and was toothless: the only reachable send failure
            # is an oversized datagram, and everything after one is smaller,
            # so no length ever carried over. What the sequence DOES prove is
            # that a failed send leaves the relay carrying traffic — a `return`
            # in that catch instead of a continue kills the transport under a
            # live tunnel, and the mutation for that turns this red.
            check("a failed send does not kill the relay",
                  "AFTERFAIL 153" in out,
                  (rk.stdout + rk.stderr)[-500:] + "\n  the pump exited on the "
                  "first oversized datagram and stopped carrying the tunnel")
            check("stopping the relay really stops it",
                  "STOPPED true" in out, out[-300:])

    print("\n[10] what the apps may and may not claim")
    # Android HAS the switch now, so "obfuscat" is no longer banned there.
    # The absolutes never stop being banned, on any surface.
    for root, label in ((os.path.join(H.REPO, "mobile", "android"), "Android"),
                        (os.path.join(H.REPO, "mobile", "ios"), "iOS")):
        hits = []
        for dirpath, _, files in os.walk(root):
            if "/build/" in dirpath or "/.gradle" in dirpath:
                continue
            for f in files:
                if not f.endswith((".kt", ".swift", ".xml", ".strings")):
                    continue
                try:
                    txt = open(os.path.join(dirpath, f), encoding="utf-8",
                               errors="replace").read().lower()
                except OSError:
                    continue
                for w in ("undetectable", "untraceable", "unblockable",
                          "invisible", "bypass censorship", "great firewall"):
                    if w in txt:
                        hits.append(f"{f}: {w}")
        check(f"the {label} app makes no absolute stealth claim", not hits, hits)

    # iOS still has no switch, so it still must not offer one.
    ios_hits = []
    for dirpath, _, files in os.walk(os.path.join(H.REPO, "mobile", "ios")):
        for f in files:
            if f.endswith(".swift"):
                t = open(os.path.join(dirpath, f), encoding="utf-8",
                         errors="replace").read().lower()
                if "dpi protection" in t:
                    ios_hits.append(f)
    check("iOS promises no DPI protection, because it has none", not ios_hits,
          f"{ios_hits} — WireGuardKit owns the packet path there and no relay "
          "sits in front of it; a switch would be a control that does nothing")

    # And the Android switch must render the FACT, not the preference.
    st = open(os.path.join(H.REPO, "mobile", "android", "app", "src", "main",
                           "java", "vpn", "zerotrust", "app", "AppState.kt")).read()
    check("Android tracks the running relay separately from the setting",
          "obfuscationActive" in st and "it.obfs != null" in st,
          "reading the preference where the fact belongs is how a tick mark "
          "comes to imply unrecognizable traffic over plain WireGuard")
    ma = open(os.path.join(H.REPO, "mobile", "android", "app", "src", "main",
                           "java", "vpn", "zerotrust", "app", "MainActivity.kt")).read()
    check("and the hint under the switch says so when they disagree",
          "this node runs no relay" in ma, "the switch alone cannot say it")

finally:
    for p in PROCS:
        p.terminate()
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()
    H.shutdown()

print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
