#!/usr/bin/env python3
"""
Deploy a mesh node the way an operator will, and reboot it.

`install.sh --mode node` is the path a fresh Ubuntu VPS takes to become part
of the mesh, and scripts/node-enroll.sh is what actually joins it — on the
first boot and on every one after. This runs the real script against the real
control plane with wg/nft/ip/systemctl stubbed, then does the thing that
breaks node deployments: it reboots the box.

That case is why enrolment exists at all. A node's disk is tmpfs, because
privacy.html and AUDIT.md §5.3 promise customers the WireGuard key never
touches persistent storage. So a reboot loses the key, the node id and the
PSK, and the one-shot provisioning token that got the node in was burned the
first time. Before this, the box came back up and silently never rejoined:
the control plane went on listing a node whose key no longer existed, handing
customers an endpoint that could not complete a handshake.

Also checked here, because both were only true by accident before:
  - a node on a non-default WireGuard port was registered as :51820 anyway
  - nftables NAT and the abuse egress filter are kernel state, and nothing on
    a stock Ubuntu box replays them, so an exit node came back from a reboot
    doing no NAT at all
"""
import json, os, re, shutil, socket, sqlite3, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

EMU = os.path.dirname(os.path.abspath(__file__))
TMP = H.tempdir("0trust-node-")
DB = os.path.join(TMP, "0trust.db")
sys.path.insert(0, os.path.join(H.REPO, "api"))
os.environ["ZTV_DB_PATH"] = DB
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB)

ENROLL = os.path.join(H.REPO, "scripts", "node-enroll.sh")
INSTALL = os.path.join(H.REPO, "scripts", "install.sh")


def mint(region="zur", role="both", ttl=3600, uses=1):
    """A provisioning token, the way mint-provision-token.py makes one."""
    import hashlib, secrets
    token = "ztvp-" + secrets.token_urlsafe(18)
    now = int(time.time())
    c = sqlite3.connect(DB, isolation_level=None)
    c.execute("""INSERT INTO provision_tokens
                   (token_hash, region, role, created_at, expires_at, max_uses)
                 VALUES (?,?,?,?,?,?)""",
              (hashlib.sha256(token.encode()).hexdigest(), region, role,
               now, now + ttl, uses))
    c.close()
    return token


def node_env(box, token, region="zur", role="both", port=51820):
    """The persistent file install.sh --mode node writes."""
    path = os.path.join(box, "node.env")
    open(path, "w").write(
        f"CONTROL_URL={H.API}\nREGION={region}\nNODE_ROLE={role}\n"
        f"WG_PORT={port}\nZTV_PROVISION_TOKEN={token}\n")
    return path


def enroll(box, envfile, public_ip="203.0.113.77", ipv6="false"):
    """
    Run the real enrolment script against a scratch filesystem.

    ZTV_ROOT prefixes every path it writes, so this drives the shipped script
    unmodified and needs no privileges. The first version bind-mounted /etc
    inside `unshare -Urm` instead, which worked as root and failed everywhere
    else — a user namespace maps uid 0 to the caller, so `mkdir /etc/0trust`
    is still denied. The enrolment path then went untested on exactly the
    unprivileged CI that was meant to be checking it.
    """
    root = os.path.join(box, "root")
    for d in ("etc/wireguard", "etc/0trust", "var/0trust", "etc/dnsmasq.d",
              "etc/nftables.d", "lib"):
        os.makedirs(os.path.join(root, d), exist_ok=True)
    for f in ("node-runtime.sh", "node-runtime-apply.sh"):
        shutil.copy(os.path.join(H.REPO, "scripts", f),
                    os.path.join(root, "lib", f))
    os.chmod(os.path.join(root, "lib", "node-runtime-apply.sh"), 0o755)
    env = {
        **os.environ,
        "PATH": os.path.join(EMU, "bin") + ":" + os.environ["PATH"],
        "STUB_LOG": os.path.join(box, "stub.log"),
        "STUB_STATE": root,
        "ZTV_ROOT": root,
        "ZTV_NODE_ENV": envfile,
        "ZTV_LIBDIR": os.path.join(root, "lib"),
        "ZTV_PUBLIC_IP": public_ip,
        "ZTV_NODE_IPV6": ipv6,
        "HOME": box,
    }
    return subprocess.run(["bash", ENROLL], capture_output=True, text=True,
                          timeout=180, env=env, cwd=root)


def rows(sql, args=()):
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row
    out = [dict(x) for x in c.execute(sql, args).fetchall()]
    c.close()
    return out


try:
    print("[1] a fresh VPS joins the mesh in one call")
    box = os.path.join(TMP, "box1"); os.makedirs(box)
    tok = mint(uses=5)
    envf = node_env(box, tok, port=51999)
    r = enroll(box, envf)
    check("enrolment succeeds", r.returncode == 0,
          (r.stdout + r.stderr)[-700:])
    check("it says which node it became",
          re.search(r'joined the mesh as [a-z]{2,8}-\d+', r.stdout) is not None,
          r.stdout[-300:])

    state = {}
    sp = os.path.join(box, "root", "var", "0trust", "enrol.state")
    if os.path.exists(sp):
        state = dict(l.strip().split("=", 1) for l in open(sp) if "=" in l)
    node_id = state.get("NODE_ID", "")
    check("it recorded the node id it was given", bool(node_id), state)

    db_rows = rows("SELECT * FROM mesh_nodes WHERE id = ?", (node_id,))
    check("the control plane has the node", len(db_rows) == 1, db_rows)
    node = db_rows[0] if db_rows else {}
    check("marked active and heartbeating", node.get("active") == 1
          and node.get("last_heartbeat", 0) > 0, node)
    check("in the region the token allowed", node.get("region") == "zur", node)

    # The bug this test exists to pin down first: the endpoint was built as
    # f"{public_ip}:51820" regardless of the port the node actually listens
    # on. Every client handed that node would have timed out, while meshd's
    # heartbeat — a separate outbound call — kept reporting it healthy.
    check("the endpoint carries the port the node really listens on",
          node.get("endpoint") == "203.0.113.77:51999",
          f"{node.get('endpoint')!r} — a node on a non-default port was "
          "registered at :51820 and nothing could reach it")

    print("\n[2] meshd got an environment it can start on")
    menv = os.path.join(box, "root", "etc", "0trust", "meshd.env")
    check("meshd.env was written", os.path.exists(menv))
    if os.path.exists(menv):
        m = dict(l.strip().split("=", 1) for l in open(menv) if "=" in l)
        check("with this node's id", m.get("NODE_ID") == node_id, m)
        check("with a PSK the control plane will accept",
              len(m.get("NODE_API_PSK", "")) == 64, sorted(m))
        check("and the right port", m.get("WG_PORT") == "51999", m)
        # The PSK is what /wg/peers authenticates on. A node holding one that
        # does not match its row cannot fetch a single peer.
        st, b = H.call("GET", f"/api/v1/wg/peers?node_id={node_id}",
                       headers={"X-Node-PSK": m.get("NODE_API_PSK", "")})
        check("and the PSK actually works against /wg/peers", st == 200,
              (st, b))

    print("\n[3] the runtime a reboot would otherwise lose")
    stub = open(os.path.join(box, "stub.log")).read()
    check("NAT was applied", "nft -f" in stub,
          "an exit node that comes back without NAT drops every customer "
          "packet silently")
    check("the mesh resolver was configured",
          os.path.exists(os.path.join(box, "root", "etc", "dnsmasq.d",
                                      "0trust.conf")),
          "clients are handed DNS = the mesh gateway; without this they "
          "connect and resolve nothing")

    print("\n[4] reboot: the key is gone, the node comes back anyway")
    old_pubkey = node.get("pubkey")
    # A reboot on a RAM-only node is exactly this: the tmpfs is empty again.
    for d in ("etc/wireguard", "etc/0trust"):
        shutil.rmtree(os.path.join(box, "root", d)); os.makedirs(os.path.join(box, "root", d))
    r2 = enroll(box, envf)
    check("it enrols again after a reboot", r2.returncode == 0,
          (r2.stdout + r2.stderr)[-700:])
    check("and says it rejoined rather than joined",
          "rejoined the mesh as" in r2.stdout, r2.stdout[-300:])

    after = rows("SELECT * FROM mesh_nodes WHERE region = 'zur' AND ephemeral = 1")
    check("it is the same node, not a second one", len(after) == 1,
          [n["id"] for n in after] or "a reboot minted a new node id and left "
          "the old row behind")
    if after:
        check("under the same id", after[0]["id"] == node_id,
              (after[0]["id"], node_id))
        check("with the fresh key it generated on boot",
              after[0]["pubkey"] != old_pubkey,
              "the same key survived a reboot — /etc/wireguard is not RAM")
        check("still active", after[0]["active"] == 1, after[0])

    print("\n[5] the token is bound to this box and nothing else")
    box2 = os.path.join(TMP, "box2"); os.makedirs(box2)
    envf2 = node_env(box2, tok)
    r3 = enroll(box2, envf2, public_ip="198.51.100.44")
    check("a copy of the token from another address is refused",
          r3.returncode != 0,
          "an enrolment token lives on a node's disk; if it works from "
          "anywhere, that disk is a way into the mesh")
    check("and the refusal says why",
          "bound to another address" in (r3.stdout + r3.stderr),
          (r3.stdout + r3.stderr)[-300:])

    print("\n[6] tokens that must not work")
    cases = [
        ("expired", mint(ttl=-10), "zur", "both", 401),
        ("wrong region", mint(region="rey"), "zur", "both", 400),
        ("wrong role", mint(role="exit"), "zur", "both", 400),
        ("never minted", "ztvp-not-a-real-token", "zur", "both", 401),
    ]
    for label, token, region, role, want in cases:
        st, b = H.call("POST", "/api/v1/node/provision",
                       {"pubkey": H.genkey(), "public_ip": "198.51.100.9",
                        "region": region, "role": role},
                       headers={"X-Provision-Token": token})
        check(f"{label} -> {want}", st == want, (st, b))

    print("\n[7] a one-shot token is still one-shot")
    one = mint(uses=1)
    st, b = H.call("POST", "/api/v1/node/provision",
                   {"pubkey": H.genkey(), "public_ip": "198.51.100.21",
                    "region": "zur", "role": "both"},
                   headers={"X-Provision-Token": one})
    check("first use works", st == 200, (st, b))
    st2, b2 = H.call("POST", "/api/v1/node/provision",
                     {"pubkey": H.genkey(), "public_ip": "198.51.100.22",
                      "region": "zur", "role": "both"},
                     headers={"X-Provision-Token": one})
    check("a second box cannot replay it", st2 == 401, (st2, b2))
    # Same box, same token: this is the reboot case for a one-shot token, and
    # it has to keep working or the old cloud-init image can never restart.
    st3, b3 = H.call("POST", "/api/v1/node/provision",
                     {"pubkey": H.genkey(), "public_ip": "198.51.100.21",
                      "region": "zur", "role": "both"},
                     headers={"X-Provision-Token": one})
    check("but the box it registered can re-register", st3 == 200,
          (st3, b3))
    check("as the same node", st3 == 200 and b3.get("node_id") == b.get("node_id"),
          (b, b3))
    check("and is told it rejoined", st3 == 200 and b3.get("rejoined") is True,
          b3)

    print("\n[8] revocation")
    rev = mint(uses=5)
    st, _ = H.call("POST", "/api/v1/node/provision",
                   {"pubkey": H.genkey(), "public_ip": "198.51.100.31",
                    "region": "zur", "role": "both"},
                   headers={"X-Provision-Token": rev})
    check("the token works before revocation", st == 200, st)
    import hashlib
    c = sqlite3.connect(DB, isolation_level=None)
    c.execute("UPDATE provision_tokens SET revoked_at=? WHERE token_hash=?",
              (int(time.time()), hashlib.sha256(rev.encode()).hexdigest()))
    c.close()
    st, b = H.call("POST", "/api/v1/node/provision",
                   {"pubkey": H.genkey(), "public_ip": "198.51.100.31",
                    "region": "zur", "role": "both"},
                   headers={"X-Provision-Token": rev})
    check("a revoked token cannot re-register, even from the bound box",
          st == 401, (st, b))

    print("\n[8b] upstream DNS leaves the node encrypted, or not at all")
    # dnsmasq used to forward straight to 9.9.9.9 over UDP 53. The tunnel
    # encrypted the customer's half of the path and then published the other
    # half: every hostname readable by the node's hosting provider and by
    # anyone between them and Quad9.
    import shutil as _sh
    rt = os.path.join(H.REPO, "scripts", "node-runtime.sh")

    def render(fn, env=None, args=""):
        r = subprocess.run(["bash", "-c", f"source {rt}; {fn} {args}"],
                           capture_output=True, text=True, timeout=60,
                           env={**os.environ, **(env or {})})
        return r.stdout

    dnsconf = render("ztv_dnsmasq_conf", args="10.64.0.1")
    check("dnsmasq forwards to the local DoT stub, not to a public resolver",
          "server=127.0.0.1#5353" in dnsconf and "server=9.9.9.9" not in dnsconf,
          dnsconf)
    check("query logging is still off", "log-queries" not in dnsconf.replace(
          "# Deliberately NOT set: log-queries", ""), dnsconf)

    stubconf = render("ztv_stubby_conf")
    check("the stub demands authentication, not just encryption",
          "GETDNS_AUTHENTICATION_REQUIRED" in stubconf,
          "without this the connection is encrypted to whoever answered")
    check("and checks a certificate name",
          'tls_auth_name: "dns.quad9.net"' in stubconf, stubconf)
    check("TLS is the only transport offered",
          "GETDNS_TRANSPORT_TLS" in stubconf and "TRANSPORT_UDP" not in stubconf,
          "a UDP entry in this list turns strict mode off")

    # The operator escape hatch has to work, and has to be loud.
    plain = render("ztv_dnsmasq_conf", env={"ZTV_DNS_ENCRYPTED": "0"},
                   args="10.64.0.1")
    check("ZTV_DNS_ENCRYPTED=0 goes back to plain resolvers",
          "server=9.9.9.9" in plain, plain)
    check("and says in the file that queries now leave in clear",
          "in clear" in plain, plain)

    if _sh.which("stubby"):
        # A real file: stubby seeks in its config, so /dev/stdin fails with
        # "Illegal seek" and would look like a rejected config.
        sconf = os.path.join(TMP, "stubby.yml")
        open(sconf, "w").write(stubconf)
        r = subprocess.run(["stubby", "-C", sconf, "-i"],
                           capture_output=True, text=True, timeout=60)
        check("stubby itself accepts the config",
              r.returncode == 0 or "Strict" in (r.stdout + r.stderr),
              (r.stdout + r.stderr)[-300:])
        # Read the settings back out of stubby's own parse, not out of the
        # file we just wrote: what matters is what stubby resolved them to.
        parsed = r.stdout + r.stderr
        check("stubby resolves it to authentication-required",
              "GETDNS_AUTHENTICATION_REQUIRED" in parsed, parsed[-300:])
        check("with TLS as the only transport it will use",
              "GETDNS_TRANSPORT_TLS" in parsed
              and "GETDNS_TRANSPORT_UDP" not in parsed,
              "any other transport in this list silently drops strict mode")
    else:
        print("      (stubby not installed — config not run)")

    if _sh.which("dnsmasq"):
        conf = os.path.join(TMP, "dnsmasq.conf")
        open(conf, "w").write(dnsconf.replace("listen-address=10.64.0.1",
                                              "listen-address=127.0.0.1"))
        r = subprocess.run(["dnsmasq", "--test", "--conf-file=" + conf],
                           capture_output=True, text=True, timeout=60)
        check("dnsmasq accepts the config", r.returncode == 0,
              (r.stdout + r.stderr)[-300:])

        # The property that matters: with the stub down, it must not answer.
        # A resolver that quietly falls back to cleartext when TLS fails is
        # the same leak with an extra step, and nobody would ever notice.
        port = H.pick_port()
        proc = subprocess.Popen(
            ["dnsmasq", "--keep-in-foreground", "--conf-file=" + conf,
             f"--port={port}", "--listen-address=127.0.0.1",
             "--bind-interfaces", "--no-daemon",
             "--pid-file=" + os.path.join(TMP, "dnsmasq.pid")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        import struct, random as _rnd
        tid = _rnd.randint(0, 65535)
        pkt = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        for lbl in ("example", "com"):
            pkt += bytes([len(lbl)]) + lbl.encode()
        pkt += b"\x00" + struct.pack(">HH", 1, 1)
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sk.settimeout(6)
        answers = None
        try:
            sk.sendto(pkt, ("127.0.0.1", port))
            data, _ = sk.recvfrom(4096)
            answers = struct.unpack(">H", data[6:8])[0]
        except socket.timeout:
            answers = 0
        finally:
            sk.close(); proc.terminate()
            try: proc.wait(timeout=5)
            except Exception: proc.kill()
        check("with the DoT stub down it answers nothing, rather than "
              "resolving in clear", answers == 0,
              f"{answers} answers came back with no encrypted upstream running")
    else:
        print("      (dnsmasq not installed — resolver not run)")

    print("\n[8c] the node's own footprint")
    # None of this is obfuscation and the docs must not imply it is. What it
    # is: not announcing the tunnel on WireGuard's registered port, and not
    # beaconing on a metronome that netflow alone can pick out.
    md = os.path.join(H.REPO, "wireguard", "0trust-meshd.py")
    import importlib.util
    spec = importlib.util.spec_from_file_location("meshd_mod", md)
    meshd = importlib.util.module_from_spec(spec)
    os.environ.setdefault("CONTROL_URL", H.API)
    os.environ.setdefault("NODE_API_PSK", H.NODE_PSK)
    os.environ.setdefault("NODE_ID", "zur-01")
    spec.loader.exec_module(meshd)

    vals = [meshd.next_interval() for _ in range(500)]
    check("the check-in interval is not a metronome",
          len(set(round(v, 3) for v in vals)) > 400,
          "a fixed-period beacon to a fixed host is a shape in netflow")
    check("and stays in a sane band around the configured interval",
          all(1.0 <= v <= meshd.POLL_INTERVAL * 2 for v in vals),
          f"min={min(vals):.1f} max={max(vals):.1f}")

    r = subprocess.run(
        ["bash", "-c",
         f'ZTV_POLL_JITTER=0 {sys.executable} -c '
         f'\'import importlib.util,os;'
         f'os.environ.update(CONTROL_URL="x",NODE_API_PSK="x",NODE_ID="n");'
         f's=importlib.util.spec_from_file_location("m","{md}");'
         f'm=importlib.util.module_from_spec(s);s.loader.exec_module(m);'
         f'print(m.next_interval())\''],
        capture_output=True, text=True, timeout=60)
    check("an operator can turn the jitter off", r.stdout.strip() == "30.0",
          (r.stdout + r.stderr)[-200:])

    # A node on 443 has to be REGISTERED on 443, or the camouflage costs the
    # customer their connection — which is the bug this suite already caught
    # once for arbitrary ports.
    box443 = os.path.join(TMP, "box443"); os.makedirs(box443)
    tok443 = mint(region="rey", uses=3)
    env443 = node_env(box443, tok443, region="rey", port=443)
    r = enroll(box443, env443, public_ip="203.0.113.201")
    check("a node can run the tunnel on udp 443", r.returncode == 0,
          (r.stdout + r.stderr)[-400:])
    row = rows("SELECT * FROM mesh_nodes WHERE public_ip = ?",
               ("203.0.113.201",))
    check("and is advertised there", bool(row)
          and row[0]["endpoint"] == "203.0.113.201:443",
          row[0]["endpoint"] if row else "no row")

    # The claim discipline: nothing may say the tunnel is hidden.
    deploy = open(os.path.join(H.REPO, "docs", "DEPLOY.md")).read()
    check("the docs say plainly that DPI identifies this",
          "deep packet" in deploy.lower() and "not obfuscated" in deploy.lower(),
          "a VPN implying stealth it does not have is the worst claim to get "
          "wrong — people route real risk through it")
    for page in ("index.html", "help.html", "privacy.html"):
        txt = open(os.path.join(H.REPO, "web", page)).read().lower()
        bad = [w for w in ("obfuscat", "undetectable", "stealth",
                           "bypass censorship", "great firewall") if w in txt]
        check(f"web/{page} claims no stealth", not bad, bad)

    print("\n[9] the sweeper does not delete a token a live node still needs")
    # The sweeper prunes provisioning tokens a day after use, on the reasoning
    # that a used token is spent. It is not: a RAM-only node re-presents its
    # token on every boot. Pruning it worked fine for a day and then, on some
    # reboot weeks later, left the box unable to register at all — with no
    # symptom until that reboot.
    sweep_tok = mint(uses=5)
    st, prov = H.call("POST", "/api/v1/node/provision",
                      {"pubkey": H.genkey(), "public_ip": "198.51.100.60",
                       "region": "zur", "role": "both"},
                      headers={"X-Provision-Token": sweep_tok})
    check("a node enrols", st == 200, (st, prov))
    live_node = prov.get("node_id") if st == 200 else ""

    # Age the use past the sweeper's 24h cutoff, and orphan a second token
    # whose node no longer exists — that one SHOULD go.
    import hashlib as _h
    long_ago = int(time.time()) - 3 * 86400
    dead_tok = mint(uses=5)
    c = sqlite3.connect(DB, isolation_level=None)
    c.execute("UPDATE provision_tokens SET used_at=? WHERE token_hash=?",
              (long_ago, _h.sha256(sweep_tok.encode()).hexdigest()))
    c.execute("UPDATE provision_tokens SET used_at=?, used_node_id=? WHERE token_hash=?",
              (long_ago, "zur-99-gone", _h.sha256(dead_tok.encode()).hexdigest()))
    c.close()

    sweep = subprocess.run([sys.executable, os.path.join(H.REPO, "api", "sweep.py")],
                           capture_output=True, text=True, timeout=120,
                           env={**os.environ, "ZTV_DB_PATH": DB})
    check("the sweeper runs", sweep.returncode == 0,
          (sweep.stdout + sweep.stderr)[-400:])

    left = {r["token_hash"] for r in rows("SELECT token_hash FROM provision_tokens")}
    check("a token whose node is still in the mesh survives",
          _h.sha256(sweep_tok.encode()).hexdigest() in left,
          "the node would reboot into a mesh that no longer recognises it")
    check("a token whose node is gone is pruned",
          _h.sha256(dead_tok.encode()).hexdigest() not in left,
          "spent tokens for dead nodes should not accumulate forever")

    # And prove the survivor still works, which is the only thing that matters.
    st, again = H.call("POST", "/api/v1/node/provision",
                       {"pubkey": H.genkey(), "public_ip": "198.51.100.60",
                        "region": "zur", "role": "both"},
                       headers={"X-Provision-Token": sweep_tok})
    check("and the node can still rejoin after a sweep",
          st == 200 and again.get("node_id") == live_node, (st, again))

    print("\n[10] the installer renders a node without touching the box")
    r = subprocess.run(
        ["bash", INSTALL, "--mode", "node", "--dry-run",
         "--control-url", "https://cp.example.com", "--region", "zur",
         "--provision-token", "ztvp-x"],
        capture_output=True, text=True, timeout=180,
        env={**os.environ, "TERM": "dumb"})
    out = r.stdout + r.stderr
    check("dry run exits clean", r.returncode == 0, out[-500:])
    check("it says the disk is RAM-only", "tmpfs" in out, out[-400:])
    check("it installs no control plane", "nginx" not in out.lower(),
          "a node running the website and the customer database is not a node")
    for flag, want in (
            (["--mode", "node", "--dry-run", "--region", "zur",
              "--provision-token", "t"], "control-url"),
            (["--mode", "node", "--dry-run", "--control-url", "https://c",
              "--provision-token", "t"], "region"),
            (["--mode", "node", "--dry-run", "--control-url", "https://c",
              "--region", "zur"], "provision-token")):
        rr = subprocess.run(["bash", INSTALL, *flag], capture_output=True,
                            text=True, timeout=120,
                            env={**os.environ, "TERM": "dumb"})
        check(f"it refuses to run without --{want}",
              rr.returncode != 0 and want in (rr.stdout + rr.stderr),
              (rr.stdout + rr.stderr)[-200:])

    print("\n[9] a node cannot name itself anything it likes")
    # `region` was an unconstrained str. It is rendered on the PUBLIC status
    # page, which built its grid by interpolating into innerHTML — somebody
    # else's markup on our page. status.html now uses textContent, and the
    # shape is constrained at both entry points: the API model, and
    # mint-provision-token.py's --region, which is where an operator typo
    # actually enters. A token pins the region a node may claim, so a typo
    # mints a token for a region that will never route and only shows up when
    # the node is live and nothing reaches it.
    #
    # The token pins (region, role), so an accepted case needs a token minted
    # for it; a rejected one is refused by the model before the token is read.
    for region, want, label in (
        ("zur", 200, "a real region is accepted"),
        ("ams", 200, "an unknown but well-formed region is still accepted"),
        ("<img src=x onerror=alert(1)>", 422, "markup is rejected"),
        ("ZUR", 422, "uppercase is rejected"),
        ("z", 422, "too short is rejected"),
        ("averylongregionname", 422, "too long is rejected"),
        ("zur; DROP TABLE mesh_nodes", 422, "punctuation is rejected"),
    ):
        tok = mint(region=region if want == 200 else "zur", role="both")
        st, b = H.call("POST", "/api/v1/node/provision",
                       {"pubkey": H.genkey(), "public_ip": "198.51.100.40",
                        "region": region, "role": "both"},
                       headers={"X-Provision-Token": tok})
        check(f"{label}: {region[:24]!r}", st == want, (st, b))

    for role, want in (("both", 200), ("entry", 200), ("exit", 200),
                       ("god", 422), ("", 422)):
        tok = mint(region="rey", role=role if want == 200 else "both")
        st, b = H.call("POST", "/api/v1/node/provision",
                       {"pubkey": H.genkey(), "public_ip": "198.51.100.41",
                        "region": "rey", "role": role},
                       headers={"X-Provision-Token": tok})
        check(f"role {role!r} -> {want}", st == want, (st, b))

    # The tool that mints the token is the other entry point.
    r = subprocess.run([sys.executable,
                        os.path.join(H.REPO, "api", "mint-provision-token.py"),
                        "--region", "BAD;rm -rf /", "--role", "both"],
                       capture_output=True, text=True, timeout=60,
                       env={**os.environ, "ZTV_DB_PATH": DB})
    check("mint-provision-token.py refuses a malformed region",
          r.returncode != 0 and "region code" in (r.stdout + r.stderr),
          (r.returncode, (r.stdout + r.stderr)[-200:]))

    # And the page that renders it must not build HTML out of it either.
    status_html = open(os.path.join(H.REPO, "web", "status.html"),
                       encoding="utf-8").read()
    check("status.html does not interpolate a region into innerHTML",
          "${r.region" not in status_html and "${r.state" not in status_html,
          "a region code reaching innerHTML is an injection point on a public page")
    check("it builds the grid with textContent instead",
          "textContent" in status_html, status_html[:200])

finally:
    H.shutdown()

print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
