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
import json, os, re, shutil, sqlite3, subprocess, sys, time
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

finally:
    H.shutdown()

print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
