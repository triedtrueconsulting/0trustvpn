# Staging deployment — two VPSes, a DuckDNS name, no money

A from-scratch build on two boxes. It is called staging and not production on
purpose: `docs/LAUNCH.md` is the production playbook (five boxes, the real
domain, signed installers, the legal items), and this is the smaller thing you
stand up first to prove the product actually works.

What this build is, stated plainly so nothing here gets mistaken for launch:

- **One control plane and one node**, so routing is **single-hop only**.
  Multi-hop requires entry ≠ exit and there is only one exit.
- **A DuckDNS hostname**, not the real domain. Every page still carries
  `0trustvpn.com` in its canonical URLs, `security.txt` and sitemap — 16 files
  hardcode it and the installer copies `web/` verbatim. Cosmetic here; the app
  calls the API on relative paths so nothing breaks.
- **No wallet.** Free trials work; paid signup returns 502. Leave it that way
  until the open finding in `docs/production-readiness/SECURITY-AUDIT.md`
  (SEC-1) is resolved.
- **Real TLS.** This is the point of using DuckDNS rather than
  `--mode test`: certbot issues a real certificate over HTTP-01, so the
  production nginx path gets exercised.

---

## Phase 0 — Both boxes, before anything

| | Control plane | Node |
|---|---|---|
| OS | Ubuntu 24.04 | Ubuntu 24.04 |
| Virtualisation | any | **KVM — mandatory** |
| Size | 1 vCPU, 2 GB, 20 GB | 1 vCPU, 1 GB+, 10 GB |
| Swap | `--swap 1G` is fine | **never** |

**KVM on the node is not negotiable.** LXC and OpenVZ containers cannot load
kernel modules, so they have no WireGuard and cannot carry a tunnel. Both are
sold as "VPS". `deploy-vps.sh` refuses a node install on one before touching
the box, and tells you which it found.

Swap is refused on a node because it can page a WireGuard private key to disk,
which is the one thing a RAM-only node exists to prevent.

**Starting over:** rebuild both boxes from the provider's panel. The installer
is idempotent and safe to re-run, but a fresh image is the only way to be sure
nothing from a previous attempt is still in `/etc`.

---

## Phase 1 — Control plane

### 1.1 Point DuckDNS at this box, first

Certbot validates the name **during** the install, so DNS has to be right
before you start. Run this **on the control plane** and omit the IP, so
DuckDNS uses the caller's address and cannot be wrong:

```bash
curl -sS -w '\n[http %{http_code}]\n' \
  "https://www.duckdns.org/update?domains=0-trust&token=YOUR_REAL_TOKEN"
```

It prints `OK` or `KO` — two bytes, **no trailing newline**, which is why
`curl -s` alone looks like it printed nothing. `-w '\n'` fixes that. HTTP is
200 either way, so the body is the only signal. `KO` means the token is wrong
or you passed the full hostname: `domains` takes the label only, `0-trust`.

Confirm, with the same command the installer's own preflight uses:

```bash
getent ahostsv4 0-trust.duckdns.org | awk '{print $1}' | sort -u
```

That must print this box's public IP before you continue.

### 1.2 Install

```bash
git clone -b claude/zero-trust-vpn-migration-irshxp \
    https://github.com/triedtrueconsulting/0trustvpn.git /opt/0trust-src

sudo bash /opt/0trust-src/scripts/deploy-vps.sh control \
     --domain 0-trust.duckdns.org \
     --email you@example.com \
     --swap 1G
```

Backups are **off** unless you pass `--backup-key age1...`, and the installer
says so out loud. Generate the key on your own machine, never on the server —
only the public half belongs here:

```bash
age-keygen -o 0trust-backup.key      # keep this file offline
grep 'public key' 0trust-backup.key  # the age1... value goes in --backup-key
```

Skipping it is fine for staging. On a box with paying customers it is not: the
database is the only record of what each one bought, and a token cannot
rebuild an expiry.

### 1.3 Create the operator account

Open `https://0-trust.duckdns.org/admin`. With no operator yet it offers to
create one, and refuses to do that a second time. Do it immediately — the
endpoint is open until the first account exists.

### 1.4 Verify before moving on

```bash
curl -fsS https://0-trust.duckdns.org/api/v1/health
curl -s  https://0-trust.duckdns.org/api/v1/status/public
sudo /opt/0trust-src/scripts/audit-verify.sh
```

`status/public` should say `service: down` with no regions — correct, there is
no node yet. A `FAIL` from audit-verify is a claim this deployment does not
keep; read it rather than skipping it.

---

## Phase 2 — The node

### 2.1 Mint an enrolment token (on the control plane)

```bash
sudo -u 0trust python3 /opt/0trust/api/mint-provision-token.py \
     --region zur --role both --uses 20 --ttl 31536000
```

Or in the browser: **/admin → NODES → Mint**. Either way it is shown **once**;
only its hash is stored.

**Use `--uses` above 1.** A node's disk is tmpfs, so a reboot forgets its
WireGuard key and its node id, and a single-use token cannot bring it back —
the box comes up and silently never rejoins the mesh. An enrolment token pins
itself to that node's public IP on first use and re-registers the *same* node
afterwards, so a reboot is a rejoin rather than an outage. A copy stolen off
the box is inert anywhere else, and the dashboard can revoke it.

### 2.2 Install the node

A token in `argv` lands in shell history and in `ps` for every local user, so
pass it by file:

```bash
printf '%s' 'ztvp-...' > /root/.ztv-token && chmod 600 /root/.ztv-token

git clone -b claude/zero-trust-vpn-migration-irshxp \
    https://github.com/triedtrueconsulting/0trustvpn.git /opt/0trust-src

sudo bash /opt/0trust-src/scripts/deploy-vps.sh node \
     --control-url https://0-trust.duckdns.org \
     --region zur \
     --token-file /root/.ztv-token
```

Optional: `--wg-port 443` blends with QUIC in netflow. `--obfs-port <n>` runs
the DPI-protection relay, which is off by default and opt-in on both ends.

### 2.3 There is nothing to add to the dashboard

The node registers itself — `POST /api/v1/node/provision` — and appears under
**/admin → NODES** with its region, role, capacity and last heartbeat. Nodes
are never added by hand-written SQL.

The dashboard's **Add node** button creates only the database row; such a node
has no keys and no meshd and cannot carry traffic. It is for a box provisioned
manually with `scripts/bootstrap-node.sh`.

From the dashboard you can then set role and capacity, **drain** the node
(toggle it inactive so clients move elsewhere as they reconnect), revoke its
enrolment token, or delete it.

---

## Phase 3 — Prove it carries traffic

Everything above verifies a host and a service. None of it proves a customer
can pass packets, and that is the one thing no part of this project has ever
confirmed in any environment.

On the node:

```bash
ip link show wg0                        # the interface exists at all
nft list ruleset | grep masquerade      # NAT is loaded
```

The masquerade check is not optional. `/etc/nftables.conf` does not include
`/etc/nftables.d`, so NAT is kernel state nothing replays on its own — a node
that comes back without it takes customer traffic into the tunnel where it
dies silently, while meshd goes on heartbeating happily over its own outbound
HTTPS.

Then, from a client:

```bash
curl -s https://0-trust.duckdns.org/api/v1/regions     # zur present
sudo 0trust connect --region zur
curl https://api.ipify.org                             # must show the NODE's IP
```

`0trust connect` waits for a real handshake and exits non-zero if none
arrives, because `wg-quick up` never contacts the node and its exit code means
nothing. A changed egress IP is the first genuine proof the product works.

---

## What is deliberately not done here

Run `./scripts/preflight.sh` on the control plane for the live list. As of
this guide it reports 11 blocked items, and none of them are bugs — they are
the things a script must not do for you:

- **SEC-1** — two extended public keys are in git history with unknown
  provenance. An extended public key cannot be rotated. Resolve this before
  pointing a wallet at the deployment.
- Release, canary and support PGP keys generated on your own machine, and the
  DEADBEEF placeholders replaced on the site.
- A warrant canary published, and signed.
- Signed installers built on real toolchains.
- Legal review of privacy.html, terms.html and the canary; the entity name
  matched to the Handelsregister entry; VAT decided **before** the first sale.

Two more that this staging build cannot demonstrate at all: the real domain,
and multi-hop. Multi-hop needs a second node in a different jurisdiction, and
the privacy argument needs all three.
