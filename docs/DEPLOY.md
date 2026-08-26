# Deploying on a fresh Ubuntu 24.04 VPS

One script, three modes. All idempotent — re-run to pick up new code or to
repair a half-finished run.

```bash
git clone <your-repo> /opt/0trust-src
cd /opt/0trust-src

# 1. Kick the tyres: no domain, no TLS, serves on the box's IP
sudo ./scripts/install.sh --mode test

# 2. Real deployment: domain + Let's Encrypt
sudo ./scripts/install.sh --mode production \
     --domain 0trustvpn.com --email you@example.com

# 3. A mesh node, joined to an existing control plane in one command
sudo ./scripts/install.sh --mode node \
     --control-url https://0trustvpn.com \
     --region zur --role both --provision-token ztvp-...
```

`--dry-run` renders everything and touches nothing, which is the safe way to
see what a run would do before letting it near a live box.

## What gets installed

| | |
| --- | --- |
| `0trust-api` | control plane on 127.0.0.1:8080 |
| `0trust-proxy` | `/surf` visitor proxy on 127.0.0.1:8081 |
| `0trust-sweep.timer` | hourly account expiry and garbage collection |
| `0trust-backup.timer` | installed but **not enabled** — needs an age key first, see `docs/DR.md` |
| nginx | TLS termination, rate limits, static site |
| `/etc/0trust/api.env` | generated with fresh `NODE_API_PSK` and `ZTV_TRIAL_SECRET` |
| `/var/lib/0trust/0trust.db` | SQLite, schema initialised |
| `0trust-meshd@wg0/1/2` | **test mode only** — three mesh nodes on this box |
| `dnsmasq` | **test mode only** — the mesh resolver on 10.64.0.1 |

Secrets are generated once. A re-run never rotates them — rotating
`NODE_API_PSK` would lock out every mesh node, and rotating
`ZTV_TRIAL_SECRET` would invalidate every challenge in flight. A re-run does
add any config keys your `api.env` predates, leaving your edits alone.

## Mode 1 — test

For seeing the thing work. One VPS becomes the entire product: website,
control plane, admin dashboard, `/surf` proxy, **and a real WireGuard mesh
carrying real traffic.** `0trust connect` works the moment the installer
finishes — there is no second box to build first.

It:

- serves plain HTTP on port 80 on the box's IP, no domain needed;
- brings up three WireGuard interfaces, one per region code, and registers
  each as a node with its real public key:

  | node | region | interface | port | mesh gateway |
  | --- | --- | --- | --- | --- |
  | `zur-01` | zur | `wg0` | 51820 | 10.64.0.1 |
  | `rey-01` | rey | `wg1` | 51821 | 10.64.0.2 |
  | `buc-01` | buc | `wg2` | 51822 | 10.64.0.3 |

- opens udp 52000-59999 for multi-hop entry ports, which nftables DNATs to
  whichever exit the control plane picked;
- masquerades customer traffic out the primary interface and loads the same
  abuse-mitigation egress filter a production node runs — no outbound SMTP, no
  pivoting into private ranges, connection-storm rate limit;
- runs `dnsmasq` on 10.64.0.1 and its IPv6 counterpart, the resolvers every
  client config names;
- carries IPv6 inside the tunnel when the box has working v6 egress. meshd
  probes for a v6 default route plus a global address and reports the answer
  on every heartbeat; where the answer is no, clients get no v6 address and v6
  is blackholed rather than leaked;
- leaves ssh alone, because locking password auth on a box you are holding
  open with a password is how you lose the box.

Then, from your laptop:

```bash
export ZTV_API_BASE=http://<ip>
0trust login                                  # or http://<ip>/trial
sudo 0trust connect --region zur              # single hop
sudo 0trust connect --entry zur --exit rey    # multi-hop
curl https://api.ipify.org                    # should print <ip>
```

### What a one-box deployment cannot prove

The installer prints all of this at the end too. It matters because the
product's claims are about topology, and this topology is not the product's.

- **No TLS.** Account tokens, the admin password and everything else cross the
  network in clear. Do not put a customer on it, and do not reuse a token you
  created here on the real deployment.
- **One machine, one jurisdiction.** `zur`/`rey`/`buc` are three interfaces on
  one host, not three countries. Nothing about the multi-jurisdiction argument
  is being demonstrated.
- **Multi-hop does not hide you here.** On a real deployment the entry node
  forwards UDP it cannot decrypt to an exit node elsewhere, so the exit never
  learns the client's address. Entry and exit are the same host here, so it
  does. The routing is real and worth testing; the privacy property is not.
- **Everything shares one IP.** Control plane, website, proxy and VPN egress.
  Seizing it gets all of them — the exact concentration the production
  topology exists to avoid.
- Payments are unconfigured, so `POST /api/v1/account` returns 502 until you
  fill them in at `/admin`. Free trials work, because they need no provider.

Pass `--no-vpn` to skip the mesh entirely and get the older behaviour:
placeholder node rows, no WireGuard, no packet forwarding. Useful when you
only care about the web side.

### Moving to real nodes

Nothing about the control plane changes. Mint an enrolment token — dashboard
**Nodes → Node enrolment token**, or `api/mint-provision-token.py` — and run
one command on each VPS:

```bash
sudo ./scripts/install.sh --mode node \
     --control-url https://<control plane> \
     --region zur --role both --provision-token ztvp-...
```

The node registers itself, so there are no `mesh_nodes` rows to write. Delete
the local placeholder rows once the real nodes are live.

## Mode 2 — production

Before you run it: point the domain's A/AAAA records at the box and make sure
port 80 is reachable, or certbot cannot complete the HTTP-01 challenge and the
installer stops with that message rather than leaving nginx half-configured.

Afterwards:

1. **Payments.** Edit `/etc/0trust/api.env`, then
   `systemctl restart 0trust-api`.
   - `ZTV_PAYMENT_PROVIDER=btcpay` with `BTCPAY_URL` / `BTCPAY_STORE_ID` /
     `BTCPAY_API_KEY` / `BTCPAY_WEBHOOK_SECRET`. Non-custodial. Your own
     BTCPay or someone else's — either way you run no blockchain node.
   - `ZTV_PAYMENT_PROVIDER=hosted` with the `ZTV_PAYMENT_*` keys. No
     infrastructure at all, but custodial and usually KYC'd. `api/payments.py`
     spells out the trade-off.
   - Webhook URL: `https://<domain>/api/v1/payment/webhook`
2. **Mesh nodes.** Until at least one exists, `/wg/register` returns 503.
   `install.sh --mode node` on each VPS with a token from
   `api/mint-provision-token.py`; `scripts/bootstrap-node.sh` if you want to
   name the node yourself and insert its row by hand.
3. **Backups.** Generate an age key and enable `0trust-backup.timer`
   (`docs/DR.md`).
4. The rest of `docs/LAUNCH.md`: signing keys, warrant canary, legal review.

## Mode 3 — node

Turns a fresh VPS into a RAM-only mesh node and joins it to the mesh. It
installs no control plane: no nginx, no database, no website, no wallet.

| | |
| --- | --- |
| `/etc/wireguard`, `/etc/0trust`, `/var/0trust` | tmpfs — the private key and node PSK are RAM only |
| swap | off, and removed from `/etc/fstab` |
| journald | `Storage=volatile` |
| `0trust-node-enroll.service` | fresh key + registration on **every** boot |
| `0trust-meshd.service` | peer sync, DNAT, heartbeat |
| `/etc/0trust-node.env` | root-only, persistent: the enrolment token |
| dnsmasq | bound to the mesh gateway only, no query log |
| nftables | masquerade + abuse egress filter, reapplied at boot |

Get a token first — dashboard **Nodes → Node enrolment token**, or on the
control plane:

```bash
sudo -u 0trust python3 api/mint-provision-token.py \
     --region zur --role both --uses 20 --ttl 31536000
```

**One-shot vs enrolment token.** `--uses 1` is burned on first registration.
That is fine for a box you will never restart, and wrong for anything else:
the node's disk is RAM, so a reboot loses its key, its id and its PSK, and a
burned token cannot bring it back. The box comes up and never rejoins, while
the control plane keeps handing customers an endpoint whose key no longer
exists. `--uses` above 1 mints a token that pins itself to the node's public
IP on first use and re-registers that same node id afterwards.

That token sits on the node's disk, which is a deliberate trade and the only
0trust file there. It is scoped to one region and role, worthless from any
other address, grants no access to customer data, cannot read another node's
peers, and is revocable from the dashboard. Revoke it if the machine leaves
your control: the node keeps running on the PSK it already holds, and simply
cannot register again.

If the provider changes the node's public IP, the pin stops matching — mint a
new token and re-run the installer.

### What the node does about being noticed

Be precise about this, because it is the area where VPN marketing lies most.
**0trust runs plain WireGuard. It is not obfuscated, and deep packet
inspection identifies it.** WireGuard's handshake is a fixed-size packet with
a constant type byte in a known position; any DPI box worth the name
fingerprints it in one packet, and a national firewall will block it. If you
need to work through that, you need an obfuscation layer that does not exist
here yet — it is on the v0.2 list, and it is a client-side change as much as
a node-side one.

What the node does do:

| | |
| --- | --- |
| `--wg-port 443` | Recommended. UDP 443 is where QUIC lives, so at the netflow level — ports and volumes, no payload — the tunnel looks like ordinary web traffic instead of announcing itself on 51820, WireGuard's registered port. It does not survive DPI, which reads the handshake. It does survive naive port blocking, which is what most restrictive networks actually do. |
| Silence to strangers | WireGuard does not reply to a packet it cannot authenticate — no banner, no error, nothing. A UDP scan of the node cannot distinguish the tunnel port from a closed one. This is WireGuard's design, not ours. |
| Jittered check-in | meshd polls the control plane over its own outbound HTTPS. That used to be every 30.00 seconds forever, which is a shape visible in netflow at the hosting provider without reading a byte. It now varies (`ZTV_POLL_JITTER`, default ±35%). |
| Nothing branded on the wire | The node sets no hostname of its own and serves nothing on any other port. Its firewall allows ssh, the tunnel port, and the multi-hop range; everything else is dropped, not rejected. |
| Constant tunnel chatter | Clients get `PersistentKeepalive = 25`, so tunnel traffic does not idle in a pattern that mirrors what you are doing. Traffic-analysis resistance beyond that is a research problem and we do not claim it. |

```bash
sudo ./scripts/install.sh --mode node \
     --control-url https://0trustvpn.com \
     --region zur --role both --wg-port 443 \
     --provision-token ztvp-...
```

## Verifying a deployment

```bash
curl -fsS https://<domain>/api/v1/health
curl -fsS https://<domain>/api/v1/status/public | jq
curl -fsS https://<domain>/api/v1/regions | jq
systemctl status 0trust-api 0trust-proxy
journalctl -u 0trust-api -n 50
```

A region shows `degraded` when it has entry capacity but no exit, or the other
way round; `down` when it has neither. One healthy node per region reads
`operational` — that is the intended topology, not a warning.

On a test box the mesh is local, so check it too:

```bash
systemctl status '0trust-meshd@*'
wg show                             # three interfaces, peers appear as clients connect
nft list table inet ztv_fwd_wg0     # multi-hop DNAT for zur-01
nft list table inet ztv_nat         # masquerade
nft list table inet ztv_egress      # abuse filter
ss -ulnp | grep 10.64.0.1:53        # the resolver clients are told to use
```

Each node has its **own** nftables table (`ztv_fwd_wg0`, `..._wg1`, `..._wg2`).
They must not share one: meshd replaces its table wholesale on every poll, so
three daemons on one name would erase each other's rules every thirty seconds
and multi-hop would work only for whichever polled last.

`wg show` listing no peers is normal until a client connects. `wg0` not
existing at all means meshd has not completed a poll — check
`journalctl -u 0trust-meshd@wg0`.

## Firewall and ssh

`--no-firewall` skips UFW, for providers that firewall at the edge.
`--no-ssh-hardening` leaves sshd alone. Production hardening only disables
password auth when it can find an `authorized_keys` to fall back on.

## Uninstall

```bash
systemctl disable --now 0trust-api 0trust-proxy 0trust-sweep.timer
systemctl disable --now '0trust-meshd@*'          # test-mode mesh, if present
nft delete table inet ztv_nat    2>/dev/null || true
nft delete table inet ztv_egress 2>/dev/null || true
for i in wg0 wg1 wg2; do nft delete table inet "ztv_fwd_$i" 2>/dev/null || true; done
rm -f /etc/systemd/system/0trust-*.{service,timer}
systemctl daemon-reload
rm -f /etc/nginx/sites-enabled/0trust /etc/nginx/conf.d/0trust-zones.conf
systemctl reload nginx
# /var/lib/0trust holds the account database — back it up before removing it.
```
