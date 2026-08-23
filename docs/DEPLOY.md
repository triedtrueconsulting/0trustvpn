# Deploying on a fresh Ubuntu 24.04 VPS

One script, two modes. Both are idempotent — re-run to pick up new code or to
repair a half-finished run.

```bash
git clone <your-repo> /opt/0trust-src
cd /opt/0trust-src

# 1. Kick the tyres: no domain, no TLS, serves on the box's IP
sudo ./scripts/install.sh --mode test

# 2. Real deployment: domain + Let's Encrypt
sudo ./scripts/install.sh --mode production \
     --domain 0trustvpn.com --email you@example.com
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

Secrets are generated once. A re-run never rotates them — rotating
`NODE_API_PSK` would lock out every mesh node, and rotating
`ZTV_TRIAL_SECRET` would invalidate every challenge in flight. A re-run does
add any config keys your `api.env` predates, leaving your edits alone.

## Mode 1 — test

For seeing the thing work. It:

- serves plain HTTP on port 80 on the box's IP, no domain needed;
- seeds `zur-01`, `rey-01`, `buc-01` so `/api/v1/regions` and the trial flow
  work immediately;
- leaves ssh alone, because locking password auth on a box you are holding
  open with a password is how you lose the box.

Then:

```bash
export ZTV_API_BASE=http://<ip>
0trust login          # or visit http://<ip>/trial for a free trial
```

**It is a test box, and the installer says so in its closing output:**

- **No TLS.** Account tokens cross the network in clear. Do not put a customer
  on it, and do not reuse a token you created here on the real deployment.
- The three seeded nodes are **placeholder rows, not WireGuard peers**.
  `0trust connect` returns a config that cannot carry traffic. Run
  `scripts/bootstrap-node.sh` on a real node to change that.
- Payments are unconfigured, so `POST /api/v1/account` returns 502. Free
  trials work, because they need no payment provider.

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
   `scripts/bootstrap-node.sh` for static nodes, or
   `api/mint-provision-token.py` for RAM-only ephemeral ones.
3. **Backups.** Generate an age key and enable `0trust-backup.timer`
   (`docs/DR.md`).
4. The rest of `docs/LAUNCH.md`: signing keys, warrant canary, legal review.

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

## Firewall and ssh

`--no-firewall` skips UFW, for providers that firewall at the edge.
`--no-ssh-hardening` leaves sshd alone. Production hardening only disables
password auth when it can find an `authorized_keys` to fall back on.

## Uninstall

```bash
systemctl disable --now 0trust-api 0trust-proxy 0trust-sweep.timer
rm -f /etc/systemd/system/0trust-*.{service,timer}
systemctl daemon-reload
rm -f /etc/nginx/sites-enabled/0trust /etc/nginx/conf.d/0trust-zones.conf
systemctl reload nginx
# /var/lib/0trust holds the account database — back it up before removing it.
```
