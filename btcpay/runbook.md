# BTCPay Server — Operations runbook

This is the playbook for the BTCPay host. It covers initial deployment,
day-to-day operations, and disaster recovery. The 0trust control plane is
deliberately separate — read this alongside `docs/README.md`.

---

## 1. Architecture

```
                                      ┌───────────────────┐
                                      │  Cold wallet      │
                                      │  (Sparrow/Electrum)│
                                      │  Holds BTC keys   │
                                      └─────────┬─────────┘
                                                │ xpub only
                                                ▼
   USER ─────HTTPS────► BTCPay Server ◄──webhook── 0trust control plane
                            │  │                    │
              ┌─────────────┘  │  ┌─────────────────┘
              │                │  │ API key  (read invoices, create invoices)
              ▼                ▼  ▼
        Bitcoin node    Monero node + hot wallet
        (pruned ~50G)   (HAS spend key — sweep regularly)
```

**Two boxes minimum**:
- BTCPay host (this runbook)
- 0trust control plane (separate, lives in `docs/README.md`)

**Funds custody**:
- **Bitcoin**: BTCPay knows the xpub only. It can *see* incoming payments
  and assign addresses but cannot spend. Your cold wallet has the private
  key. This is the safe option.
- **Monero**: BTCPay holds the spend key in `monero-wallet-rpc`. Funds in
  this wallet are hot. **Sweep at least weekly** to a cold address.

---

## 2. Initial deployment

### 2.1 Prerequisites

- Ubuntu 24.04 LTS bare-metal or VPS
- At least 8GB RAM, 4 cores, 200GB disk
  - 50GB pruned Bitcoin
  - ~100GB Monero blockchain
  - 50GB buffer for DB, logs, Docker images
- DNS A record `pay.your-domain.tld` pointing at the box
- A cold-wallet xpub for Bitcoin (generate in Sparrow or Electrum — never on
  this box)
- An age keypair for backups (`age-keygen -o ~/.age/key.txt` on your laptop)

### 2.2 Bootstrap

Two flavors — pick one based on your hardware budget and patience:

**Full** (`bootstrap.sh`) — Full BTC + XMR nodes locally. 200GB disk,
~$30-50/mo VPS, 1-3 days initial sync. Maximum self-sovereignty.

**Lite** (`bootstrap-lite.sh`) — Pruned BTC + remote XMR daemon. 15GB
disk, ~$5-10/mo VPS, 2-3 hours to ready. Trades some Monero query
privacy for not running a 100GB blockchain.

```bash
# On the BTCPay host:
git clone https://your-git/0trust-vpn /opt/0trust-src
cd /opt/0trust-src

# Full deployment:
sudo BTCPAY_HOST=pay.0trustvpn.com \
     LETSENCRYPT_EMAIL=0trustvpn@proton.me \
     ENABLE_MONERO=1 \
     ./btcpay/scripts/bootstrap.sh

# OR Lite deployment:
sudo BTCPAY_HOST=pay.0trustvpn.com \
     LETSENCRYPT_EMAIL=0trustvpn@proton.me \
     ./btcpay/scripts/bootstrap-lite.sh
```

The script:
- Installs Docker via the official BTCPay deployment
- Configures fragments appropriate to the chosen mode
- Sets up nginx reverse-proxy with auto Let's Encrypt
- Hardens firewall (UFW: only 22/80/443 inbound)
- Configures fail2ban for SSH
- Disables public registration on the BTCPay UI
- Caps journald retention to 14 days, 500MB

Expected runtime: 5-20 minutes for the install itself; chain sync time
on top of that depends on mode (see table in `README.md`).

### 2.3 Create the admin account

Browse to `https://pay.0trustvpn.com/Account/Register`.
The **first** account becomes admin. Subsequent registrations are blocked.

Use a password manager, generate a 32-char password, store the password
**and** the URL in a passphrase-protected entry.

### 2.4 Run the configure script

This script never sees your xpub's private key; you paste only the xpub.

**`BTC_XPUB` below is a placeholder, not a key.** It used to be a real
extended public key copied from BTCPay's own documentation, which is a
command somebody eventually pastes whole: every customer payment then
settles into a stranger's wallet, and nothing anywhere reports an error.
Put your own account zpub in, and confirm it before you take money:

```bash
./scripts/check-wallet.sh zpub...    # compare address 0 with your wallet
```

```bash
sudo BTCPAY_HOST=pay.0trustvpn.com \
     BTCPAY_ADMIN_EMAIL=0trustvpn@proton.me \
     BTCPAY_ADMIN_PASSWORD='paste-from-password-manager' \
     BTC_XPUB='PASTE-YOUR-OWN-ACCOUNT-ZPUB-HERE' \
     CONTROL_HOST=0trustvpn.com \
     ./btcpay/scripts/configure.sh
```

The output includes a `/tmp/0trust-btcpay.env` file with the four values
the control plane needs. Move that to the control plane host and merge
into `/etc/0trust/api.env`:

```bash
scp /tmp/0trust-btcpay.env root@0trustvpn.com:/etc/0trust/api.env.btcpay
ssh root@0trustvpn.com 'cat /etc/0trust/api.env.btcpay >> /etc/0trust/api.env \
                    && systemctl restart 0trust-api \
                    && rm /etc/0trust/api.env.btcpay'
```

### 2.5 Smoke test

Wait until the Bitcoin and Monero nodes finish syncing (a few hours to a
few days). Then run the integration test:

```bash
sudo CONTROL_URL=https://0trustvpn.com \
     BTCPAY_URL=https://pay.0trustvpn.com \
     BTCPAY_API_KEY=<admin-key-from-BTCPay-UI> \
     BTCPAY_STORE_ID=<store-id-from-configure-output> \
     ./btcpay/scripts/test-integration.sh
```

This creates a $1 test invoice, marks it settled via the admin API, waits
for the webhook to fire, and confirms the 0trust account flipped to active.
All in ~30 seconds.

---

## 2.5 Lite mode specifics

Skip this section if you ran `bootstrap.sh` (full mode). If you ran
`bootstrap-lite.sh`, the following operational notes apply.

### Picking and rotating the remote Monero daemon

The bootstrap defaults to `node.monerodevs.org:18089`. Other widely-trusted
public nodes (rotate quarterly or whenever one becomes unreliable):

```
node.monerodevs.org:18089       Monero Dev community, donation-supported
xmr-node.cakewallet.com:18081   Cake Wallet team
nodex.monerujo.io:18081         Monerujo wallet team
node.community.rino.io:18081    Rino wallet team
node.sethforprivacy.com:18089   Privacy advocate maintained
```

To swap to a different daemon:

```bash
# Edit the override
sudo sed -i 's|MONERO_DAEMON_ADDRESS:.*|MONERO_DAEMON_ADDRESS: "xmr-node.cakewallet.com:18081"|' \
    /root/btcpayserver-docker/Generated/docker-compose.override.yml
sudo sed -i 's|--daemon-address=.*|--daemon-address=xmr-node.cakewallet.com:18081|' \
    /root/btcpayserver-docker/Generated/docker-compose.override.yml

# Restart the wallet RPC to pick up the change
cd /root/btcpayserver-docker
docker compose -f Generated/docker-compose.generated.yml \
               -f Generated/docker-compose.override.yml \
               restart monero-wallet-rpc
```

### Verifying remote daemon connectivity

If Monero payments aren't being detected, check the wallet RPC's view of
its daemon:

```bash
docker logs --tail 50 monero-wallet-rpc 2>&1 | grep -iE "(daemon|height|error)"
```

Healthy output:
```
Daemon at <host>:<port> is responsive
Wallet height N, Daemon height N
```

Failure modes:
- **"Failed to connect to daemon"** → daemon is down, swap nodes (above)
- **"Wallet height N, Daemon height N+1000+"** → wallet is catching up; wait ~10 min
- **"Untrusted daemon flag"** → expected, we run with `--untrusted-daemon` deliberately

### If the Monero override file ever breaks BTCPay

The `BTCPAY_XMR_*` environment variables in the override target BTCPay's
Monero plugin discovery. Across major BTCPay version bumps these names
sometimes shift. If you upgrade BTCPay and Monero payments start failing:

1. Check BTCPay's logs for "Monero plugin" warnings:
   ```bash
   docker logs --tail 100 $(docker ps -qf name=btcpayserver) 2>&1 | grep -i monero
   ```

2. If env vars need updating, edit
   `/root/btcpayserver-docker/Generated/docker-compose.override.yml`
   and restart with the docker compose command above.

3. **Fallback if all else fails**: switch back to a pruned-but-local
   monerod by re-running `bootstrap.sh` (full) with `PRUNE_BITCOIN=1` —
   you'll need ~50GB more disk but skip the override entirely.

### Bitcoin pruning at extra-small size

Lite mode uses `opt-save-storage-xs` which keeps Bitcoin to ~5-15GB. This
is enough for invoice settlement (we only need the recent UTXO set and
fee estimation) but means you cannot serve arbitrary historical block
data. That's fine for a payment processor — you'd never want to anyway.

If you need to look up an old transaction, use a public block explorer
(mempool.space, blockstream.info) rather than your own node.

### Storage budget summary (lite)

```
$ df -h /var/lib/docker
≈ 12-18GB used after sync settles
```

If your VPS has 20GB total disk, that's tight but workable. 40GB+ gives
headroom for logs, BTCPay updates, and the occasional surprise.

---

### 2.6 Enable backups

On the BTCPay host:

```bash
# Generate an age key on your LAPTOP (not the BTCPay host)
age-keygen -o ~/.age/btcpay-backup.key
# Note the public key (age1...)

# On the BTCPay host:
sudo install -m 0640 \
    /opt/0trust-src/btcpay/docker/btcpay-backup.env.example \
    /etc/0trust/btcpay-backup.env
sudoedit /etc/0trust/btcpay-backup.env
# → paste your age public key into BACKUP_AGE_RECIPIENT

sudo install -m 0644 \
    /opt/0trust-src/btcpay/systemd/btcpay-backup.{service,timer} \
    /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now btcpay-backup.timer

# Confirm it ran
sudo systemctl list-timers btcpay-backup
sudo systemctl status btcpay-backup.service
```

---

## 3. Day-2 operations

### 3.1 Sweep the Monero hot wallet

Monero is the highest-risk component because the hot wallet's spend key
lives on the BTCPay box. **Set a calendar reminder to sweep weekly.**

```bash
# Open monero-wallet-cli inside the container
sudo /root/btcpayserver-docker/monero-wallet-cli.sh

# Inside the wallet REPL:
> balance
# Wait for confirmed balance to settle (10 confirmations = ~20min)
> transfer <your_cold_address> <amount>
# Leave a small float (~0.1 XMR) for fees
> exit
```

For Bitcoin you don't need to do anything — payments deposit into your
cold wallet's addresses directly because BTCPay only watches the xpub.

### 3.2 Check chain sync health

Cron a check that catches a stalled node before customers do:

```bash
# Quick sync sanity check
sudo /root/btcpayserver-docker/bitcoin-cli.sh getblockchaininfo \
    | jq '{blocks, headers, ibd: .initialblockdownload}'

sudo /root/btcpayserver-docker/monero-cli.sh status
```

In both cases, `blocks` should be within 6 of `headers` once IBD is
complete. If a node falls behind, customers' invoices show payment
errors. Restart the affected container:

```bash
cd /root/btcpayserver-docker
docker compose restart btcpayserver bitcoind   # or monerod
```

### 3.3 Updates

BTCPay ships regular updates. Apply them with their own script (which our
bootstrap script also wraps):

```bash
cd /root/btcpayserver-docker
sudo ./btcpay-update.sh
```

**Important**: BTCPay updates can occasionally break the Greenfield API
schema. After every update, re-run `test-integration.sh` to confirm the
0trust control plane is still happy.

### 3.4 Reviewing webhook delivery

If 0trust accounts aren't activating after payment, the chain is usually:
invoice settles → BTCPay queues webhook → webhook hits 0trust → 0trust
updates DB. Each step can fail.

BTCPay's webhook delivery log is at:
```
https://pay.0trustvpn.com/stores/<store-id>/webhooks
```

Each delivery shows the response status and headers. The 0trust webhook
endpoint should return `200 OK`; anything else means BTCPay will retry
on its own (configured with `automaticRedelivery: true`).

On the control plane side:
```bash
sudo journalctl -u 0trust-api -f | grep -i webhook
```

### 3.5 Adding more payment methods later

Configure script enables only BTC + XMR. To add Lightning, ETH, or LTC
later: bring up the relevant BTCPay fragment, then re-run `configure.sh`
(it's idempotent and just enables anything new it sees).

---

## 4. Disaster recovery

### 4.1 What's actually at risk if the BTCPay box dies

| Loss | Severity | Recovery |
|------|----------|----------|
| Bitcoin keys | NONE | Cold wallet (off-host) holds them |
| Monero hot wallet | TOTAL of in-flight balance | Restore from encrypted backup |
| Invoice history | LOW | Customers' subscriptions on 0trust unaffected; only refund-window data lost |
| Store config | LOW | Re-run `configure.sh` (it's idempotent) |
| Bitcoin blockchain (full mode) | NONE | Re-sync in ~1 day via fastsync |
| Bitcoin blockchain (lite mode) | NONE | Re-sync in ~2h via fastsync |
| Monero blockchain (full mode) | NONE | Re-sync in ~3 days |
| Monero blockchain (lite mode) | N/A | Lives on remote daemon |

The only catastrophic loss is **Monero wallet without a recent backup**.
That's why backups exist and why the operator should sweep weekly.

**Lite mode bonus**: the smaller Bitcoin footprint and zero local Monero
chain means recovery from a destroyed host is faster — Bitcoin fastsync
+ remote-daemon Monero means you're back online within hours, not days,
once the wallet backup is restored.

### 4.2 Restoring on a fresh host

```bash
# 1. On the new host, do steps 2.1–2.2 above (bootstrap + create admin)
sudo BTCPAY_HOST=pay.0trustvpn.com LETSENCRYPT_EMAIL=0trustvpn@proton.me \
     ./btcpay/scripts/bootstrap.sh

# 2. Stop BTCPay so we can restore over its volumes
cd /root/btcpayserver-docker
docker compose stop

# 3. Pull the most recent backup from off-host storage
rclone copy remote:backups/btcpay/btcpay-2026-05-23.tar.gz.age /tmp/

# 4. Decrypt + extract
age -d -i ~/.age/btcpay-backup.key < /tmp/btcpay-2026-05-23.tar.gz.age \
    | tar -xz -C /tmp/restore/

# 5. Restore PostgreSQL
docker compose up -d postgres
sleep 5
docker exec -i $(docker ps --format '{{.Names}}' | grep postgres) \
    psql -U postgres < /tmp/restore/postgres.sql

# 6. Restore Monero wallet
XMR_VOLUME=$(docker volume ls -q | grep -E '(monero|wallet)' | head -1)
docker run --rm \
    -v "$XMR_VOLUME:/data" \
    -v /tmp/restore:/restore \
    alpine \
    tar -xzf /restore/monero-wallet.tar.gz -C /data

# 7. Restore Let's Encrypt (optional — LE will re-issue if missing)
LE_VOLUME=$(docker volume ls -q | grep letsencrypt | head -1)
docker run --rm \
    -v "$LE_VOLUME:/data" \
    -v /tmp/restore:/restore \
    alpine \
    tar -xzf /restore/letsencrypt.tar.gz -C /data

# 8. Bring everything up
docker compose up -d

# 9. Verify
./btcpay/scripts/test-integration.sh
```

### 4.3 If the BTCPay HOST IP changes

BTCPay binds to the hostname (`BTCPAY_HOST`), not the IP, so internal
config is fine. But the 0trust webhook URL on the BTCPay side is fixed.
Re-run `configure.sh` on the new BTCPay host and update the control plane's
`/etc/0trust/api.env` with the new values.

### 4.4 If the operator forgets the admin password

Reset via the BTCPay docker tooling:

```bash
cd /root/btcpayserver-docker
sudo ./btcpay-admin.sh resetpassword 0trustvpn@proton.me
# Prints a new temporary password
```

---

## 5. Security notes specific to this deployment

- **Bitcoin keys never live on this box.** Confirmed by the absence of
  any private-key file under `/var/lib/docker/volumes/generated_bitcoin_*`.
  Auditor can verify with:
  ```bash
  docker exec $(docker ps -qf name=bitcoind) ls /data/.bitcoin/wallets
  # Should be empty or only contain watching-only wallets
  ```

- **Monero keys DO live on this box.** That's why the wallet must be
  swept regularly and the backup must be encrypted off-host. An adversary
  who exfiltrates `monero-wallet.tar.gz` plaintext owns whatever balance
  is in that wallet at the moment of theft.

- **The control plane never sees a customer's wallet address.** It only
  receives the invoice ID, amount, and `Settled`/`Invalid`/`Expired` event.
  Confirmed in `api/main.py:btcpay_webhook()`.

- **API key scope**: the production key minted by `configure.sh` is
  restricted to one store and three permissions (view invoices, create
  invoices, view store settings). It cannot create new stores, modify
  payment methods, or extract API keys.

- **Webhook signature**: every webhook delivery is HMAC-SHA256 signed
  with `BTCPAY_WEBHOOK_SECRET`. The control plane drops requests with
  invalid signatures. The secret is 256 bits of entropy.

- **fail2ban** is only configured for SSH. The BTCPay UI's own brute-force
  protection handles login attempts.

---

## 6. Useful commands cheat-sheet

```bash
# BTCPay admin
cd /root/btcpayserver-docker
./btcpay-update.sh                     # Update BTCPay
./btcpay-restart.sh                    # Restart everything
./btcpay-down.sh && ./btcpay-up.sh     # Full down/up cycle

# Inspect Bitcoin node
./bitcoin-cli.sh getblockchaininfo     # sync status
./bitcoin-cli.sh getbalance "*" 0      # should always be 0 (watching-only)

# Inspect Monero node
./monero-cli.sh status                 # sync status
./monero-wallet-cli.sh                 # interactive wallet REPL

# Inspect 0trust integration
journalctl -u 0trust-api -f | grep btcpay   # webhook activity on control plane
curl -sS https://pay.0trustvpn.com/api/v1/health  # BTCPay liveness
```
