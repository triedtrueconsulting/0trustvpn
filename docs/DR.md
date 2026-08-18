# Disaster recovery procedures

What to do when something is on fire. Each scenario lists the **time to
recover** so you know what slippage looks like, and the **practice frequency**
because a procedure you've never run is barely better than no procedure.

---

## Scenario 1 — Control plane host destroyed

**Impact:** No new signups, no `/account/status`, no device registration. Existing tunnels keep working (mesh nodes pull peers cached from last sync).

**Time to recover:** 30-60 minutes if backups are tested, 4+ hours if not.

**Procedure:**

```bash
# 1. Provision a fresh Ubuntu 24.04 VPS
# 2. Point DNS for 0trustvpn.com at the new host (TTL <300 helps here)
# 3. Bootstrap as usual
git clone https://github.com/0trust/cli /opt/0trust-src
sudo /opt/0trust-src/scripts/bootstrap.sh

# 4. Stop the API service while we restore the DB
sudo systemctl stop 0trust-api

# 5. Decrypt the most recent backup
sudo age -d -i /root/.age/0trust-backup.key \
              /path/to/0trust-<ts>.db.age \
              > /var/lib/0trust/0trust.db
sudo chown 0trust:0trust /var/lib/0trust/0trust.db
sudo chmod 600 /var/lib/0trust/0trust.db

# 6. Restore api.env (BTCPay key, node PSK, etc).
#    Keep an encrypted copy of /etc/0trust/api.env off-host alongside the DB.
sudo age -d -i /root/.age/0trust-backup.key \
              /path/to/api.env.age \
              > /etc/0trust/api.env
sudo chmod 600 /etc/0trust/api.env

# 7. Start
sudo systemctl start 0trust-api
sudo systemctl status 0trust-api
curl -fsS https://0trustvpn.com/api/v1/health
```

**Verification:** customers can log in (`0trust login <known-token>` against the new host), `/status` page loads, `/api/v1/regions` returns the three regions.

**Practice frequency:** quarterly. Add to the LAUNCH.md recurring tasks.

---

## Scenario 2 — A mesh node is destroyed or compromised

**Impact:** That region appears as `down` on `/status`; customers connected to it get routed elsewhere on next rotation.

**Time to recover:** 15 minutes — provision a new VPS and bootstrap.

**Procedure:**

```bash
# 1. Mark the dead node inactive in the control plane (control plane host)
sudo sqlite3 /var/lib/0trust/0trust.db \
    "UPDATE mesh_nodes SET active = 0 WHERE id = 'zur-01'"

# 2. Provision a replacement
sudo NODE_API_PSK=<from /etc/0trust/api.env> \
     NODE_REGION=zur \
     NODE_ROLE=both \
     CONTROL_URL=https://0trustvpn.com \
     /opt/0trust-src/scripts/bootstrap-node.sh

# 3. Verify
curl -fsS https://0trustvpn.com/api/v1/status/public | jq
```

**If the node was COMPROMISED** (not just dead), additionally:
- Rotate the global `NODE_API_PSK` and redeploy all nodes
- Re-sign the warrant canary with an explicit note in the operator commentary section
- Notify customers via Mastodon/Bluesky and on the status page

**Practice frequency:** monthly. Tear down a node and rebuild it as part of the monthly maintenance cycle.

---

## Scenario 3 — BTCPay host destroyed

**Impact:** No new signups possible. Existing customers still connect (their accounts are in the control plane DB, independent of BTCPay).

**Time to recover:** 4-6 hours if BTC fastsync is needed; 1-2 hours if you have a pre-synced backup snapshot.

**Procedure:**

```bash
# 1. Provision a fresh VPS for BTCPay
# 2. DNS: point pay.0trustvpn.com at the new host
# 3. Re-bootstrap
sudo BTCPAY_HOST=pay.0trustvpn.com \
     LETSENCRYPT_EMAIL=0trustvpn@proton.me \
     /opt/0trust-src/btcpay/scripts/bootstrap-lite.sh

# 4. Restore BTCPay state from off-host backup
#    (btcpay/runbook.md §6 has the dr procedure with the exact commands)

# 5. Re-run configure.sh against the SAME xpub
sudo BTCPAY_HOST=pay.0trustvpn.com \
     BTCPAY_ADMIN_EMAIL='0trustvpn@proton.me' \
     BTCPAY_ADMIN_PASSWORD=<from password manager> \
     BTC_XPUB='<your zpub>' \
     CONTROL_HOST=0trustvpn.com \
     /opt/0trust-src/btcpay/scripts/configure.sh

# 6. Update /etc/0trust/api.env on the control plane with the new
#    BTCPAY_WEBHOOK_SECRET (configure.sh emits it). Restart 0trust-api.

# 7. Smoke test
sudo /opt/0trust-src/btcpay/scripts/test-integration.sh
```

**Note:** because you used the same xpub, all customer wallets continue to derive deterministic addresses — no money is lost. The btcpay db restore is what recovers in-flight invoice state.

**Practice frequency:** quarterly. Standing up a parallel BTCPay test instance and restoring into it counts.

---

## Scenario 4 — Domain seized / DNS hijacked

**Impact:** Customers' DNS lookups fail or return wrong IPs. Existing tunnels keep working (the client cached the control plane URL when last used) but new signups + status fetches break.

**Time to recover:** depends on registrar, but **the .onion mirror keeps working** through this exactly because it's not DNS-dependent.

**Procedure:**

1. Announce the situation on Mastodon / Bluesky / Nostr from your operator accounts
2. Direct customers to the `.onion` address (it's published in the canary)
3. Restore DNS via your registrar — they're the gatekeeper, and Njalla (recommended in LAUNCH.md) is reasonable about this
4. If the registrar is the problem (seizure / pressure), prepare to migrate to a backup domain you registered as a contingency

**Pre-launch hardening:** register a backup domain at a different registrar (e.g., `0trust.vpn` itself, or `zerotrustvpn.com`). Keep DNS pointing at the same control plane. This protects against single-registrar pressure.

---

## Scenario 5 — Lost signing key (PGP)

**Impact:** Can't sign releases or canary. Existing canary entries remain valid; absence of new ones will trigger the freshness alarm within a week.

**Procedure:**

1. Stop using the old key immediately
2. Generate a new release key
3. Issue a **key transition statement** signed by the OLD key (if it's only suspected-compromised, not destroyed) OR sign one with a backup operator key (if you have one)
4. Publish the transition statement at:
   - `https://0trustvpn.com/.well-known/security.txt`
   - In the next warrant canary
   - On Mastodon/Bluesky
   - On `keys.openpgp.org` as a revocation certificate
5. Re-sign and re-publish the most recent canary with the new key
6. Update `EXPECTED_KEY` in `scripts/verify-release.sh` and cut a new release

**Pre-launch hardening:** generate a revocation certificate for each PGP key at the time you create it (`gpg --gen-revoke <fpr> > revoke.asc`). Store it off-host, age-encrypted. This is what you publish if the key is destroyed (not just suspected-compromised).

---

## Scenario 6 — Mass abuse complaints

**Impact:** Hosting provider threatens to terminate. See `docs/ABUSE.md` for the prevention and response procedure. If termination happens, treat as Scenario 2.

---

## What to keep off-host

The minimum recovery set, age-encrypted to a key on your hardened
workstation (NOT on any production host):

- `/etc/0trust/api.env` (BTCPay key, NODE_API_PSK, BTCPay webhook secret)
- Daily SQLite backup (`0trust-<ts>.db.age` — produced by `scripts/backup.sh`)
- The xpub recovery seed (paper, 2 locations) — recovers wallet
- BTCPay backups (per `btcpay/runbook.md`)
- Tor onion private key (`/var/lib/tor/0trust-hs/hs_ed25519_secret_key`)
- PGP private keys + revocation certs for: release key, support key

Test that you can decrypt all of these on a fresh workstation **at least
twice a year**. A backup you can't restore from is a non-backup.

## Practice cadence

| Scenario | Practice |
|----------|----------|
| Control plane restore | Quarterly |
| Mesh node replacement | Monthly (rotate one as part of routine) |
| BTCPay restore       | Quarterly |
| Domain failover      | Annually + as part of any registrar change |
| Key rotation         | Annually (keys themselves last 2y) |
| Off-host backup decrypt | Twice yearly on a clean workstation |

Put these on the recurring calendar. The first time you need them, the
practice is what gets you back online before customers notice.
