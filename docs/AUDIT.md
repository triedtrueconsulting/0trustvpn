# 0trust VPN — No-Logs Audit Pack

Document version: 0.1.0
Last revised: 2026-05-24
Intended audience: independent security auditors (Cure53, Assured AB,
                   Cure53, KPMG Cyber, internal counsel)

---

## 1. Purpose of this document

This is the operational evidence pack that backs 0trust's public no-logs
claim. It enumerates **every place** the system touches customer data,
**what** that data is, **where** it's stored, **for how long**, and **how
an auditor can verify** that the implementation matches this document.

Nothing in this pack should be a surprise relative to what's on the
landing page. If it is, the landing page is wrong.

---

## 2. Definitions

| Term | Meaning |
|------|---------|
| **Customer data** | Anything an outsider could use to identify a specific human or correlate their behavior. Includes (but isn't limited to) names, emails, IP addresses, device names, payment trails, traffic destinations. |
| **Operational data** | Information needed to keep the service running: node health, peer manifests, capacity counters. Operational data MAY be retained when it cannot be tied back to a specific customer. |
| **Logs** | Any record of activity persisted beyond the moment it occurs. Includes access logs, application logs, database writes, syslog. |
| **Ephemeral** | RAM-only; gone on process or host restart. |

---

## 2.5 Server jurisdictions

The 0trust mesh runs exactly three nodes, in three countries:

| Code | City | Country | Outside Five/Nine/Fourteen Eyes |
|------|------|---------|---------------------------------|
| `zur` | Zurich | Switzerland | YES |
| `rey` | Reykjavik | Iceland | YES |
| `buc` | Bucharest | Romania | YES |

All three are outside every iteration of the Anglosphere intelligence-
sharing alliances (Five, Nine, and Fourteen Eyes). The operator has
committed publicly (see `https://0trustvpn.com/`) to NOT deploying
servers in any Eyes jurisdiction — including the United States, United
Kingdom, Canada, Australia, New Zealand (Five), Denmark, France,
Netherlands, Norway (Nine), Germany, Belgium, Italy, Spain, Sweden
(Fourteen).

This is a meaningful but not complete privacy property. Specifically:

1. **What it gives you**: customer traffic is not subject to bulk
   collection or routine peer-sharing among the Eyes signatories.
   Individual legal requests via MLAT still exist, but they are slower,
   more visible, and judicially reviewed in each step.
2. **What it does NOT give you**: protection from a sufficiently
   motivated nation-state adversary willing to compromise infrastructure
   without legal process. The RAM-only ephemeral node design (§5.3
   below) is the operational mitigation for that threat.
3. **Country-specific legal regimes (auditor should verify these
   remain current)**:
   - Switzerland: constitutional right to telecom privacy (Art. 13);
     revised Federal Act on Data Protection (revFADP) effective Sept 2023;
     no general data-retention mandate; surveillance limited by BÜPF.
   - Iceland: no general data-retention regime for ISPs/hosts; strong
     source-protection law (Act 38/2011); IMMI initiative baseline.
   - Romania: Constitutional Court Decision 440/2014 struck down EU
     Data Retention Directive transposition; no general comms-data
     retention currently in force; long-established privacy-VPN
     industry presence.

Auditor: verify that the IP addresses returned by
`POST /api/v1/wg/register` actually geolocate to these three countries
and only to these three. The mesh-node table in the control-plane
database should contain only `zur`, `rey`, and `buc` regions; any other
region code is a regression.

---

## 3. Data we collect (and do not collect)

### 3.1 At signup

| Field | Stored? | Where | Retention | Justification |
|-------|---------|-------|-----------|---------------|
| Email address | NO | — | — | Not requested anywhere in the flow |
| Phone number | NO | — | — | Not requested |
| Real name | NO | — | — | Not requested |
| IP address | NO* | — | — | See §4 (nginx logs) |
| User-Agent | NO* | — | — | See §4 |
| Account token (hash) | YES | `accounts.token_hash` | Lifetime of subscription | Sole credential |
| Subscription expiry | YES | `accounts.expires_at` | Lifetime of subscription | Required to enforce duration |
| Account status | YES | `accounts.status` | Lifetime of subscription | active / expired / banned |

(* nginx records anonymized IPs in /29 buckets with no User-Agent. See §4.)

### 3.2 At payment

Payment processing happens at whichever provider the operator has configured
(`ZTV_PAYMENT_PROVIDER`). The control plane never sees a wallet address,
transaction ID or coin choice — only that an invoice settled.

**Which provider is configured changes what an auditor should conclude here,
and it is the first thing to check:**

| Provider | Custody | What a third party learns |
|---|---|---|
| `btcpay` | non-custodial, funds go to the operator's wallet | whoever hosts the BTCPay instance sees the addresses |
| `hosted` | custodial, usually KYC'd | the gateway holds the funds and its own records |
| `stripe` / `square` | custodial card rails | **the processor holds the customer's real identity** |

The last row is a genuine break in the no-identity property, not a nuance. A
customer who pays by card is identified to the processor, and that record
links a person to a VPN subscription. It is disclosed on web/privacy.html
§4a in those words. An auditor should confirm the card option is either
disabled or disclosed, and should treat a deployment that accepts cards while
advertising anonymity as non-compliant with its own claims.

| Field | Stored? | Where | Retention | Justification |
|-------|---------|-------|-----------|---------------|
| Crypto wallet address | NO | BTCPay only | BTCPay retention | Not exposed to control plane |
| TX ID | NO | BTCPay only | BTCPay retention | Not exposed to control plane |
| Invoice ID | YES | `invoices.id` | 30 days after Settled, deleted with the account | Required to honor refunds during dispute window |
| Amount (USD) | YES | `invoices.amount_usd` | Same as invoice ID | Required for refund processing |
| Months purchased | YES | `invoices.months` | Same | Required to compute expiry |

### 3.3 At connect

| Field | Stored? | Where | Retention | Justification |
|-------|---------|-------|-----------|---------------|
| Customer device pubkey | YES | `devices.pubkey` | Until customer removes device or account expires | Required for WireGuard peering |
| Customer device name | YES | `devices.device_name` | Same | Customer-provided label for their own devices |
| Mesh IP allocation | YES | `devices.mesh_ip` | Same | Required to route packets to their device |
| Customer private key | **NO** | Customer's device only | — | Never generated server-side, never transmitted |
| Customer's real IP | NO | — | — | See §4 |
| Destination IPs of customer traffic | NO | — | — | See §5 |
| Bandwidth counters | NO | — | — | Deliberately disabled in WireGuard config |
| Connection start/end times | NO | — | — | Not recorded anywhere |

### 3.4 At multi-hop session

| Field | Stored? | Where | Retention | Justification |
|-------|---------|-------|-----------|---------------|
| Entry node ID | YES | `hop_pairs.entry_node` | 24h (auto-rotated) | Required to allocate UDP port |
| Exit node ID | YES | `hop_pairs.exit_node` | 24h | Required to route packets |
| Allocated UDP port | YES | `hop_pairs.entry_port` | 24h | Required for nftables DNAT |
| Customer's traffic content | NO | — | — | Entry node literally cannot decrypt (WG is e2e to exit) |
| Customer's traffic destinations | NO | — | — | Exit decrypts but does not log |

### 3.5 At payment settlement (webhook)

When BTCPay POSTs to `/api/v1/payment/webhook`, the system marks the
account active and extends `expires_at`. **No metadata about the payment
itself is persisted** beyond fields enumerated in §3.2.

---

## 4. Web-tier logs (nginx)

The nginx access log is the most likely place for accidental data
retention. Its current configuration:

```
log_format anon '$remote_addr_anon - [$time_local] "$request_method $uri" '
                '$status $body_bytes_sent';

access_log /var/log/nginx/0trust-access.log anon buffer=32k flush=5s;
```

Where `$remote_addr_anon` strips the last octet from IPv4 and the host
portion of IPv6, producing a /24 or /48 bucket respectively. The
User-Agent header is **deliberately omitted** from the log format —
client fingerprinting is the main re-identification vector against
anonymized IPs.

### 4.1 What's NOT in the access log

- Full client IPs
- User-Agent strings
- Referrer headers
- Cookies (we don't set any)
- Querystring contents
- Request body contents
- Response body contents

### 4.2 Retention

`logrotate.d/0trust` rotates the file daily and **keeps two days** with
gzip compression. Anything older is gone. Auditor verification:

```bash
ls -la /var/log/nginx/0trust-access.log*
# Expect: current file + at most 2 .gz rotations
```

### 4.3 Why not zero retention?

Two days of anonymized access logs help with:

1. **DDoS forensics** — abuse traffic patterns at /24 granularity
2. **Production incident triage** — "did we serve any 5xx in the last hour?"

A /24-anonymized record is one of 4.3 million possible /24s globally; an
auditor should confirm whether this is appropriate for the threat model.
Zero retention is also a defensible option; the operator chose 2 days as
a compromise.

---

## 5. WireGuard mesh-node logs

### 5.1 Exit nodes

Exit nodes terminate WireGuard tunnels and NAT outbound traffic. They are
the only nodes that ever see plaintext destination IPs. By default
WireGuard's kernel module does not log packet contents or destinations.
The mesh-node syncer (`0trust-meshd`) logs only its own sync events
(peer-list refreshes), not customer traffic.

Verification:

```bash
# On any exit node:
journalctl -u 0trust-meshd | head -100
# Expect: lines like "synced 47 peers to wg0"
# Should NOT see: customer IPs, destination IPs, packet counts

# Confirm WG packet counters aren't being polled and stored anywhere:
grep -r "wg show" /opt /etc /var/lib 2>/dev/null
# Expect: only in the syncer's own status check, never written to disk

# Confirm nftables logging is OFF
nft list ruleset | grep -i log
# Expect: empty
```

### 5.2 Entry nodes

Entry nodes only DNAT UDP packets — they decrypt nothing. They log only
the `meshd` sync events. Same verification as exit nodes.

### 5.3 RAM-only ephemeral nodes

When deployed via `cloud-init-ephemeral.yaml`, the entire `/etc/wireguard`,
`/etc/0trust`, and `/var/0trust` paths are `tmpfs` mounts. journald is
configured `Storage=volatile` so even system logs are RAM-only. On reboot,
everything is wiped.

Verification on an ephemeral node:

```bash
mount | grep -E "(tmpfs.*(0trust|wireguard))"
# Expect: 3 tmpfs entries

grep Storage /etc/systemd/journald.conf.d/*.conf
# Expect: Storage=volatile

swapon --show
# Expect: empty (no swap = no chance of paging private keys to disk)
```

---

## 6. Control-plane database (SQLite)

The full schema is in `api/main.py`. Tables and their content:

| Table | Customer-identifying content? | Retention |
|-------|-------------------------------|-----------|
| `accounts` | Token hash, plan, expiry | Lifetime of subscription; unpaid signups deleted after 7 days |
| `devices` | Pubkey + customer label | Until removed or account expired 7+ days |
| `invoices` | Amount, status, checkout URL | Account lifetime; failed invoices GC'd after 30 days |
| `hop_pairs` | Entry/exit node refs, port | 24h auto-rotation |
| `mesh_nodes` | Node ID, pubkey, public IP | Persistent for static nodes; ephemeral nodes pruned 1h after last heartbeat |
| `provision_tokens` | Token hash + region/role | Burned on use; row deleted 24h after that |
| `trial_grants` | A random nonce we generated | 24h — long enough that a solved stamp cannot be reused, then gone |
| `device_nodes` | Which nodes may see a device's pubkey | Rewritten on every connect; deleted with the device |

Two of these deserve a note, because "we keep the minimum" only means
something if abandoned data actually leaves.

**Unpaid signups.** `POST /api/v1/account` cannot require authentication —
there is no account yet — so an abandoned checkout leaves a `pending_payment`
row behind. The sweeper deletes those after 7 days, but only when no settled
invoice points at them, so a slow payer is never caught by it. Before this
existed the table grew forever, which contradicted the retention claim above.

**Trial nonces.** `trial_grants` holds nothing about the person: the nonce is
random, generated by us, and never derived from the browser, the address, or
anything else. It exists only so one solved proof-of-work cannot mint a
second account. Redemption already rejects an expired challenge, so the row
stops being load-bearing once the challenge lapses; the sweeper drops it after
24 hours.

Auditor checks:

```bash
sudo sqlite3 /var/lib/0trust/0trust.db <<'SQL'
.schema
-- Confirm there's no plaintext token column anywhere:
.tables
SELECT sql FROM sqlite_master WHERE sql LIKE '%token%' AND sql NOT LIKE '%token_hash%';
-- Expect: only token_hash columns, no plaintext token columns.
SQL
```

---

## 7. Application logs (FastAPI / journald)

The API logs to journald via systemd. Configured retention:
`/etc/systemd/journald.conf` → `MaxRetentionSec=7day`.

What gets logged:

- **Uvicorn access lines** are disabled (`--no-access-log` would be
  cleaner — currently filtered out at the log-format level).
- **FastAPI route exceptions** include the route path but not request
  bodies. Stack traces never include token values because the auth
  dependency hashes tokens before they hit any logger.
- **DB integrity errors** could conceivably leak a row's content; the
  control plane wraps DB calls in narrow try/except blocks to prevent
  this. See `api/main.py` lines [TODO]–[TODO].

Auditor verification:

```bash
journalctl -u 0trust-api --since "1 hour ago" | grep -iE "(token|pubkey|secret)"
# Expect: empty
```

---

## 8. Backups

The control-plane SQLite database **is** backed up — encrypted, off-host,
on a nightly schedule (`scripts/backup.sh` → `age`-encrypted, pushed
off-site). This is an operational necessity: the database is the only
record that a given (hashed) token has paid through a given expiry date.
Without backups, losing the host would forfeit every customer's paid
subscription with no way to restore it — the token alone cannot rebuild
the expiry date or device records.

**Crucially, backing up this database does not weaken the no-logs claim,
because of what the database does and does not contain:**

What the backup contains (all already-retained operational data, §3 and §6):
- SHA-256 **hashes** of account tokens (never the tokens themselves)
- Device WireGuard **public** keys and assigned mesh IPs
- Subscription expiry dates
- Invoice IDs + USD amounts (already retained ~30 days for refunds)
- Mesh-node inventory (region, role, public key)

What the backup does NOT and CANNOT contain — because it is never
collected anywhere in the system:
- Real client IP addresses
- Traffic destinations or contents
- Connection/disconnection times or session durations
- Bandwidth counters
- Any data that could deanonymize a customer

In other words: the backup extends the durability of data we already
retain and disclose (§3), not the *scope* of what we retain. A seized or
leaked backup reveals the same thing a seized live database would — which
tokens exist (as hashes) and which pubkeys are provisioned — and nothing
about anyone's activity.

Backup security properties:
- Encrypted at rest with `age` to operator-held recipient key(s); the
  cleartext snapshot is shredded immediately after encryption
- Stored off the control-plane host (the host that has the data shouldn't
  be the only host that has the backup)
- Rotated: 7 daily, 4 weekly, 12 monthly
- Restore procedure documented and practiced quarterly (`docs/DR.md`)

Out of scope of 0trust's claim:
- BTCPay's own database is backed up per BTCPay's defaults; payment data
  governance is documented separately in `btcpay/runbook.md`.

**Auditor note:** verify that `scripts/backup.sh` encrypts before writing
anywhere persistent (it should `age` then `shred` the plaintext) and that
the backup contains no columns beyond those enumerated in §3. The schema
is fixed; a backup cannot contain data the schema doesn't store.

---

## 9. Third-party services and data flows

| Service | Hosted by | What it sees |
|---------|-----------|--------------|
| BTCPay Server | 0trust (separate host) | Crypto addresses, TX IDs, USD amounts. Sends webhook to control plane on settle. |
| Let's Encrypt | LE / EFF | The domain `0trustvpn.com`. No customer data. |
| DNS provider | (operator's choice) | DNS queries for `0trustvpn.com`. No customer data. |
| Hosting provider | (operator's choice) | Network metadata visible at the IP layer; no application data. |
| cdnjs.cloudflare.com | n/a | RESOLVED — the landing page now self-hosts vendored JS from `/vendor/`. See `scripts/vendor-third-party.sh`. |

---

## 10. Verification script

`scripts/audit-verify.sh` runs the full check matrix against a live
production host. It exits non-zero if any verification fails.

```bash
sudo ./scripts/audit-verify.sh
```

Each check has a short name; run with `-v` to see the underlying command.

---

## 11. Known limitations the auditor should call out

The operator is required to declare these proactively:

1. **Nginx retains 2 days of /24-bucketed access logs.** Defensible but
   not zero. Auditor may recommend cutting to zero.
2. **The systemd journal default retention is 7 days.** Apart from
   ephemeral nodes (where it's volatile), control-plane logs persist 7
   days, including any operational error messages.
3. **Hop-pair rotation only happens every 24h by default.** A motivated
   adversary observing 24h of traffic on one entry can still correlate.
   Customers wanting tighter rotation should `0trust rotate` manually
   or set the timer to 1h.
4. **A seized mesh node still learns the customers routed through it.**
   `/wg/peers` is scoped: a node receives only the public keys and mesh IPs
   of devices actually routed through it, so one node's PSK no longer
   enumerates the whole customer base. What a node cannot avoid seeing is
   its own traffic — an exit knows the pubkeys terminating on it, and an
   entry knows the source addresses connecting to it. Multi-hop splits those
   two facts across jurisdictions; it does not erase either.
5. **Memory forensics on a seized control-plane host could recover the
   in-memory database connection's state**, including recently-queried
   tokens. RAM encryption (LUKS + cold-boot protection) on the control
   plane is recommended but out of scope for this audit pack.
6. **Static pages load Google Fonts** from `fonts.googleapis.com` and
   `fonts.gstatic.com`. Lighter exposure than cdnjs was (fonts don't
   execute code) but still lets Google see page visits. Mitigation:
   self-host the three font families. Tracked in CSP comment in
   `nginx/0trustvpn.com.conf`.
6. **The CSP allows `'unsafe-inline'` for scripts and styles**, because
   each static page embeds its style and behavior inline. This means a
   theoretical XSS in our HTML output could execute attacker JS. The
   mitigation path is to extract each page's `<style>` and `<script>`
   into hash-pinned external files, allowing `'unsafe-inline'` to be
   removed entirely. Not blocking launch because all our static pages
   are author-controlled HTML with no user input rendered into them.

---

## 12. Process

1. The operator publishes this document and signs a SHA-256 of it with
   the warrant-canary key.
2. An independent auditor runs `scripts/audit-verify.sh` against
   production, reviews source vs. behavior, and publishes a separate
   report.
3. The operator integrates audit findings, bumps this document's
   `version`, re-signs.
4. Cadence: at minimum annually, and whenever schema or logging
   behavior changes.

---

## 13. Contact

Questions about this document: PGP-signed email to
`0trustvpn@proton.me` (PGP key on the landing page).
