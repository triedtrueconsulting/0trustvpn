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

## 2.6 Operator jurisdiction

§2.5 is about where the **servers** are. This is about where the **company**
is, and they are different questions with different consequences. An auditor
will ask; better that the pack answers first.

| | |
|---|---|
| Operating entity | 0trust GmbH |
| Jurisdiction of incorporation | **to be confirmed** — see `/.well-known/security.txt` |

What follows from that, stated plainly:

1. **The company is subject to legal process where it is incorporated**,
   whatever the servers' jurisdictions are. Moving a server to Zurich does not
   move the company. A court in the company's own jurisdiction can compel the
   operator directly.
2. **What it can compel is bounded by what exists.** §3 is the complete list
   of what is stored; a valid order can only reach that. There is no
   connection log, no IP record and no traffic record to produce, because none
   is written — which is the point of the design, and the thing the checks in
   §10 exist to prove rather than assert.
3. **If the entity is incorporated in the United States**, the specific
   exposure is a National Security Letter or a FISA order, both of which can
   carry a gag preventing disclosure. That is exactly the scenario the warrant
   canary in §9 is structured for, and it is why the canary is a canary rather
   than a promise. An auditor should treat a US-incorporated operator as
   raising the importance of the canary's cadence, not as disqualifying.
4. **This is a disclosed limitation, not a hidden one.** The site's
   jurisdictional commitment has always been about server placement
   specifically, and web/privacy.html §6 says the operator will comply with
   valid legal orders while disclosing the minimum the law requires. Nothing
   on the site claims the company itself sits outside the Eyes.

**Auditor action:** confirm the entity named in `/.well-known/security.txt`
matches the registration record, and that terms.html §9 — which defers to that
file for the governing law — resolves to a real jurisdiction.

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
| Account token (hash) | YES | `accounts.token_hash` | Subscription + 30d, then deleted | Sole credential |
| Subscription expiry | YES | `accounts.expires_at` | Subscription + 30d, then deleted | Required to enforce duration |
| Account status | YES | `accounts.status` | Subscription + 30d, then deleted | active / expired / banned |
| Invoice id and USD amount | YES | `invoices` | Deleted with the account | Refunds, and the only revenue record |

"Subscription + 30d" is `ZTV_ACCOUNT_RETAIN_DAYS`, set to the refund window
in terms.html §4. `api/sweep.py` deletes the account row and everything
hanging off it — devices, invoices, notices — once it has been expired that
long. Verified on a live database by `db-no-stale-expired-accounts`, and
end to end by `tests/emulation/test_lifecycle.py`.

**An operator should read the consequence of that before launch.** Deleting
settled invoices with the account means the all-time revenue figure on the
dashboard decays: money taken from a customer who lapsed more than a month
ago is no longer counted anywhere in this system. That is the privacy policy
working as written, not a bug. If the operating jurisdiction requires
commercial records to be retained — Swiss law obliges a GmbH to keep
accounting records for ten years — those records have to be kept OUTSIDE this
database, from the payment side, where they belong. Do not solve it by
raising the retention here: that would quietly extend how long customer
records live in order to serve an accounting need, which is the trade this
whole document exists to refuse.

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
retention. It very nearly was one: this section described the logging in
`nginx/0trustvpn.com.conf`, and **`scripts/install.sh` generates its own
config and has never installed that file**. A real deployment therefore fell
through to the stock `access_log ... combined` in `/etc/nginx/nginx.conf` and
wrote the full client IP, the User-Agent, the Referer and the complete
request line to `/var/log/nginx/access.log`, for the fourteen rotations
Ubuntu's stock logrotate keeps. The checks below could not see it either —
they looked for `/etc/nginx/sites-enabled/0trustvpn.com.conf`, a filename the
installer does not create, and a missing file SKIPs. Everything described
here is now emitted by the installer, and the checks read what it writes.

The http-context part, in `/etc/nginx/conf.d/0trust-zones.conf`:

```
map $remote_addr $remote_addr_anon {
    ~(?P<ip>\d+\.\d+\.\d+)\.    $ip.0;
    ~(?P<ip>[^:]+:[^:]+):       $ip::;
    default                     0.0.0.0;
}

map $uri $uri_anon {
    default                                 $uri;
    "~^/api/v1/devices/.+$"                 /api/v1/devices/-;
    "~^/api/v1/payment/[^/]+/(?<rest>.*)$"  /api/v1/payment/-/$rest;
}

log_format anon '$remote_addr_anon - [$time_local] "$request_method $uri_anon" '
                '$status $body_bytes_sent';

access_log off;
```

That last line matters as much as the format: it cancels the stock
`access_log` in `nginx.conf` at the same level. Without it nginx writes every
request twice — once anonymised, once not — and the second copy is the one
that would end up in a subpoena response. Each server block then opts back
in:

```
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
- The secret-bearing part of a path (see below)

### 4.1.1 Paths, and the two that are secrets

The path **is** logged — `$uri_anon`, not `$uri`. `$uri` is nginx's decoded
path, and two of our routes carry a secret in the path itself:

| Route | What the path segment is |
|---|---|
| `DELETE /api/v1/devices/{pubkey}` | the customer's WireGuard public key |
| `GET /api/v1/payment/{invoice_id}/status`, `/methods` | a bearer capability: it returns a receive address and the amount owed, and is deliberately unauthenticated because the checkout page polls it before the customer holds any credential |

Logging those verbatim put a device key and a payment capability into a file
kept for two days. The `$uri_anon` map replaces the secret segment with `-`,
leaving every other path exactly as it was:

```
"DELETE /api/v1/devices/-"          not  /api/v1/devices/yQDx…LCs=
"GET /api/v1/payment/-/status"      not  /api/v1/payment/btc-3-EhV2…/status
"GET /download"                     unchanged
```

Triage still sees that device deletions are 500ing. It never needed to see
whose. The same leak existed a second time in uvicorn's own access line; see
§7. Auditor verification:

```bash
sudo ./scripts/audit-verify.sh nginx-log-no-secret-paths
grep -E '^log_format anon' -A2 /etc/nginx/sites-available/0trustvpn.com
# Expect: $uri_anon, not $uri
```

### 4.1.2 Why there is no fail2ban jail on the web tier

An auditor will look for one, so here is the reasoning rather than the
absence. Our access log records `$remote_addr_anon` — the client address with
its final octet zeroed, §4 above — and fail2ban bans what its filter
extracts. A jail reading this log could therefore ban only a /24: the
attacker plus up to 254 people who share their prefix, which on a mobile
carrier or a university is a lot of customers.

We keep the truncation and skip the jail. The web tier is rate-limited where
the full address exists but is never written down: six nginx `limit_req_zone`
zones (tightest on signup at 5r/m and the trial at 3r/m), and the admin
login's own counter in `api/admin.py`, keyed on source and attempted
username, held in memory and swept. Neither writes an address anywhere.

fail2ban IS installed and configured, for sshd, on the control plane and on
every mesh node — `config/fail2ban/0trust.local`, backend `systemd` because
Ubuntu 24.04 ships no rsyslog and a node's journald is volatile by design.
sshd logs the full source address to the journal, which never leaves the box
and on a node does not survive a reboot.

### 4.2 Retention

`/etc/logrotate.d/0trust` rotates the file daily and **keeps two days** with
gzip compression. Anything older is gone. This file is written by
`scripts/install.sh`; this section described it for a long time before
anything created it, and nginx's stock `/etc/logrotate.d/nginx` keeps
fourteen weekly rotations — so the claim was out by about a factor of fifty.
Auditor verification:

```bash
cat /etc/logrotate.d/0trust          # Expect: daily, rotate 2
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

### 5.4 The control channel, and what routing it over Tor does and does not do

Every mesh node checks in with the control plane every ~30 seconds.
`ZTV_POLL_JITTER` varies that interval, which hides the **cadence** — nobody
picks a metronome out of netflow. It does nothing about the **destination**.
Each node opens a regular connection to the same control-plane address, so a
party able to observe two nodes' uplinks — a hosting provider that happens to
have two of them, or anyone sampling flow records at scale — can group the
boxes into one system without decrypting a byte. Jitter is the wrong tool for
that; the shared destination is the signal.

`tor/scripts/control-onion.sh` stands up a second onion service for this, and
`ZTV_CONTROL_PROXY` points meshd's control traffic through a local Tor SOCKS
port at it. Each node then reaches its own guard relay and the real endpoint
is inside the circuit, so there is no common destination to correlate on.

Three properties are worth stating precisely, because each is a decision:

- **The address is never published.** Unlike the browsing mirror in
  `bootstrap.sh`, it appears on no page. It lives in each node's meshd env.
- **It requires v3 client authorization.** A party who learns the address
  anyway cannot fetch the descriptor without a key the operator issued. This
  is the property the public onion cannot have and the reason `/api` stays off
  that one.
- **It is an allowlist of four endpoints**, not a proxy of the API. Only
  `/api/v1/wg/peers`, `/wg/forwards`, `/node/heartbeat` and `/node/provision`
  exist at that address; the admin dashboard and every customer route return
  404 there. Verified by driving a real nginx with the generated block.

**There is no fallback to a direct connection.** If Tor is unreachable the
node stops syncing, keeps serving the tunnels it already has, and goes stale
in the control plane where an operator can see it. A silent downgrade would
put the shared-destination signal back on the wire at exactly the moment
somebody was interfering with Tor, and nothing would report it — the same
reasoning that makes the node's upstream DNS fail closed rather than retry in
cleartext (§4d of the privacy policy).

**What this does not do.** It does not make WireGuard undetectable. Customer
tunnels still run plain WireGuard to the node's public IP, and DPI identifies
that on sight. This hides the control plane's relationship to its nodes and
nothing else. No page may imply otherwise.

Auditor verification:

```bash
# On a node, with the transport enabled:
grep ZTV_CONTROL_PROXY /etc/0trust/meshd.env     # Expect: a loopback SOCKS port
journalctl -u 0trust-meshd | grep 'control='     # Expect: "via SOCKS5 …(no direct fallback)"
ss -tnp | grep meshd                             # Expect: only the SOCKS port, never the control plane
```

### 5.5 The obfuscated transport, and what it does and does not conceal

A node may optionally run `0trust-obfs`, a relay that lets a customer's
WireGuard traffic reach it without carrying WireGuard's signature. It is off
by default on the node (`install.sh --mode node --obfs-port <n>`) and off by
default in the client (`0trust connect --obfuscate`, or the GUI switch), so
the ordinary case is unchanged from everything above.

**What it conceals.** WireGuard's handshake initiation is 148 bytes beginning
`01 00 00 00`. Sealed in a Shadowsocks AEAD packet it is a random 32-byte
salt followed by ciphertext and a tag, with no fixed bytes anywhere. A DPI
box cannot classify the protocol.

**What it does not.** Four things, each of which an auditor should confirm we
state everywhere we mention the feature:

| | |
| --- | --- |
| Not authentication | Every client on a node is handed the same relay key — that is what lets the relay open their packets. It is not a secret from anyone who can buy an account. WireGuard remains the only thing authenticating a customer, with or without this. |
| Not traffic-analysis resistance | Packet sizes, timing and volume are unchanged. A flow to this node still looks like a flow to this node, in the same shape as before. |
| Not a UDP-block bypass | UDP in, UDP out. A network dropping all outbound UDP drops this too. |
| Not on by default | It costs an extra userspace hop at each end and 55 bytes of payload. A customer who is not being filtered gains nothing. |

**What it logs: nothing.** The relay writes no file. Its unit is
`ProtectSystem=strict` with no `ReadWritePaths`, so it has nowhere to write
even if it tried, and this is deliberate — the only thing it could usefully
record is which addresses talked to it, which is the log §3.3 says we do not
keep. A packet that fails to authenticate is dropped in silence and counted
nowhere: answering it, even with an error, would tell an unauthenticated
prober that something speaks on that port.

**Privilege.** The relay is a separate unit from meshd, running as a
`DynamicUser` with `CAP_NET_BIND_SERVICE` and nothing else. meshd holds
`CAP_NET_ADMIN` over WireGuard, nftables and routing; the relay parses bytes
an unauthenticated stranger sent to a public port. Those two facts must not
share a process.

**The open-relay question, which an auditor should press on.** A stock
Shadowsocks server forwards to whatever destination the packet names. Ours
holds an allowlist of the node's own loopback WireGuard ports and forwards
nowhere else; hostname destinations (SOCKS5 ATYP 3) are rejected outright, so
it never performs a lookup for anybody; and `NewServer` refuses to start on an
empty allowlist or one naming a non-loopback address. Without that, a key
every customer holds would make this an open proxy sourced from our node's
address.

```bash
# On a node, with the relay enabled:
systemctl show 0trust-obfs -p CapabilityBoundingSet   # Expect: CAP_NET_BIND_SERVICE only
systemctl show 0trust-obfs -p ReadWritePaths          # Expect: empty
grep ZTV_OBFS_WG_PORTS /etc/0trust/obfs.env           # Expect: this node's ports only
ss -lunp | grep 0trust-obfs                           # Expect: it is actually listening
```

The end-to-end behaviour is exercised by `tests/emulation/test_obfs.py`,
which starts the real binary, pushes a real handshake initiation through the
real client relay, and confirms both that it arrives and that the bytes on
the wire do not begin `01 00 00 00`. The open-relay guard is checked by
sending a packet naming a destination the relay was not told about and
confirming nothing comes back — after first confirming that the allowlisted
destination does answer, so the check cannot pass on a relay that forwards
nothing at all.

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

- **Uvicorn access lines are off** — `--no-access-log` in
  `systemd/0trust-api.service`. This is a privacy control, not tidiness.
  The access line is the request path, and two of our paths carry a secret
  in the path itself: `DELETE /api/v1/devices/{pubkey}` is the customer's
  WireGuard public key, and `GET /api/v1/payment/{invoice_id}/status` is a
  bearer capability that returns a receive address and an amount owed.
  Earlier revisions of this document said the access lines were "filtered
  out at the log-format level". Nothing did any such filtering: the unit ran
  uvicorn at `--log-level info`, and every device removal wrote that
  customer's key into the journal, percent-encoded, for the seven days
  `MaxRetentionSec` keeps. The claim is corrected here, the flag is in the
  unit, and `audit-verify.sh api-no-access-log` fails if it is ever removed.
- **FastAPI route exceptions** produce a Python traceback: the exception
  type, its message, and the *source lines* of the frames. Not the frames'
  local variables, and not the parameters bound into a SQL statement —
  CPython's default traceback formatter emits neither. Request bodies are
  not logged at all.
- **DB integrity errors** surface as `sqlite3.IntegrityError`, whose message
  names the constraint that failed — `UNIQUE constraint failed:
  invoices.id`, `NOT NULL constraint failed: devices.pubkey`. The table and
  the column, never the value. There is no exception handler suppressing
  these and there does not need to be; the operator needs the traceback and
  it carries no customer data.
- **Account tokens** are hashed by the auth dependency before anything can
  log them, so a token cannot reach the journal by way of a stack trace.

Auditor verification — run the two checks rather than typing a grep, because
the grep most people reach for is the one that missed the leak above:

```bash
sudo ./scripts/audit-verify.sh api-log api-no-access-log
# Expect: api-log-no-tokens PASS, api-log-no-pubkeys PASS,
#         api-no-access-log PASS
```

`api-log-no-pubkeys` matches a 44-character WireGuard key wherever it
appears and in either encoding — raw, or percent-encoded as it would arrive
in a URL. It previously matched only the JSON shape `"pubkey": "…"`, which
is the one place a key is never logged, since bodies are not. If you want to
run it by hand:

```bash
journalctl -u 0trust-api --since "1 hour ago" \
  | grep -oE '([A-Za-z0-9]|%2[BbFf]|[+/]){43}(=|%3[Dd])'
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
| Quad9 (`9.9.9.9`) | Upstream for the in-tunnel resolver, over DNS-over-TLS (RFC 7858, port 853), authenticated against `dns.quad9.net` | Customer DNS queries, sourced from the exit node's address. Not attributable to an account, and not readable by anyone between the node and Quad9. Configurable per deployment (`ZTV_DNS_TLS_UPSTREAM`); `ZTV_DNS_ENCRYPTED=0` reverts to cleartext UDP 53 and the resolver config says so in a comment. Verified by `node-dns-encrypted-upstream`. |
| Bitcoin explorer (`mempool.space` by default) | Asks whether a derived BTC address has been paid | One receive address per invoice, and the fact that somebody is watching it. No account identifier is ever sent. Configurable (`NODE_RPC_BTC`); any Esplora instance, including your own. |
| Zcash explorer (`api.blockchair.com/zcash` by default) | The same question for a transparent ZEC address | As above. Configurable (`NODE_RPC_ZEC`); Blockchair and Esplora shapes are both read, chosen from the URL. **Transparent addresses only** — shielded ones cannot be watched from a public key, and are not offered. |
| Kraken public ticker | USD → coin conversion when an invoice is opened | Nothing but the pair name. No account, no key. Configurable (`ZTV_PRICE_API`). |
| A Monero remote node (operator's choice) | Blocks for the view-only wallet to scan | That an IP is scanning the chain. It cannot see the wallet's keys, its balance, or which outputs are the operator's. Configured on `monero-wallet-rpc` itself (`--daemon-address`), not by the control plane. |
| Hosting provider | (operator's choice) | Network metadata visible at the IP layer; no application data. |
| cdnjs.cloudflare.com | n/a | RESOLVED — the landing page now self-hosts vendored JS from `/vendor/`. See `scripts/vendor-third-party.sh`. |
| Web analytics | **none** | There is no analytics provider, no tag manager and no pixel, on any page including `/surf`. This is not an omission to be filled in later; see below. |

### 9.1 Measurement, and what it deliberately cannot see

An auditor should expect a commercial service to measure its funnel, and
should ask what that measurement collects. The answer here is that the
operations dashboard counts rows the service already holds, and nothing else:

| Figure | Counted from | New data collected |
|--------|--------------|--------------------|
| Trials started / converted | `accounts.trial_started_at`, `accounts.plan` | none |
| Paid without a trial | the same two columns | none |
| Invoices created / settled | `invoices.status` | none |

Both tables are documented in §3 and §6 and exist to deliver what a customer
paid for. `accounts.trial_started_at` survives conversion, which is what makes
trial-to-paid conversion knowable without adding a column — or a cookie.

What the operator therefore **cannot** answer, and has no mechanism to
answer: how many people visited any page, where they came from, what they
clicked, or whether a given visitor ever returned. Measuring that needs
either a third-party script or a per-visitor identifier, and the service has
neither. privacy.html §5 states this to customers in the same terms.

The honest limitation for an auditor to record: this arrangement is enforced
by there being no code that does otherwise, not by a technical control. The
checks that would notice one appearing are `no third parties` in
`tests/emulation/test_site.py`, which fails on any off-origin script,
stylesheet, image, icon or preconnect on any page, and the CSP.

---

## 10. Verification script

`scripts/audit-verify.sh` runs the full check matrix against a live
production host. It exits non-zero if any verification fails.

```bash
sudo ./scripts/audit-verify.sh
```

Each check has a short name; run with `-v` to see the underlying command,
and pass names as arguments to run only those (`audit-verify.sh nginx db`).

Exit code is the number of failed checks. A **SKIP** means the check does not
apply to the host it was run on — the ephemeral-node checks skip on a control
plane and vice versa, so expect a majority of skips from any single machine.
Run it on the control plane and on each mesh node to cover the matrix.

### The checks

Every check below is the executable form of a claim made earlier in this
document. If one fails, the claim above it is the one that needs answering.

**§2.5 JURISDICTION RESTRICTIONS**

| Check | What a pass proves |
|-------|--------------------|
| `juris-allowlist` | Only zur, rey, buc regions present in mesh_nodes |
| `juris-no-eyes-codes` | No Eyes-country region codes anywhere in DB |
| `juris-public-ip-geolocate` | Node public IPs geolocate to declared countries |

**§3. CONTROL-PLANE DATABASE**

| Check | What a pass proves |
|-------|--------------------|
| `db-exists` | Database file exists |
| `db-no-plaintext-token` | No plaintext token columns anywhere |
| `db-no-customer-ip` | No IP-address column anywhere |
| `db-no-private-key` | No customer private-key column |
| `db-hop-pairs-ttl` | All hop_pairs have non-null expires_at |
| `db-failed-invoices-gc` | No failed invoices older than 30d |

**§4. WEB-TIER (nginx) LOGS**

| Check | What a pass proves |
|-------|--------------------|
| `nginx-conf-exists` | nginx config present |
| `nginx-no-user-agent` | Access log format does not include User-Agent |
| `nginx-anonymizes-ip` | Access log uses anonymized client IP |
| `nginx-log-no-secret-paths` | Access log collapses secret-bearing paths |

**§5. MESH-NODE BEHAVIOR**

| Check | What a pass proves |
|-------|--------------------|
| `node-egress-filter` | Abuse egress filter is loaded (mesh nodes) |
| `node-nat-table` | Exit NAT table is loaded (mesh nodes) |
| `node-dns-no-query-log` | In-tunnel resolver keeps no query log (mesh nodes) |
| `node-dns-encrypted-upstream` | Upstream DNS leaves the node over TLS (mesh nodes) |

**§3. CONTROL-PLANE DATABASE**

| Check | What a pass proves |
|-------|--------------------|
| `db-no-abandoned-signups` | No unpaid signups retained past 7 days |
| `db-no-stale-trial-nonces` | No trial nonces retained past 24h |
| `db-no-stale-expired-accounts` | Expired accounts purged after the refund window |

**§4. WEB-TIER**

| Check | What a pass proves |
|-------|--------------------|
| `nginx-log-retention` | Access log retention ≤ 7 days |
| `nginx-canary-no-cache` | Canary served with no-cache headers |

**§5. MESH-NODE BEHAVIOR**

| Check | What a pass proves |
|-------|--------------------|
| `meshd-installed` | 0trust-meshd service unit exists |
| `nft-no-logging` | nftables ruleset contains no log statements |
| `wg-no-monitoring` | No periodic 'wg show' polling writing to disk |
| `meshd-log-no-customer-data` | meshd journal has no customer pubkeys |

**§5.3 EPHEMERAL (RAM-ONLY) NODES**

| Check | What a pass proves |
|-------|--------------------|
| `ram-tmpfs-wireguard` | Ephemeral: /etc/wireguard is tmpfs |
| `ram-tmpfs-0trust` | Ephemeral: /var/0trust + /etc/0trust are tmpfs |
| `ram-no-swap` | Ephemeral: swap is fully disabled |
| `ram-journald-volatile` | Ephemeral: journald is volatile |

**§7. APPLICATION (API) LOGS**

| Check | What a pass proves |
|-------|--------------------|
| `api-log-no-tokens` | Recent API log has no account-token leakage |
| `api-log-no-pubkeys` | Recent API log has no WireGuard pubkeys |
| `api-no-access-log` | API unit does not log request paths |
| `api-journald-retention` | journald retention ≤ 7 days |

**§8. BACKUPS**

| Check | What a pass proves |
|-------|--------------------|
| `backups-encrypted` | No UNENCRYPTED database copies on disk |
| `backups-no-leftover-snapshot` | No leftover plaintext .snap-* snapshots |

**§11. KNOWN-LIMITATION DISCLOSURES**

| Check | What a pass proves |
|-------|--------------------|
| `no-cdnjs` | Landing page does not reference cdnjs or other CDNs |
| `vendor-sri-pinned` | All vendored scripts have SRI integrity attributes |
| `canary-fresh` | Warrant canary is within its published signing deadline |

`tests/emulation/test_audit.py` asserts this table and the script cannot drift
apart: a check with no row here, or a row naming a check that does not exist,
fails the build.

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
6. **The pages contact no third-party origin at all.** They used to load
   Google Fonts from `fonts.googleapis.com` and `fonts.gstatic.com`, which
   let Google observe page visits — mild next to executing code, but on
   `/surf`, whose entire claim is that a visit is not handed to anyone, it
   was a contradiction. The three families are now served from `/fonts`
   (`scripts/fetch-fonts.sh` regenerates them from upstream, latin and
   latin-ext subsets), and both origins have been removed from `style-src`
   and `font-src` rather than left whitelisted for nothing.
7. **The CSP allows `'unsafe-inline'` for scripts and styles**, because
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
