# Rollback and recovery

Audit date 2026-10-17.

`docs/DR.md` covers disaster recovery — the host is gone, restore it. This
file covers the other direction: a deploy that went out and needs to come
back, and the states this product can get into where the *service* looks
healthy and the *product* is not.

The distinction matters here more than in most systems. Several components
report success on their own terms while doing nothing useful: `wg-quick up`
never contacts the node, `systemctl enable --now` says nothing about whether
an interface exists, a timer reports active whether or not its service can
exec anything, and a node with no NAT keeps heartbeating happily over its
own outbound HTTPS while dropping every customer packet.

---

## 1. Before any deploy

| Step | Why |
|---|---|
| Record the current release tag and commit | You cannot roll back to a state you did not write down |
| Confirm a backup completed **tonight**, not merely that the timer is enabled | A unit that fails every night looks like backups exist, which is worse than none |
| `./scripts/backup.sh` by hand if in doubt | It writes `api.env` beside the database, encrypted to the same recipients |
| Note which payment provider is configured | A rollback across a provider change is not a rollback |

A backup is only a backup if it can be read. `backup.sh` encrypts to the
recipients in `/etc/0trust/backup-recipients.txt`, and only the **public**
half of the age key is ever on the server — whoever seizes the box must not
be able to read the backups it made.

## 2. Rolling back the control plane

The database is the thing that cannot be re-derived. A token alone cannot
rebuild a subscription expiry, so the database is the record of what every
customer paid for.

```
# 1. Stop the API, leave nginx serving so customers get a page, not a reset
systemctl stop 0trust-api

# 2. Snapshot the CURRENT database before touching it — even a bad one
cp /var/lib/0trust/0trust.db /var/lib/0trust/0trust.db.pre-rollback

# 3. Check out the previous release and reinstall
git checkout <previous-tag>
./scripts/install.sh --mode production   # same flags as the original install

# 4. Start, then verify rather than assume
systemctl start 0trust-api
curl -fsS https://0trustvpn.com/api/v1/health
./scripts/audit-verify.sh
```

**Do not restore an older database to accompany a code rollback unless the
schema actually changed.** Migrations here are additive (`MIGRATIONS` adds
columns), so a newer database generally runs under older code. Restoring an
older database discards every account, invoice and device created since the
backup — including payments that have already settled on-chain, which the
operator cannot undo and the customer will not forget.

If a migration must be reversed, do it to a **copy**, verify it, then swap:
never decrypt or migrate straight over the live file. A truncated archive or
the wrong key destroys the only copy you had left with a half-written file.

## 3. Rolling back a node

A node is cheap to replace and that is the design. Prefer replacement to
repair.

```
# Take it out of rotation first — the control plane stops handing it out
#   (set active = 0 via the admin dashboard, not hand-written SQL)
# Customers reconnect; _pick_node routes them to a live node.
```

Failover is **the client reconnecting after its handshake check fails**, not
a peer list — one peer per config, because a second peer claiming `0.0.0.0/0`
takes that prefix off the first. So a node withdrawn from rotation drains as
clients reconnect, rather than instantly.

To rebuild: re-run `install.sh --mode node` with the enrolment token. It
re-registers the **same** node id rather than accumulating a row per boot,
because the token is IP-pinned on first use.

After any node comes back, verify what reboot does not replay:

```
nft list ruleset | grep -E 'masquerade|ztv_'   # NAT and egress filter present
ip link show                                   # the interface actually exists
resolvectl query example.com                   # resolver answers (DoT upstream)
```

The masquerade check is not optional. Its absence is the silent outage
described above.

## 4. States where the service is up and the product is broken

These are the ones to look for after any change, because none of them
raises an alert on its own.

| Symptom | Cause | Check |
|---|---|---|
| Customers connect, no traffic flows | NAT not reapplied after node reboot | `nft list ruleset \| grep masquerade` |
| Tunnel healthy, "some sites hang" | MTU wrong for the transport in use | full-size packet test, both transports |
| Payments arrive, accounts never activate | Provider is not `watch` but the poll timer is the only settlement path | `ZTV_PAYMENT_PROVIDER`, `0trust-poll.timer` |
| Invoices settle one block deep | Confirmation depth misread | `/api/v1/config` → `confirmations` |
| Addresses issued that the operator cannot spend | Wrong extended key | `./scripts/check-wallet.sh` |
| Co-located nodes lose rules every 30s | Shared nftables table name | `ZTV_NFT_TABLE` per node |
| Multi-hop routes but hides nothing | Entry and exit on one host (`--mode test`) | this is the test rig; never run it for customers |
| Canary stops being fetchable as the current one | `/canary.txt` cached | the no-store block in the rendered nginx config |
| Backups "exist" but are empty or unreadable | Timer enabled with no recipient, or wrong key | decrypt last night's archive to a scratch path |

## 5. Payment and refund incidents

**Never issue a refund by rolling back.** The control plane holds no
spending authority and never will — it cannot move coins, and that is the
design, not a gap.

The sequence is: send the coins back by hand, **then** record it with
`POST /api/v1/admin/invoices/{id}/refund`, which marks the invoice
`REFUNDED` and takes back exactly `months * 30` days — the same arithmetic
settling added. Refunding one month of three leaves the other two.

It is guarded on stored state rather than on being called once, so a retried
POST does not revoke twice. It moves no money and says so in its response.

If the two steps get out of order, the account keeps days it was refunded
for, or loses days it still paid for. Record the invoice id and the
on-chain txid together in the operator's own notes — `ops_events` must not
carry an account id, because that would turn it into the activity log
privacy.html denies keeping.

## 6. Rolling back a release the public already has

Published artifacts cannot be recalled; they can only be superseded.

1. Cut a new version. Do not re-publish a tag.
2. Re-run `./scripts/release.sh` and re-sign `SHA256SUMS`.
3. Leave the old artifacts and their hashes in place. Removing them breaks
   verification for anyone who already downloaded, which looks exactly like
   tampering — the thing the verifier exists to detect.
4. Say what changed on the download page.

## 7. The warrant canary

The canary is the one document written to be relied on when it **stops**
appearing. Rolling anything back must not cause a missed or stale
statement.

- If a deploy breaks canary publication, fix publication — do not back-date
  a statement.
- `audit-verify.sh` ages the canary; confirm it reads the published file and
  not an mtime, which it did once and which made a stale canary look fresh.
- A cached canary cannot stop appearing, which is the only thing a canary
  does. Confirm the `/canary.txt` no-store block survived the rollback.

## 8. After any rollback

```
./scripts/audit-verify.sh      # on the host, not in the repo
./scripts/preflight.sh
```

Then confirm by hand the three things no script can see: that a real client
connects and passes traffic, that a test payment settles, and that the
canary's current statement is fetchable and in date.
