# Operations dashboard

`https://<domain>/admin` — everything needed to run the service and the
business behind it. Accounts, mesh nodes, payments, settings and an audit
trail of who did what.

## First run

Open `/admin`. With no operator account, it offers to create one. Do this
immediately after installing: until it exists, anyone who finds the URL can
create it themselves.

There is no password reset. Losing it means editing the `admins` table by
hand. `scripts/install.sh` can seed an account instead via `ZTV_ADMIN_USER`
and `ZTV_ADMIN_PASSWORD`, but the setup screen is the better default — a
password that was never written to a config file cannot leak from one.

## Lock it down

The dashboard can ban customers, hand out free time and change where money
lands. Treat it as the most sensitive surface you run.

`nginx/0trustvpn.com.conf` ships with commented-out `allow`/`deny` lines on
`/admin` and `/api/v1/admin/`. Either fill in your own address, or leave both
denied and reach the dashboard through an SSH tunnel:

```bash
ssh -L 8443:127.0.0.1:443 you@your-server   # then browse https://localhost:8443/admin
```

What the application enforces regardless:

- scrypt-hashed passwords, minimum twelve characters
- sessions stored as hashes, expiring after 8 hours (`ZTV_ADMIN_SESSION_TTL`)
- HttpOnly, SameSite=Strict cookies, Secure behind TLS
- a CSRF header on every mutation
- rate-limited logins, per username and per address
- every state-changing action written to `admin_audit`

## What each tab does

**Overview** — accounts by state, 30-day and all-time revenue, node health,
and the last ten admin actions.

**Accounts** — there is no name or email to search by; that is the product.
Search by the token the customer gives you, by account id, mesh IP, or a
device key from an abuse report. From an account you can ban, unban, add or
remove days, message, remove individual devices, leave a private note, or
delete it outright.

*Banning removes the devices as well as flipping the status.* That is the
part that stops traffic: the peer manifest is built from live devices, so the
nodes drop the keys at their next sync. Flipping the status alone would leave
them connected until expiry.

**Nodes** — add a static node without touching sqlite3, take one out of
rotation, remove one (releasing its sessions), or mint a one-shot
provisioning token for a RAM-only node. Regions are checked against the
jurisdiction allowlist: a node in the wrong country is a broken promise, and
`audit-verify.sh` will fail on it the next day.

**Payments** — which provider is configured, whether it is reachable, and
what is still missing from its configuration. Invoices can be credited by
hand for the case every crypto operator eventually hits: the payment landed
on chain but the webhook never arrived. That path runs through the same
credit-once guard as a webhook, so using it twice cannot double an
account's expiry.

**Notices** — see below.

**Settings** — payment credentials, wallet addresses, public chain endpoints
and trial parameters, saved to the database and applied immediately. No
restart. Secrets display as dots; leave them alone to keep the stored value.

Changing **Trial length (days)** changes the offer everywhere at once. The
landing page, the trial page, the `/surf` banner and the desktop GUI all read
it from `GET /api/v1/config` rather than stating a number of their own, so
there is no copy left behind advertising the old length. `/surf` runs as its
own service and caches the answer for five minutes, so its banner catches up
within that window.

**Audit** — every mutation, with who and when. Secret *values* are never
recorded, only which keys changed.

## Notices, not email

There is no email address on any account. That is the central design
decision, not an oversight, so **the dashboard cannot email anyone.**

What it can do is leave a message that the customer's client collects on its
next check-in — `0trust status`, the desktop GUI, or the phone app. Notices
can go to one account or to everyone, carry a severity, and expire.

The honest limitation: a customer who never opens their client never sees it.
For anything genuinely urgent, the status page and the warrant canary are the
channels that do not depend on the customer running software.

If you want reachable customers, that is a product decision — an optional,
clearly-labelled contact field that customers opt into — and it needs to be
reconciled with `web/privacy.html` and `docs/AUDIT.md` before it ships.

## Payments and identity

`ZTV_PAYMENT_PROVIDER` selects one of four:

| | Custody | Node to run | Anonymous |
|---|---|---|---|
| `btcpay` | yours | none — point at a hosted BTCPay | yes |
| `hosted` | the gateway's | none | usually KYC'd |
| `stripe` | Stripe's | none | **no** |
| `square` | Square's | none | **no** |

None requires this operator to run a Bitcoin, Ethereum, Monero or Zcash node.
The `NODE_RPC_*` settings name the public endpoints to use where a provider
consults them; no chain is ever synced locally.

**Enabling a card processor changes what the product is.** The processor
learns the customer's identity and that they bought a VPN, and can be
compelled to disclose it. `web/privacy.html` §4a says this in those words and
must keep saying it for as long as cards are enabled. A deployment that
accepts cards while advertising anonymity is failing its own audit.
