# Data requests, deletions and breaches

The runbook for the three letters that will eventually arrive: *what do you
hold on me*, *delete it*, and — the one nobody wants — *we have been
breached*. Written down because each has a deadline, and because the answer
for this product is unusual enough that improvising it under time pressure
would produce a worse answer than the true one.

privacy.html §12 is the customer-facing version of the first two, and §13 of
the third. If you change anything here, change it there. They are the same
promise written for two audiences.

---

## 1. "What data do you hold on me?"

**Right of access** — FADP art. 25 (Switzerland), GDPR art. 15 (EU/EEA/UK).
A month to answer under the GDPR, extendable to three with a reason.

**The answer is that they already have it.** Everything the control plane
holds about an account is readable by the token holder:

    0trust status      # plan, expiry, device cap, days remaining
    0trust devices     # every device key, name and mesh IP on the account
    0trust notices     # anything we have sent them

There is no profile behind the token and no second table keyed to it. So the
reply is those three commands, a pointer to privacy.html §2 for what each
field means and §8 for how long it survives, and an offer to run them on
their behalf if they cannot.

**Only ever answer to a token.** The token is the sole identifier; presented
with one you can find exactly one account, and presented without one you
cannot honour anything. Someone who has lost their token has not proved
anything about which account is theirs, and treating an email address or a
transaction ID as proof is how you hand somebody else's account away. Say no,
say why, and point at §12 — this is the cost of the design, and it is
supposed to be said out loud rather than worked around.

**Do not go looking in the chain.** An invoice ID plus a block explorer can
sometimes tie a payment to an address, and from there to a person. Doing that
to satisfy a request would create the linkage this product exists to avoid,
and it would be a new processing activity with no lawful basis. The answer to
"I lost my token but here is my transaction" is still no.

## 2. "Delete my data"

**Right to erasure** — GDPR art. 17, and the FADP equivalent.

With a token: Accounts → search the token → **Delete**. It removes the
account row and every dependent — devices, invoices, notices, and the trial
stamp is detached rather than deleted so it cannot be redeemed a second time.
The audit row records that account *N* was deleted and by whom, which is the
one trace left and holds no customer data.

Without a token: you cannot, and §12 says so. Nothing to do.

Note that **doing nothing also works**: the subscription expires, and 30 days
later the sweeper deletes the row on its own. Say this — a customer who wants
to be gone may prefer to simply stop paying, and it is the same outcome.

Deleting an account does **not** refund it. If they asked for both, the
refund comes first (§3 below), because deleting the account removes the
invoice you would have recorded the refund against.

## 3. "I want my money back"

**terms.html §4** — full refund within 30 days of payment, on request, to a
crypto address they supply.

1. Find the invoice: Invoices → filter Settled → match the invoice ID they
   gave you. If they cannot produce one, `0trust status` shows their expiry
   and the Accounts tab will find the account from the token.
2. **Send the coins first**, by hand, from the wallet the payment arrived in.
   The control plane holds no keys and never will, so nothing here can do it
   for you.
3. Then Invoices → **Record refund** on that invoice. This marks it refunded
   and takes the days it bought back off the subscription — one month
   refunded out of three leaves the other two. Recording it twice is refused;
   the days come off once.

Recording it is not bookkeeping neatness. Skip it and the customer keeps the
service they were refunded for, which is the state the button exists to
prevent.

## 4. "We have been breached"

**Deadlines.** GDPR art. 33: notify the supervisory authority within 72 hours
of becoming aware, unless the breach is unlikely to result in a risk. FADP
art. 24: notify the FDPIC as soon as possible. Art. 34 GDPR: tell the
affected people too, where the risk to them is high — for us that means the
site and the canary, because we have no way to email anyone.

**Hour zero.** Do not wait for a complete picture; the clock runs from
"aware", not from "understood".

1. **Contain.** Follow docs/DR.md for the mechanics. A compromised node is
   destroyed and re-enrolled, not repaired — it is RAM-only for exactly this
   reason. A compromised control plane is the serious case: rotate the admin
   password, revoke every provisioning token, and restore from backup onto a
   new host.
2. **Establish what was reachable, and write it down as you go.** Consult
   docs/AUDIT.md §10 for what each table holds. Be precise about the
   difference between a node (the customers it was itself routing, per
   `device_nodes`) and the control plane (every account row).
3. **Notify the FDPIC**, and any EU supervisory authority that applies. Say
   what you know and what you do not.
4. **Publish**, on the site and in the canary: what happened, when, what was
   exposed, what you did. Before it is tidy. A privacy service that goes
   quiet during an incident has already answered the only question that
   mattered.
5. **Then** work out the cause, and write the fix into
   `scripts/audit-verify.sh` so it cannot come back unnoticed.

**What is actually at stake, so you can say it accurately.** There is no
email list, no payment identity, no browsing history and no connection log.
An attacker holding the whole control-plane database gets token *hashes* —
which do not work as tokens — expiry dates, device public keys, mesh IPs and
invoice amounts. An attacker holding a node gets the customers that node was
routing at that moment and nothing about anyone else. privacy.html §3 and §7
state this to customers; make sure any notice you write agrees with them.

---

## Before launch

Both of the following need the answer of a lawyer in the operating
jurisdiction, not this file:

- **Who the supervisory authority is**, and whether an EU representative is
  required (GDPR art. 27) for a Swiss company selling to EU residents.
- **VAT.** A Swiss GmbH selling a digital service to EU consumers has VAT
  obligations in the customer's country, and this product deliberately does
  not know which country that is. Pricing, and whether it is VAT-inclusive,
  is a decision to take with an accountant before the first sale — not after.

Neither is engineering, and neither is optional.
