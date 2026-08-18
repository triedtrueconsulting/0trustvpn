# Abuse handling runbook

Within days of launch, your exit-node hosting providers will forward abuse
complaints: DMCA notices, spam reports, scan/intrusion alerts, sometimes
law-enforcement preservation requests. **How you handle the first one
determines whether you keep that VPS.** A provider that gets an
unanswered abuse complaint terminates the server, taking down a whole
region with no warning.

This runbook is the standard operating procedure. Print it; you won't have
time to improvise at 2am.

---

## The core tension

You deliberately keep no logs and cannot see customer traffic. So when a
complaint says "IP 1.2.3.4 attacked our server at 14:32 UTC," you genuinely
cannot identify which customer did it — and that's the design working as
intended. Your job in abuse handling is therefore NOT to find and punish the
customer. It's to:

1. Respond promptly and professionally so the provider keeps you online
2. Apply the narrowest effective mitigation
3. Document the response (for your own records and the provider's)

A provider mostly wants to see that a human read their complaint and did
*something*. Silence is what gets you terminated.

---

## Triage by complaint type

### DMCA / copyright notice

The most common complaint. Someone's automated system saw a torrent swarm
member at your exit IP.

**Response template** (adapt and keep ready):

> Thank you for your notice. The IP address in question is an exit node of
> a no-logs VPN service operated by [entity]. We do not host the content
> referenced and we do not retain logs that would let us identify the
> individual user, as documented in our privacy policy at
> https://0trustvpn.com/privacy. We have no stored content to remove. We
> take abuse seriously; if you continue to observe activity from this IP,
> please let us know and we will rotate the exit address. Reference:
> [ticket-id].

**Mitigation:** Usually none needed for a one-off DMCA. If a single exit IP
draws repeated DMCA volume, rotate it (provision a fresh ephemeral node,
deactivate the old one — `bootstrap-node.sh` + mark old `active=0`). DMCA
notices are not legal orders requiring data; they're takedown requests for
content you don't host.

### Spam complaint

A provider reports outbound spam from your exit IP. This threatens the IP's
reputation and the provider's relationship with blocklists (Spamhaus, etc).

**Mitigation:** Block outbound SMTP on exit nodes by default. Add to the
exit node's nftables ruleset:

```
# Block outbound mail submission from VPN clients (anti-spam)
nft add rule inet filter forward tcp dport {25, 465, 587} drop
```

This is a standard, defensible VPN policy — legitimate users send mail
through their provider's webmail or authenticated submission on other ports,
not raw SMTP. Document this in your AUP (already noted in /terms §5).

**Response:** Tell the provider you've blocked outbound SMTP mesh-wide.
They'll be satisfied — it's the canonical fix.

### Port-scan / intrusion-attempt complaint

A provider or third party reports scanning or attack traffic.

**Mitigation:** Rate-limit new outbound connections per source on exit nodes:

```
# Throttle connection-storm behavior (scan mitigation)
nft add rule inet filter forward ct state new \
    limit rate over 50/second drop
```

**Response:** Confirm you've applied egress rate-limiting. If a single exit
keeps drawing scan complaints, rotate it.

### Law-enforcement request (preservation / data / subpoena)

**Stop. Do not respond off the cuff. Do not respond from the support
inbox.** Route to `legal@` (your counsel). General principles:

- A **preservation request** asks you to retain data. You can truthfully
  respond that the data they're asking about isn't retained (see privacy
  policy). You are generally not obligated to *begin* collecting data you
  don't already collect.
- A **subpoena / production order** valid in your jurisdiction may compel
  you to provide what you *have*. What you have is: hashed tokens, device
  pubkeys, mesh IPs, invoice IDs + amounts. You do not have: real IPs,
  traffic, destinations, identities. Provide only what's lawfully compelled,
  nothing more, after legal review.
- If a request would compel you to **start logging** a specific user
  going forward, that is the scenario the warrant canary exists for.
  Consult counsel immediately; this may be the moment you can no longer
  truthfully sign the canary.
- **Child-exploitation reports** are the documented exception in your AUP.
  Cooperate fully with lawful authorities to the extent you technically can.

**Never** discuss a law-enforcement request publicly while it's active if
doing so is unlawful (some orders carry gag provisions). The canary's job is
to signal through absence, not through statements.

---

## The first-hour checklist

When any complaint lands:

- [ ] **Acknowledge within hours, not days.** A short "received, investigating,
      reference #X" reply buys you goodwill and time.
- [ ] **Classify** it (DMCA / spam / scan / legal / other).
- [ ] **Identify the affected node** from the IP in the complaint.
- [ ] **Apply the narrowest mitigation** that addresses it (often none for a
      one-off; egress rules or IP rotation for patterns).
- [ ] **Reply to the provider** with what you did, referencing your privacy
      policy for the "we have no logs" part.
- [ ] **Log it** in your own abuse ledger (encrypted, off the control plane):
      date, type, node, action taken. NOT the complainant's PII beyond what
      you need to reply.
- [ ] **If legal:** stop, route to counsel, do not improvise.

---

## Pre-launch hardening (do this BEFORE you have customers)

Bake these into `bootstrap-node.sh` so every exit node ships with sane
abuse defaults:

- [ ] Block outbound SMTP (ports 25/465/587) on exit nodes
- [ ] Egress connection rate-limiting (scan mitigation)
- [ ] Block outbound to RFC1918 / link-local / your own infra ranges
      (prevents using the VPN to pivot into private networks)
- [ ] Set up an `abuse@0trustvpn.com` address (or alias to your main inbox)
      and **publish it in WHOIS / RDAP and at the abuse contact for your
      IP ranges** — providers look here first
- [ ] Pre-write the DMCA / spam / scan response templates above so you're
      not drafting under pressure
- [ ] Choose exit-node providers known to be VPN-friendly (the ones in
      LAUNCH.md were selected partly for this) — a provider that understands
      VPNs forwards complaints instead of instantly terminating

## The abuse ledger

Keep a simple append-only encrypted log, OFF the control plane:

```
2026-06-03  DMCA      buc-01   one-off, replied w/ no-logs notice, no action
2026-06-05  spam      zur-01   blocked SMTP mesh-wide (already was), replied
2026-06-11  scan      rey-01   pattern; added egress rate-limit, rotated IP
```

This ledger is your evidence of good-faith abuse handling if a provider ever
questions whether you're a responsible operator. It contains no customer
data because you have none to put in it — only node + action.

---

## What you must NOT do

- **Don't start logging to "catch" abusers.** It would break your core
  promise and your privacy policy, and it wouldn't even work well (the
  abuser just rotates tokens). The honest answer to "who did this" is "we
  don't know and can't know," and that's defensible.
- **Don't ignore complaints hoping they go away.** They escalate to the
  provider's abuse desk, which terminates you.
- **Don't respond to legal requests without counsel.** Getting this wrong
  can create criminal exposure for you personally.
- **Don't publicize an active gagged legal request.** Let the canary speak
  through absence.
