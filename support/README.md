# 0trust support workflow

How customers get help and how you provide it without compromising the
no-logs claim.

---

## 1. Design principles

The support channel is the most common accidental data-collection point
for a privacy product. Customers send screenshots, full account tokens,
network logs, IP addresses, sometimes their real names. **Every one of
those would invalidate AUDIT.md if it sat in a normal helpdesk system.**

The goals:

1. Customers can ask for help without revealing more than they need to.
2. Anything they do send is encrypted in transit AND at rest.
3. The operator can delete completely — no `INBOX.Trash` shadow copies.
4. We never use a third-party helpdesk SaaS (Zendesk, Intercom, etc.) —
   they retain logs and can be subpoenaed.

---

## 2. Channel choice

### Recommended: PGP-only email at an encrypted provider

Use **ProtonMail** or **Tuta** for the `0trustvpn@proton.me` address. Both:

- Encrypt mail at rest with keys derived from your password
- Sit in jurisdictions with relatively privacy-friendly mail laws (CH, DE)
- Accept payment in crypto for the account itself
- Don't keep server-side IP logs of senders (Tuta) or scrub them quickly (Proton)

Setup is 30 minutes:

1. Open a paid ProtonMail or Tuta account using a separate identity.
2. Use their custom-domain feature to make `0trustvpn@proton.me` an alias.
3. Set DNS MX records to point at the provider per their docs.
4. Generate a PGP key for that address — see §3 below.
5. Publish the public key at:
   - `https://0trustvpn.com/.well-known/openpgpkey/hu/...`  (Web Key Directory)
   - `https://keys.openpgp.org/`
   - In every page footer that mentions support

### Why not run your own mail server?

You can, but:
- Postfix + Dovecot + Rspamd is a multi-day deploy and a continuous
  hardening job
- IP reputation for outbound delivery is real work
- An MX record that points only at your control-plane IPs reveals
  infrastructure you'd rather keep separate
- Encrypted-at-rest IMAP storage is not something Dovecot does well
  by default

For a small operator, hosted is the right answer. If you grow into
needing your own MTA, the migration path is straightforward (different
MX, same PGP key).

### What about Matrix / Signal / Tor onion contact?

Useful as additional channels for technical users, but email remains
the lowest barrier for support inquiries. Listing all of them on a
contact page is fine. PGP-encrypted email should be the primary.

---

## 3. Generate the support PGP key

```bash
# On a hardened workstation (not the control-plane host):
./support/scripts/generate-key.sh
```

The script generates an ed25519 keypair, exports the public key to
`pubkey.asc`, and prints the fingerprint to publish.

After running:

1. Import the **private** key into your ProtonMail / Tuta account
   (both providers support uploading custom keys).
2. Upload the public key to `keys.openpgp.org` and verify the email.
3. Add the public key fingerprint to `https://0trustvpn.com/security.txt`
   (see [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)).
4. Add the WKD-format public key at the well-known URL:
   ```
   https://0trustvpn.com/.well-known/openpgpkey/hu/<wkd-hash>
   ```
   `support/scripts/generate-key.sh` prints the exact filename to use.

---

## 4. Auto-reply

Configure the support account to send the auto-reply in
`templates/auto-reply.txt` on every inbound message. This:

- Sets clear expectations about response time
- Reminds the customer that we don't have their account details
  (the token is the only identifier)
- Asks them to encrypt sensitive info with our PGP key
- Provides the FAQ link before they wait

Edit it for your operator persona, then paste into the provider's
"vacation responder" or "auto-reply" feature.

---

## 5. Triage workflow

When a real human ticket comes in:

### 5.1 Read first, reply nothing

Don't quote the customer's message unless you're going to encrypt the
reply. Many mail clients send quoted replies in cleartext even when the
original was PGP-encrypted.

### 5.2 Classify

| Category | Action |
|----------|--------|
| Connection trouble | Walk through `0trust status` output → region health on `/status` |
| Forgot token | "The token is the only credential. We literally cannot recover it. Sign up again, your previous account expires naturally." |
| Refund request | Within 30 days, refund via BTCPay's invoice → admin → refund flow |
| Payment didn't credit | Check BTCPay webhook delivery log; if delivered + signature valid, manual `POST /account/topup` |
| Press / legal | DO NOT respond from support@. Forward to a separate `legal@` address handled by counsel. |
| Vulnerability report | Acknowledge within 24h, route to `security@` |

### 5.3 Delete after resolution

Once the ticket is resolved:

1. Forward your final reply + customer's last message to `0trustvpn@proton.me`
   (a separate mailbox YOU control, used only for audit-trail).
2. **Hard delete** the original thread from the support inbox.
3. Empty trash.

The archive mailbox is your evidence of having handled the ticket
properly. It should also be PGP-encrypted to a key the operator controls
that's NOT the support key (so a support-account compromise can't read
historical tickets).

### 5.4 Never store PII outside the encrypted inbox

If a customer accidentally sends:
- Their full account token in plaintext → reply asking them to rotate
  via `0trust login` again; tell them the old token will expire when
  the subscription ends.
- Their real IP address → don't comment on it; certainly never copy it
  into anything that lives outside the support inbox.
- A photo of themselves or their location → same.

---

## 6. What goes in the public-facing FAQ

Most support tickets are repeats. The FAQ at
`https://0trustvpn.com/help` should cover (and exists to *prevent* tickets):

- "I lost my token" → "We can't help. Buy another subscription."
- "Why crypto-only?" → "Because we can't accept payment without
   learning a real name otherwise. The pre-paid card workaround is
   coming."
- "Is X jurisdiction safe?" → operator's threat-model write-up
- "Why no 30-day money-back guarantee?" → "We do refunds in the BTCPay
   dispute window (~30 days). After that, you've used the bandwidth."
- "Do you log anything?" → "See AUDIT.md. The short answer is no, and
   the longer answer is what we DO retain and why."

A well-written FAQ cuts support volume by ~70%.
