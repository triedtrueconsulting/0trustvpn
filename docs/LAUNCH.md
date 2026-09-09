# 0trust VPN — Launch playbook

You have the code. You have the design docs. This is the playbook for
turning the repo into a service that customers can actually pay you for.

Estimated total time: **8-14 days of calendar time**, ~25 hours of
hands-on work spread across them. Most of the calendar time is waiting
on chain syncs, certificate provisioning, third parties, and your own
attention to weekly tasks.

Tick items as you go.

---

## Before you start

```bash
./scripts/preflight.sh --repo    # what is still outstanding, and how to fix it
```

Run it again after every day below. It is the checklist that cannot go stale,
because it reads the files rather than trusting this document.

---

## Day 1 — Identity and hosts

### Generate your operator identities

These are the keys you'll use forever. Generate them once, carefully,
on a workstation that is **not** connected to anything 0trust touches.

All four at once, on your own machine — the script refuses to run in CI or on
anything that looks like the server, and prints the exact edits afterwards:

```bash
./scripts/generate-keys.sh          # release + canary + support PGP, age backup
```

- [ ] **Release-signing PGP key** — pin its fingerprint in `EXPECTED_KEY`
      (`scripts/verify-release.sh`) and on the site. Until you do,
      `scripts/preflight.sh` blocks: the download page tells customers to
      verify against a fingerprint, and right now that fingerprint is nobody's.
- [ ] **Warrant canary signing key**
- [ ] **Support/security PGP key** — publish via WKD (`support/scripts/generate-key.sh`)
- [ ] **Age key for backups** — the PUBLIC half goes on the control plane; the
      private half never does. It is the only thing that can read a backup.
- [ ] **Android upload keystore** — `generate-keys.sh` does NOT make this one;
      it comes from the JDK, and it is the key Android identifies your app by.

      ```bash
      keytool -genkey -v -keystore zerotrust-upload.jks -alias 0trust \
              -keyalg RSA -keysize 4096 -validity 10000
      ```

      Free, self-signed, no certificate authority — nothing to buy, unlike the
      Windows situation. **Losing it is the worst key loss on this list**, and
      it is worse here than for most apps: Android refuses an update signed by
      a different key, so customers would have to uninstall to take one — and
      uninstalling destroys the account token, which by design nobody can
      recover, not even you. A lost keystore can therefore cost customers the
      accounts they paid for. Back it up with the rest, in more than one place.

- [ ] **Back up `~/.0trust-keys` AND the Android keystore offline before doing
      anything else.** Four of those keys cannot be replaced without telling
      every customer the old ones are dead.

- [ ] **Bitcoin xpub** — the extended PUBLIC key of the wallet that receives
      payments. It is deliberately **not** committed anywhere in this repo: an
      xpub exposes the wallet's whole balance and transaction history to
      anyone who holds it, permanently, and you cannot rotate one without
      moving the funds. It belongs in `WALLET_BTC` in `/etc/0trust/api.env`
      and nowhere else.
      ```bash
      ./scripts/check-wallet.sh zpub...     # before you use it
      ```
      Its *identity* is pinned in `scripts/wallet.pin` — the SHA-256 of the
      key, which reveals nothing and still catches a truncated or
      wrong-account paste. `check-wallet.sh` exits 3 on a mismatch, and
      `install.sh --wallet`, `preflight.sh` and the BTCPay configure script
      all refuse to proceed on one. Running this deployment against your own
      wallet instead:
      ```bash
      ./scripts/check-wallet.sh --pin zpub...   # then commit scripts/wallet.pin
      ```
      - [ ] **Compare the first address it prints against the next receive
            address your wallet shows.** This is the one failure in the system
            with no symptom: a wrong or wrong-account key issues addresses you
            cannot spend, invoices never settle, and every health check stays
            green.
      - [ ] Confirm the seed phrase backup is written down on paper, two copies, two locations
      - [ ] Test-restore from the seed to a different wallet app; verify the same addresses generate

### Pick your hosting

- [ ] **Control plane host** — 1 vCPU, 2GB RAM, 20GB disk. Privacy-friendly provider (1984.hosting, Njalla, Greenhost). ~€5/mo.
- [ ] **BTCPay host** — 2 vCPU, 4GB RAM, 40GB disk. Same provider OR a different one for blast-radius isolation. ~€8/mo.
- [ ] **Three mesh nodes** — 1 vCPU, 1GB RAM, 10GB disk each, in:
      - 🇨🇭 **Zurich, Switzerland** — try Init7, Cloudsigma Zurich, or BlackHOST
      - 🇮🇸 **Reykjavik, Iceland** — 1984.is or FlokiNET
      - 🇷🇴 **Bucharest, Romania** — M247, Hosterion, or FlokiNET
      ~€4/mo each, ~€12/mo for the trio.
- [ ] Pay each provider in crypto if possible. Use anonymous registration where the provider allows it.

### DNS

- [ ] Register `0trustvpn.com` (or your chosen domain) through a registrar that accepts crypto and doesn't require KYC. **Njalla** is the standard choice here.
- [ ] Point `0trustvpn.com` and `www.0trustvpn.com` A records at the control plane host
- [ ] Point `pay.0trustvpn.com` A record at the BTCPay host
- [ ] **Don't** set up any wildcard records or vanity subdomains for mesh nodes — we want their IPs to look like ordinary cloud instances, not part of an obvious cluster.
- [ ] **Register a backup domain** at a *different* registrar (e.g. `zerotrustvpn.com`). DNS can point at the same control plane. This is your hedge against single-registrar pressure (see `docs/DR.md` Scenario 4).

### Legal &amp; commercial setup

- [ ] **Review the privacy policy** (`web/privacy.html`) and **terms** (`web/terms.html`) line by line. They are written to match the audit-pack claims exactly; if you change the audit-pack claims, change these too.
- [ ] **Operating entity: `0trust GmbH`** Recorded in
      `web/.well-known/security.txt`, which `terms.html` §9 makes the governing
      law of the contract.
      - [ ] **Add the jurisdiction** — country, and the state if incorporated in
            the US. `preflight.sh` blocks until it is there, because §9 defers
            the governing law to that line and it currently resolves to nothing.
      - [ ] Read `docs/AUDIT.md` §2.6. The company's jurisdiction is a different
            question from the servers', and an auditor will ask. If the entity
            is US-incorporated, the exposure is an NSL or FISA order with a gag
            — which is precisely what the warrant canary is structured for, and
            makes its weekly cadence load-bearing rather than decorative.
- [ ] **Read `docs/ABUSE.md`** end-to-end and pre-write the response templates so you're not drafting under pressure when the first DMCA arrives (it will, within days).
- [ ] **Set up `abuse@0trustvpn.com`** as an alias of the proton.me account. Publish it in WHOIS and in the abuse-contact for your IP ranges (your hosting provider configures this).
- [ ] **Read `docs/DR.md`** end-to-end. Understand which off-host artifacts you need to keep age-encrypted (the list is at the bottom of that doc).

### Backup recipients

- [ ] Generate the age key on your hardened workstation: `age-keygen -o ~/.age/0trust-backup.key`
- [ ] Save the **public** part (`age1...`) to `/etc/0trust/backup-recipients.txt` on the control plane (one recipient per line; you can add a co-operator's key here too for two-of-N recovery)
- [ ] Test-encrypt a dummy file to it and decrypt it back. A backup you can't decrypt isn't a backup.

---

## Day 2 — Control plane

```bash
# On the control plane host:
git clone https://your-git/0trust-vpn /opt/0trust-src
sudo /opt/0trust-src/scripts/bootstrap.sh
```

Then:

- [ ] Verify `systemctl status 0trust-api` is green
- [ ] Verify `curl -fsS https://0trustvpn.com/api/v1/health` returns 200
- [ ] Verify the landing page renders at `https://0trustvpn.com/`
- [ ] Verify `https://0trustvpn.com/status` renders (will show "no regions reporting" since we haven't deployed any mesh nodes yet — that's correct)
- [ ] Verify the audit-verify script:
      ```bash
      sudo /opt/0trust-src/scripts/audit-verify.sh
      ```
      Most checks should PASS or SKIP. Investigate any FAIL before continuing.
- [ ] **Enable nightly database backups** (do this before you have any customers, so the habit + cron are in place):
      ```bash
      # Recipients file from Day 1 (your age public key)
      sudo install -Dm600 /dev/stdin /etc/0trust/backup-recipients.txt <<<'age1your_public_key_here'
      # Optional off-site target
      echo 'ZTV_OFFSITE=b2:0trust-backups' | sudo tee /etc/0trust/backup.env
      sudo cp /opt/0trust-src/systemd/0trust-backup.{service,timer} /etc/systemd/system/
      sudo cp /opt/0trust-src/scripts/backup.sh /opt/0trust/scripts/
      sudo systemctl daemon-reload
      sudo systemctl enable --now 0trust-backup.timer
      # Run once now to confirm it works end-to-end:
      sudo systemctl start 0trust-backup.service
      sudo ls -la /var/lib/0trust/backups/daily/
      ```
- [ ] **Verify you can decrypt** that first backup on your workstation:
      ```bash
      age -d -i ~/.age/0trust-backup.key 0trust-<ts>.db.age | sqlite3 :memory: '.tables'
      ```

---

## Day 3 — BTCPay

This is the longest single step because of Bitcoin sync time, even with
fastsync. Start it in the morning, expect to revisit in the afternoon.

```bash
# On the BTCPay host:
sudo BTCPAY_HOST=pay.0trustvpn.com \
     LETSENCRYPT_EMAIL=0trustvpn@proton.me \
     /opt/0trust-src/btcpay/scripts/bootstrap-lite.sh
```

- [ ] Verify `https://pay.0trustvpn.com/` resolves with a valid LE certificate
- [ ] **Register the admin account** at `https://pay.0trustvpn.com/Account/Register`
      — use a strong randomly-generated password from your manager
- [ ] Wait for Bitcoin fastsync to finish (~2 hours; check progress via `sudo /root/btcpayserver-docker/bitcoin-cli.sh getblockchaininfo`)
- [ ] Run configure.sh:
      ```bash
      sudo BTCPAY_HOST=pay.0trustvpn.com \
           BTCPAY_ADMIN_EMAIL='0trustvpn@proton.me' \
           BTCPAY_ADMIN_PASSWORD='paste-from-manager' \
           BTC_XPUB='zpub6msFu...vP1xU' \
           CONTROL_HOST=0trustvpn.com \
           /opt/0trust-src/btcpay/scripts/configure.sh
      ```
- [ ] Copy the `/tmp/0trust-btcpay.env` to the control plane:
      ```bash
      scp /tmp/0trust-btcpay.env root@0trustvpn.com:/tmp/
      ssh root@0trustvpn.com 'cat /tmp/0trust-btcpay.env >> /etc/0trust/api.env \
                            && systemctl restart 0trust-api \
                            && rm /tmp/0trust-btcpay.env'
      ```
- [ ] Smoke test:
      ```bash
      sudo CONTROL_URL=https://0trustvpn.com \
           BTCPAY_URL=https://pay.0trustvpn.com \
           BTCPAY_API_KEY=<admin-key-from-UI> \
           BTCPAY_STORE_ID=<from-configure-output> \
           /opt/0trust-src/btcpay/scripts/test-integration.sh
      ```
      Should print "INTEGRATION TEST PASSED" in under a minute.
- [ ] Enable BTCPay backups (see `btcpay/runbook.md` §2.7)

---

## Day 4 — Mesh nodes (all three)

We're running a deliberately small mesh: three nodes in three jurisdictions
outside any Eyes alliance.

| Code | Provider suggestion | Region | Role |
|------|---------------------|--------|------|
| `zur` | Init7 (Switzerland), Cloudsigma Zurich, BlackHOST | Zurich, CH | both |
| `rey` | 1984.is, FlokiNET (IS) | Reykjavik, IS | both |
| `buc` | M247 Bucharest, Hosterion, FlokiNET (RO) | Bucharest, RO | both |

For each of the three boxes (Ubuntu 24.04, 1 vCPU / 1GB / 10GB), two steps.

**On the control plane**, mint an enrolment token for that region:

```bash
sudo -u 0trust python3 /opt/0trust/api/mint-provision-token.py \
     --region zur --role both --uses 20 --ttl 31536000
```

or the same thing from the dashboard: **Nodes → Node enrolment token**, which
prints the exact command to run next.

**On the node**, one command:

```bash
sudo ./scripts/install.sh --mode node \
     --control-url https://0trustvpn.com \
     --region zur --role both \
     --provision-token ztvp-...
```

That is the whole deployment. The installer makes the box RAM-only — `/etc/wireguard`,
`/etc/0trust` and `/var/0trust` are tmpfs, swap is off, journald is volatile, which
is what web/privacy.html and `docs/AUDIT.md` §5.3 promise customers — generates a
WireGuard keypair in RAM, registers with the control plane, and starts meshd. There
is no SQL to run afterwards and nothing to copy back.

**Why `--uses 20` and not a one-shot token.** The node's disk is RAM, so a reboot
loses its key, its node id and its PSK. A single-use token cannot bring it back:
the box comes up and silently never rejoins, while the control plane goes on
handing customers an endpoint whose key no longer exists. An enrolment token pins
itself to that node's public IP on first use and re-registers the *same* node id
afterwards, so a reboot is a rejoin. The token lives in `/etc/0trust-node.env`
(root-only, the one 0trust file deliberately on persistent disk) and is inert
anywhere but that address.

- [ ] Revoke a node's token from the dashboard if the box ever leaves your
      control. The node keeps running on the PSK it holds; it just cannot
      register again.
- [ ] If the provider changes the node's public IP, the pinned token stops
      matching. Mint a new one and re-run the installer.

<details><summary>Manual alternative (fixed node id, shared PSK)</summary>

`scripts/bootstrap-node.sh` still exists for a node you want to name yourself.
It does not self-register — it prints the `INSERT` for you to run on the
control plane — and it cannot rejoin unattended after a reboot.

```bash
sudo CONTROL_URL=https://0trustvpn.com \
     NODE_API_PSK=<from-control-plane:/etc/0trust/api.env> \
     NODE_ID=zur-01 \
     REGION=zur \
     NODE_ROLE=both \
     /opt/0trust-src/scripts/bootstrap-node.sh
```

</details>

The `both` role means each node serves as either entry or exit depending
on the customer's chosen route. With three `both` nodes you get:

- 3 single-hop options (terminate at zur, rey, or buc)
- 6 multi-hop combinations (3 entries × 3 exits − 3 same-node pairs)
- 24h auto-rotation between pairs

For better privacy you can deploy more nodes per country later (e.g.,
two `zur` nodes both running `both` role). The schema and routing logic
already handle it; just run the node installer on more boxes with the same
region code, each with its own enrolment token.

### Verification (run after deploying all three)

- [ ] All three appear in the control plane:
      ```bash
      sudo sqlite3 /var/lib/0trust/0trust.db \
          'SELECT id,region,role,active,last_heartbeat FROM mesh_nodes;'
      ```
      Expect three rows, all `active=1`, recent heartbeats.

- [ ] The `/status` page on `https://0trustvpn.com/status` shows three
      regions, all `operational` (or `degraded` if you only have one
      per region — that's fine for v1).

- [ ] **End-to-end test from your own workstation**:
      ```bash
      sudo ./0trust login    # paste a test token
      sudo ./0trust connect zur                # single-hop Swiss
      curl ifconfig.me                         # should show zur node's IP
      sudo ./0trust connect zur --exit buc     # multi-hop CH→RO
      curl ifconfig.me                         # should show buc node's IP
      sudo ./0trust rotate                     # hot-swap to a different pair
      sudo ./0trust disconnect
      ```

- [ ] **Geographic verification** (paranoia check before launch):
      ```bash
      for region in zur rey buc; do
        sudo 0trust connect $region
        ip=$(curl -fsS ifconfig.me)
        country=$(curl -fsS "https://ipapi.co/$ip/country/" 2>/dev/null || echo '?')
        echo "$region → $ip → $country"
        sudo 0trust disconnect
      done
      # Expect: zur → CH, rey → IS, buc → RO. If anything else, abort.
      ```

If this works, **the system is functionally complete**. Everything from
here is hardening, polish, and announcing.

---

## Day 5 — Tor onion mirror + Polish

```bash
# On the same host as nginx (control plane):
sudo /opt/0trust-src/tor/scripts/bootstrap.sh
```

- [ ] Note the .onion address; back up the private key:
      ```bash
      age -r age1... -o /root/onion-backup.age \
          /var/lib/tor/0trust-hs/hs_ed25519_secret_key
      ```
- [ ] Test from Tor Browser: visit the clearnet site, look for the purple onion icon
- [ ] Update the landing page footer with the .onion address (manual edit of `web/index.html`)

### Self-host the support email

Pick one:

- [ ] **ProtonMail Business** — $13/mo per mailbox, supports custom domains and custom PGP keys
- [ ] **Tuta Premium** — €3/mo per mailbox, simpler crypto-payment workflow

For either:
- [ ] Set MX records per provider's docs
- [ ] Verify ownership of `0trustvpn.com` via DNS TXT record
- [ ] Upload your support PGP key (the one you generated Day 1)
- [ ] Configure the auto-reply with `support/templates/auto-reply.txt`
- [ ] Send yourself a test PGP-encrypted email to confirm decryption works
- [ ] Add `security@`, `legal@`, `archive@` aliases

### Publish the public-facing keys

- [ ] Upload PGP pubkeys to keys.openpgp.org:
      ```bash
      gpg --keyserver hkps://keys.openpgp.org --send-keys <support-fpr> <release-fpr>
      ```
      Verify the confirmation emails for each.
- [ ] Deploy `security.txt`:
      ```bash
      scp /tmp/security.txt root@0trustvpn.com:/var/www/0trust/.well-known/security.txt
      ```
- [ ] Deploy WKD files (from `support/scripts/generate-key.sh` output):
      ```bash
      scp -r wkd/ root@0trustvpn.com:/var/www/0trust/
      ```
- [ ] Verify discoverability: `gpg --auto-key-locate wkd --locate-keys 0trustvpn@proton.me`

---

## Day 6 — Warrant canary

Schedule a recurring weekly calendar reminder right now. Don't put this
off; the canary has more value the longer it runs unbroken.

- [ ] Sign and publish the first canary:
      ```bash
      export CANARY_SIGNER_NAME="Your Name"
      export CANARY_SIGNER_KEY=<fingerprint>
      sudo -E /opt/0trust/canary/scripts/generate.sh
      ```
      It asks for four current headlines and shows you the rendered document
      before it signs anything. Read it — that is the point of the step.
- [ ] Verify it serves correctly: `curl https://0trustvpn.com/canary.txt`
- [ ] Verify the signature: `gpg --verify canary.txt.sig canary.txt`
- [ ] Enable the freshness alarm:
      ```bash
      sudo cp /opt/0trust-src/canary/systemd/*.{service,timer} /etc/systemd/system/
      sudo systemctl enable --now 0trust-canary-check.timer
      sudo systemctl start 0trust-canary-check.service   # prove it runs
      systemctl status 0trust-canary-check.service
      ```
      `install.sh` stages the canary scripts under `/opt/0trust/canary/`, which
      is where the unit looks. Run it once by hand anyway: a timer that fails
      every night still reports `active` on the timer itself.
- [ ] Configure ALERT_WEBHOOK if you have a notification channel (Matrix, Signal-CLI, ntfy.sh):
      ```bash
      sudo install -m 0600 /opt/0trust-src/systemd/canary.env.example \
           /etc/0trust/canary.env
      sudo $EDITOR /etc/0trust/canary.env
      ```
      Without it the only notice of a lapsed canary is a `wall` message and a
      failed unit on a box nobody is logged into.

---

## Day 7 — Cut release 0.1.0

```bash
# On a workstation with the release signing key
cd /opt/0trust-src
git tag -a v0.1.0 -m "First release"

RELEASE_SIGNER_KEY=<release-fpr> ./scripts/release.sh 0.1.0
```

- [ ] Verify the release:
      ```bash
      ./scripts/verify-release.sh --release-dir releases/0.1.0/
      ```
- [ ] Upload `releases/0.1.0/` to the web host:
      ```bash
      rsync -av releases/0.1.0/ root@0trustvpn.com:/var/www/0trust/releases/0.1.0/
      ```
- [ ] Update the download page with the correct fingerprint (replace `DEADBEEF...`)
- [ ] Test the public download flow end-to-end from a separate machine

---

## Days 8-10 — Soft launch

- [ ] Pay for a one-month test subscription yourself via the full clearnet flow
- [ ] Connect, browse, disconnect, rotate, export to mobile, log out, log back in. Do everything a customer would.
- [ ] Run `audit-verify.sh` again on the live, customer-having system. Note any new findings.
- [ ] Recruit 2-3 trusted alpha users (friends in security-adjacent fields). Have them go through the same flow with fresh eyes. Listen to their complaints.
- [ ] Fix what they find. Re-release as 0.1.1 if needed.

---

## Days 11-14 — Public launch

- [ ] **Final review of public-facing copy**: landing page, help, audit, security-policy. Especially the explicit no-logs claims — make sure every word is true and verifiable.
- [ ] **Test failure modes**: kill the BTCPay box for an hour (test that customer disconnects are graceful). Kill a mesh node (test that the sweeper deactivates it). Re-test that paying customers can still connect during a BTCPay outage.
- [ ] **Announcements**, in order of escalation:
      1. Mastodon / Bluesky / Nostr — your existing personal accounts first
      2. r/PrivacyGuides, r/Monero, r/selfhosted — they have community standards, read them first
      3. Hacker News — submit as `Show HN: 0trust VPN — no-logs mesh VPN with multi-hop` once you're confident the site can handle ~2k visitors in 4 hours
      4. PrivacyGuides.org, PrivacyTools.io — these gate-keep, but inclusion drives sustained traffic. Write the submission carefully.
- [ ] **Commission the audit**: contact Cure53 or Assured AB. Quotes typically come back in 1-2 weeks. The audit itself takes 4-8 weeks. Plan to update the AUDIT.md based on findings and re-cut a release.

---

## Recurring weekly tasks

- [ ] Re-sign the warrant canary (Mondays, 09:00 local)
- [ ] Sweep the Monero hot wallet (after 10 confirmations on incoming, typically Fridays)
- [ ] Review `audit-verify.sh` output (or accept that you trust the cron alerts)
- [ ] Process customer support emails (target: 48h response, encrypted to PGP)
- [ ] **Review abuse ledger** — any patterns from this week's complaints? See `docs/ABUSE.md`

## Recurring monthly tasks

- [ ] Apply updates to the control plane host (`apt-get update && apt-get upgrade && reboot`)
- [ ] Apply updates to BTCPay (`./btcpay-update.sh` then re-run `test-integration.sh`)
- [ ] Apply updates to tor (`apt-get install --only-upgrade tor && systemctl restart tor`)
- [ ] Rotate Monero remote daemon (lite mode only — pick a different one from the runbook list)
- [ ] Verify backups: pull one backup off-host, decrypt it, make sure it's intact
- [ ] **Rotate one mesh node** as DR practice (see `docs/DR.md` Scenario 2)

## Recurring quarterly tasks

- [ ] Test the disaster-recovery procedure: stand up a fresh BTCPay box and restore from backup (see `docs/DR.md`)
- [ ] **Test control plane restore** — bring up a parallel instance, restore the latest age-encrypted DB, verify customers can authenticate against it
- [ ] Review AUDIT.md for accuracy as the system evolves
- [ ] **Review privacy policy + terms** — are they still accurate? Any drift between claims and reality?
- [ ] Audit-key rotation: generate fresh PGP keys for support and release, publish the transition signed by the OLD keys, deprecate the old keys after 90 days

---

## Cost summary (year 1)

| Item | One-time | Recurring (€/mo) |
|------|----------|------------------|
| Domain (`0trustvpn.com` via Njalla) | €15 reg + €15/yr | — |
| Control plane VPS | — | €5 |
| BTCPay VPS (lite) | — | €8 |
| Mesh nodes (3 × €4) | — | €12 |
| Email (ProtonMail Business) | — | €11 |
| Cure53 / Assured AB audit | €10k-30k once | — |
| Operator time | (your call) | ~10 hr/week |

Year 1 infrastructure: **€432**. Audit: **€10k-30k** (negotiable; can be
delayed until you have revenue).

Break-even at €8/month per customer (which is in the typical range for
a privacy VPN): **~55 customers** covers infrastructure. **3000+ customers**
to cover audit on the year-1 timeline. Privacy VPN customer acquisition
is slow; the audit can wait until you've grown into it.

---

## What you should NOT do at launch

- **Don't promise things you can't measure.** The audit pack is the
  ceiling of what's verifiable. Anything beyond that is marketing
  vapor that bites you when a journalist or auditor pokes at it.
- **Don't accept fiat.** Stripe, PayPal, etc. will ask for KYC and
  log every transaction. Stay crypto-only at launch. Pre-paid VISA
  workaround is a "future work" item.
- **Don't add IPv6 customer traffic until you've thought about leaks.**
  The default WireGuard config we ship is IPv4-only. IPv6 brings DNS
  leak risks that need separate handling.
- **Don't run a referral program.** Pay-per-signup affiliate networks
  collect customer data on your behalf, which means your no-logs claim
  now depends on them. Reject this category of growth lever.
- **Don't be persuaded to add telemetry to the client.** Ever. The
  client should remain stateless, anonymous, and not phone home except
  for the explicit API calls the customer triggers.

---

You're ready. The launch sequence is concrete; the recurring tasks are
manageable; the trade-offs are documented. Anything you encounter that
isn't covered here, ask early and document the answer for the next
operator.
