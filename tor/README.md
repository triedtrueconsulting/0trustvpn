# Tor onion service mirror

A `.onion` mirror of the 0trust landing site, run on the same host as
nginx. Customers can browse, read the audit pack, download the client,
and verify the canary — all without their ISP / DNS resolver learning
they visited us.

```
tor/
├── README.md                    (this file)
└── scripts/
    └── bootstrap.sh             Stand up tor + configure nginx + verify
```

## What it provides

| URL on clearnet | URL on the onion |
|-----------------|-----------------|
| `https://0trustvpn.com/` | `http://<...>.onion/` |
| `https://0trustvpn.com/help` | `http://<...>.onion/help` |
| `https://0trustvpn.com/canary.txt` | `http://<...>.onion/canary.txt` |
| `https://0trustvpn.com/download` | `http://<...>.onion/download` |
| `https://0trustvpn.com/audit` | `http://<...>.onion/audit` |
| `https://0trustvpn.com/releases/0.1.0/...` | `http://<...>.onion/releases/0.1.0/...` |
| `https://0trustvpn.com/api/v1/*` | **NOT EXPOSED** (clearnet only) |

The API surface is deliberately not exposed over the onion. Customer
auth tokens flow through `/api/v1/account/status`, `/wg/register`, etc.,
and those need rate-limiting and TLS pinning that nginx applies on the
clearnet server block. The onion is for browsing only.

## What it doesn't provide

- **It doesn't anonymize you, the operator.** The .onion address points at
  a 3-hop circuit terminating at this host. Your hosting provider still
  sees nginx running on a public IP. Tor protects *visitors*, not us.
- **It doesn't replace TLS for sensitive operations.** Customer API calls,
  webhook deliveries from BTCPay, mesh-node communications — all stay
  on clearnet over TLS.
- **It doesn't fix DNS for the operator.** The clearnet domain `0trustvpn.com`
  still resolves and is still subject to TLD-level seizure. The onion is
  a complementary path, not a replacement.

## Why both clearnet and onion?

Most customers will arrive via search engines and DNS. The clearnet site
is non-negotiable for discovery. The onion is a privacy upgrade for
customers who care, and a censorship-circumvention path for customers
who need it. The `Onion-Location` header on the clearnet site
auto-promotes Tor Browser users to the onion without them having to
remember the address.

## Setup

```bash
sudo ./tor/scripts/bootstrap.sh
```

Run this on the same host as nginx. The script:

1. Installs the current stable `tor` from the official Tor Project
   repo (not the often-stale Ubuntu fork).
2. Creates `/var/lib/tor/0trust-hs/` with the correct ownership.
3. Adds a v3 hidden service definition to `/etc/tor/torrc`.
4. Starts tor and waits for the .onion address to be generated.
5. Writes two nginx snippets:
   - `0trust-onion-server.conf` — the .onion-side server block
   - `0trust-onion-location.conf` — the `Onion-Location` header
6. Includes them from your existing nginx config.
7. Reloads nginx and tests the onion is reachable through the local
   tor SOCKS proxy.

When it finishes, it prints the .onion address. Publish that:

- Footer of the landing page
- "How do I contact you?" section of `/help`
- In the next warrant canary (under "Verification")
- On your Mastodon/Bluesky bio
- Anywhere else customers look for you

## Back up the private key

The most important post-deploy task. Without the key file at
`/var/lib/tor/0trust-hs/hs_ed25519_secret_key`, a host loss means a new
.onion address — and customers who bookmarked the old one can't find you.

```bash
# On your backup workstation, generate an age key
age-keygen -o ~/.age/onion-backup.key
# Copy the public key (age1...)

# On the BTCPay host (or wherever you ran bootstrap.sh):
sudo age -r age1... -o /root/onion-backup.age \
    /var/lib/tor/0trust-hs/hs_ed25519_secret_key

# Ship the .age file off-host:
rclone copy /root/onion-backup.age remote:backups/0trust/
```

To restore on a fresh host: decrypt `onion-backup.age` back into
`/var/lib/tor/0trust-hs/hs_ed25519_secret_key`, fix ownership
(`chown debian-tor:debian-tor`), and restart tor.

## Verification (run after first deploy)

From any machine with `tor` running:

```bash
curl --socks5-hostname 127.0.0.1:9050 -fsS http://<your-onion>.onion/ \
    | head -1
# Expect: <!DOCTYPE html>
```

In Tor Browser, navigate to your clearnet URL `https://0trustvpn.com/` —
you should see a purple onion icon in the address bar offering to
switch to the onion site. That's the `Onion-Location` header doing its job.

## Operational notes

### tor needs to keep running

`systemctl enable tor` is done by the bootstrap script. If the tor
service ever exits, the onion goes down — clearnet keeps working.
Monitor:

```bash
systemctl status tor
journalctl -u tor --since '1 hour ago' | grep -iE '(error|warn)'
```

### Updating tor

When upstream releases a new tor:

```bash
sudo apt-get update
sudo apt-get install --only-upgrade tor
sudo systemctl restart tor
```

The .onion address survives across updates.

### Rotating the .onion address (if compromised)

If you suspect the private key has leaked:

```bash
sudo systemctl stop tor
sudo rm -rf /var/lib/tor/0trust-hs
sudo /opt/0trust/tor/scripts/bootstrap.sh
```

A new .onion is generated. Update all publication points. Announce the
change in the next canary. The old onion goes dark within minutes.
