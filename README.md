# 0trustvpn

A true 0 trust VPN — an anonymous WireGuard mesh service. No email, no name,
no password. Pay in crypto, get a 16-character token, route traffic through a
mesh that doesn't know who you are.

Traffic exits through three nodes in three jurisdictions outside the
Five/Nine/Fourteen Eyes alliances — `zur` (Zurich), `rey` (Reykjavik), `buc`
(Bucharest) — single-hop, or multi-hop where the entry node can't decrypt and
the exit node never sees your IP.

## Where things live

| Path | What it is |
| --- | --- |
| `api/` | FastAPI + SQLite control plane, BTCPay integration, expiry sweeper |
| `client/` | Go CLI and browser GUI; WireGuard control for Linux/macOS/Windows |
| `mobile/android/` | Kotlin/Compose app |
| `mobile/ios/` | Skeleton — out of scope for v0.1 (QR export covers iOS) |
| `wireguard/` | RAM-only ephemeral node daemon and cloud-init |
| `installer/` | Windows WiX MSI, Linux `.deb` and AppImage builders |
| `btcpay/` | BTCPay Server deployment and runbook |
| `canary/` | PGP-signed warrant canary |
| `tor/` | v3 onion mirror |
| `web/` | Landing site, status, help, legal pages |
| `docs/` | Full documentation — start with `docs/README.md` |

## Start here

- **`CLAUDE.md`** — project guide: locked decisions, architecture invariants,
  recurring bug classes, and the validation battery. Read it before changing
  anything; Claude Code loads it automatically.
- **`docs/README.md`** — architecture, components, threat model, deployment.
- **`docs/LAUNCH.md`** — the day-by-day playbook for going live.

## Validate a change

```bash
# Go client: vet + all six release targets
cd client && CGO_ENABLED=0 go vet ./... && make all && cd ..

# Python: parse everything
python3 -c "import ast,glob; [ast.parse(open(f).read()) for f in glob.glob('**/*.py',recursive=True)]"

# Shell: syntax-check every script
for f in $(find . -name '*.sh' -not -path './.git/*'); do bash -n "$f" || echo "FAIL: $f"; done

# Markup: web pages, Android resources, the MSI source
python3 -c "import html.parser,glob
class P(html.parser.HTMLParser): pass
[P().feed(open(f).read()) for f in glob.glob('web/*.html')]"
python3 -c "import xml.etree.ElementTree as ET,glob
[ET.parse(f) for f in glob.glob('mobile/android/**/*.xml',recursive=True)+glob.glob('installer/**/*.wxs',recursive=True)]"

# Stale region codes — only zur/rey/buc are valid
grep -rnE '\b(ams|fra|lon|sto|nyc|sjc|sgp|tyo)-[0-9]+\b' --exclude-dir=.git .
```

Android APKs need Android Studio + NDK; the MSI needs a Windows host with WiX.
Everything else builds on Linux.

## Status

Engineering for v0.1 is complete and validated. What remains is operator
action — provisioning servers, generating signing keys, compiling signed
installers, legal review, commissioning a third-party audit. See the
"Remaining" section of `CLAUDE.md` and `docs/LAUNCH.md`.
