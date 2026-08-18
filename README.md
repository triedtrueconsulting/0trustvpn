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

## Deploy

```bash
sudo ./scripts/install.sh --mode test                     # no domain, no TLS
sudo ./scripts/install.sh --mode production \
     --domain 0trustvpn.com --email you@example.com       # domain + Let's Encrypt
```

Idempotent, and `--dry-run` shows what a run would do without touching the
box. Full walkthrough in [`docs/DEPLOY.md`](docs/DEPLOY.md).

## Validate a change

```bash
./scripts/validate.sh          # the whole battery
./scripts/validate.sh go api   # only checks whose id contains these
./scripts/validate.sh -l       # list the check ids
```

Thirteen checks: `go vet`, `go test`, all six cross-compile targets, real .deb
packages, the control-plane smoke test, every `.py`/`.sh`/`.html`/`.xml`/`.json`/
`.yaml` parsed, and the two invariants that keep biting — only `zur`/`rey`/`buc`
appear as region codes, and clients authenticate with `X-Account-Token` rather
than a bearer token. Exit code is the number of failures.

The same battery runs in CI on every push to `main` and every pull request
against it (`.github/workflows/validate.yml`), so local, web-session and CI all
gate on one definition of green.

Claude Code on the web provisions itself via `.claude/hooks/session-start.sh`.
Working locally, create the venv the script expects:

```bash
python3 -m venv .venv && .venv/bin/pip install -r api/requirements-dev.txt
export PATH="$PWD/.venv/bin:$PATH"
```

Android APKs need Android Studio + NDK; the MSI needs a Windows host with WiX.
Everything else builds on Linux.

## Status

Engineering for v0.1 is complete and validated. What remains is operator
action — provisioning servers, generating signing keys, compiling signed
installers, legal review, commissioning a third-party audit. See the
"Remaining" section of `CLAUDE.md` and `docs/LAUNCH.md`.
