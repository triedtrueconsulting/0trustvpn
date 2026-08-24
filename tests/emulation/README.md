# Emulation suite

Boots the product and drives it, rather than testing functions in isolation.
Every module here starts a real stack:

| piece | what actually runs |
| --- | --- |
| control plane | the real `api/main.py` under uvicorn, on a temp SQLite DB |
| BTCPay | `fake_btcpay.py` — enough Greenfield surface to mint and settle invoices, and it signs its webhooks with the real HMAC scheme |
| mesh node | the real `wireguard/0trust-meshd.py` |
| CLI / GUI | the real compiled `client/cmd/0trust` binary |
| `wg` / `wg-quick` / `nft` / `ip` | stubs in `bin/`, which record what they were asked to do so tests can assert on the resulting peer list and DNAT ruleset |

Only the kernel-level networking is stubbed. Everything above it is the code
that ships.

```bash
./tests/emulation/run.py               # all modules
./tests/emulation/run.py client meshd  # just these
./tests/emulation/test_lifecycle.py    # one module directly
```

Needs the venv from `api/requirements-dev.txt` on PATH and a Go toolchain.
`scripts/validate.sh` runs the suite as the `emulation` check.

## What each module covers

- **test_lifecycle** — signup through BTCPay, webhook settlement and replay,
  device registration and removal, multi-hop allocation, rotation, node
  provisioning and heartbeat, the public status page, and a sweeper run.
- **test_concurrency** — parallel writers racing for mesh IPs, entry ports and
  node ids; topologies with no exit node; token and webhook auth edges.
- **test_client** — `login`, `status`, `regions`, `connect` (twice, single and
  multi-hop), `rotate`, `devices`, `remove`, `export`, `disconnect`, `logout`.
- **test_meshd** — peer propagation to `wg`, DNAT rule installation, heartbeat
  attribution, revocation, and survival of a control-plane outage.
- **test_integration** — public keys containing `/` and `+` through the delete
  path, and that the GUI's 3s poll does not become 20 upstream calls a minute.
- **test_apps** — the Android app and the Windows MSI, neither of which can be
  compiled here (no Android SDK, no reachable Google Maven, and WiX is
  Windows-only). It boots the control plane and compares the Kotlin
  `@SerialName` keys against real JSON from real calls — the drift that broke
  the Android client once — then checks the manifest invariants and the MSI's
  build inputs and uninstall behaviour. `mobile/android/syntax-check.sh` is the
  other half: it parses the Kotlin with the real compiler front-end.
- **test_funnel / test_gui / test_admin_ui / test_site_ui** — the four modules
  that drive a real Chromium. They exit 77 (skip) where Playwright or a browser
  is absent, which is the case on CI, so run them locally before shipping
  anything with a visual surface. `test_site_ui` is the one that renders the
  shared nav at five viewport widths: unreadable buttons, controls pushed off
  the right edge of a phone, and content sitting under the fixed bar are all
  invisible to a source-level check and all shipped past one before.

## Adding a case

Put shared setup in `harness.py` (`boot`, `call`, `settle`, `paid_account`,
`seed_nodes`, `mint_provision_token`). A module is a plain script: build state,
call `check(name, condition, detail)`, exit non-zero if anything failed.
