# BTCPay Server for 0trust VPN

Self-hosted Bitcoin + Monero payment processing. Wraps the official
[BTCPay Server](https://btcpayserver.org/) Docker deployment with the
specific configuration 0trust needs.

```
btcpay/
├── README.md                          (this file)
├── runbook.md                         Full operations playbook
├── scripts/
│   ├── bootstrap.sh                   Full deployment (large server)
│   ├── bootstrap-lite.sh              Lite deployment (small VPS)
│   ├── configure.sh                   Store + wallets + webhook + API key
│   ├── test-integration.sh            End-to-end smoke test
│   └── backup.sh                      Encrypted daily backup
├── systemd/
│   └── btcpay-backup.{service,timer}
└── docker/
    ├── monero-remote.override.yml     Compose override for remote XMR daemon
    └── btcpay-backup.env.example
```

## Pick a deployment size

|                          | **Full** (`bootstrap.sh`)     | **Lite** (`bootstrap-lite.sh`)        |
|--------------------------|-------------------------------|---------------------------------------|
| Disk                     | ~200GB                        | ~15GB                                 |
| RAM                      | 8GB                           | 4GB                                   |
| Monthly cost (typ. VPS)  | $30-50                        | $5-10                                 |
| Time to first payment    | 1-3 days (Monero sync)        | 2-3 hours (BTC fastsync)              |
| Bitcoin storage          | 50GB pruned, local            | ~10GB pruned, local                   |
| Monero storage           | ~150GB full node, local       | ~500MB wallet-RPC only, remote daemon |
| What's local             | Full BTC + XMR chains         | Pruned BTC + XMR wallet only          |
| What's remote            | Nothing                       | Monero blockchain                     |
| Privacy concern          | None                          | Remote XMR node sees you polling      |

**Pick lite** if you're starting out, running on a single small VPS, or
have low expected volume. You can graduate to full later — the swap is
"rsync the wallet over, re-run configure.sh" — without customer-facing impact.

**Pick full** if you want zero third-party dependencies in your payment
path, have the budget for a dedicated host, and accept the longer initial
sync.

## Quick start (lite)

```bash
# On a fresh Ubuntu 24.04 VPS (~$8/mo class) with DNS pointing at it:
sudo BTCPAY_HOST=pay.0trustvpn.com \
     LETSENCRYPT_EMAIL=0trustvpn@proton.me \
     ./btcpay/scripts/bootstrap-lite.sh

# Browse to the admin URL and register the first account, then:
sudo BTCPAY_HOST=pay.0trustvpn.com \
     BTCPAY_ADMIN_EMAIL=0trustvpn@proton.me \
     BTCPAY_ADMIN_PASSWORD='...' \
     BTC_XPUB='zpub6m...' \
     CONTROL_HOST=0trustvpn.com \
     ./btcpay/scripts/configure.sh

# Wait ~2 hours for Bitcoin fastsync (Monero is instant via remote daemon).
# Then verify end-to-end:
sudo ./btcpay/scripts/test-integration.sh
```

## What goes where (lite)

- **Bitcoin keys**: cold wallet, never on this box. BTCPay watches the xpub.
- **Bitcoin blockchain**: pruned locally to ~10GB.
- **Monero spend key**: in `monero-wallet-rpc` on this box. Sweep weekly.
- **Monero blockchain**: NOT on this box. Provided by a public remote daemon.
- **API key + webhook secret**: in the control plane's `/etc/0trust/api.env`.

## Full operations docs

Read [`runbook.md`](runbook.md) before going to production. Covers both
deployment modes, day-2 ops (Monero sweeps, updates, webhook debugging),
disaster recovery, and security invariants for the audit.

## Why not run BTCPay on the same box as the control plane?

Two reasons:

1. **Blast radius.** A BTCPay compromise gives an attacker the Monero
   hot wallet but no control-plane data. A control-plane compromise gives
   them account tokens but no payment keys. Keeping them separated means
   one compromise is recoverable.

2. **Resource isolation.** Even in lite mode, BTCPay's Bitcoin node and
   wallet RPCs benefit from dedicated CPU. The 0trust control plane is
   tiny by comparison and benefits from running on a smaller, more
   locked-down host.

Different hosting providers for the two boxes is even better.
