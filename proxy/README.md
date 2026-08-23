# Visitor proxy (`/surf`)

A quick way to read a public page through our egress, and the top of the
signup funnel: after a few pages the banner offers a free trial of the VPN. The
length comes from the control plane, so the banner never advertises an offer the
API no longer grants.

Runs as its own service on its own port. That isolation is the point — abuse
complaints, blocklisting, or a crash here must not touch the control plane.

```bash
ZTV_PROXY_PORT=8081 ZTV_PROXY_BLOCKLIST=example-abuse.test \
  python3 proxy/server.py
# or: systemctl start 0trust-proxy
```

| variable | default | meaning |
| --- | --- | --- |
| `ZTV_PROXY_PORT` | `8081` | listen port (loopback only; nginx fronts it) |
| `ZTV_PROXY_PREFIX` | `/surf` | public path |
| `ZTV_PROXY_BLOCKLIST` | empty | comma-separated host suffixes to refuse |
| `ZTV_PROXY_UA` | `0trust-surf/1.0` | User-Agent sent upstream |
| `ZTV_PROXY_TRIAL_AFTER` | `3` | page views before the offer sharpens |

## What it will not do

`guards.py` is the whole security argument; read it before changing anything
here. In summary: GET and HEAD only, http/https only, ports 80 and 443 only,
public unicast destinations only (re-checked on every redirect, so a DNS
rebind cannot walk past the first check), 5 MB and 12 s caps, and a content
type allowlist that excludes archives and executables. No cookies, Referer or
credentials go upstream; no `Set-Cookie` comes back.

Responses carry a CSP with `script-src 'none'`, and the rewriter strips
`<script>` and `on*` handlers, so a proxied page cannot execute in our origin.

## Honest limits, stated in the UI

The banner says this out loud, and it should keep saying it:

- It is **not** the VPN. One browser tab, nothing else on the device.
- The visitor's ISP still sees the connection to us.
- The origin sees a datacentre address shared with every other visitor.
- Scripts are stripped, so script-dependent sites will look broken.

Overstating this would be the exact claim-vs-reality drift `CLAUDE.md` warns
about, on the most visible page we have.

## Abuse

An open proxy attracts abuse regardless of the rails. `ZTV_PROXY_BLOCKLIST`
is the fast lever, the egress should be an IP you can rotate without moving
the main site, and `docs/ABUSE.md` covers the complaint workflow. Watch for
the egress landing on blocklists — that is the failure mode that arrives
first and is slowest to undo.
