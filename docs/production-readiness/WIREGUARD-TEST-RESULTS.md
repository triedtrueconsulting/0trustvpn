# WireGuard verification — what was tested, and what could not be

Audit date 2026-10-17.

This document is written to be falsifiable. Where a property was verified
against a real kernel, it says so and names the assertions. Where it was
not, it says that instead, states precisely why, and names the gate that
has to be run elsewhere. A VPN audit that blurs the two is worthless.

---

## 1. Environmental limitation — read this first

**The WireGuard kernel module is not available in this environment and
neither are the `wg` userspace tools.**

```
$ ip link add dev ztvprobe type wireguard
Error: Unknown device type.

$ command -v wg
(absent)

$ lsmod | grep -i wireguard
not loaded                      # modprobe is not present either

$ uname -r
6.18.44-fc-v139                 # microVM kernel, no WireGuard
```

Network namespaces and veth pairs **do** work, which is what made the
packet-path testing in §2 possible:

```
$ ip netns add ztvprobe && ip netns del ztvprobe
netns: WORKS
```

### What this means cannot be claimed

The following have **not** been executed anywhere, by this audit or by CI,
and must not be reported as verified:

| Property | Why it could not be tested |
|---|---|
| A real WireGuard handshake completes against a node | No WireGuard device type |
| Traffic through an established tunnel is encrypted on the wire | Same |
| The published MTU is correct for either transport | Needs a real tunnel carrying full-size packets |
| No DNS leak outside the tunnel on a live client | Needs a real tunnel and a real resolver path |
| No IPv4/IPv6 leak outside the tunnel on a live client | Same |
| The kill switch actually blocks traffic when the tunnel drops | Needs a real tunnel to drop |
| `wg syncconf` applies a generated peer set | No `wg` binary |

This is the single largest gap in the verification of this product, and it
is an environment limitation rather than a defect. §5 states what has to be
run on real hardware before launch.

## 2. What WAS verified against a real kernel

Network namespaces, veth pairs and **real nftables rulesets loaded by the
real `nft` binary**. These are not simulations: the rules under test are the
ones `meshd` and `node-runtime.sh` generate, loaded into a live kernel, with
packets pushed through them.

### 2.1 `test_multihop_netns.py` — 27 assertions, all passing

| Section | What it establishes |
|---|---|
| [1] | The ruleset meshd generates is one `nft` will actually load |
| [2] | A packet really traverses client → entry → exit |
| [3] | **The privacy property: the exit must NOT see the client** |
| [4] | The rule holds whatever source port the client picks |
| [5] | The old rule is proven broken — and intermittently so |
| [6] | The rules a node installs, from the shared library |
| [7] | The egress filter blocks what it claims to |

Section [3] is the one that matters most for the product's claims. In
multi-hop, the exit node must see the entry node as the source and never the
customer. That is tested by sending a packet and reading what arrives.

Section [5] is unusual and worth keeping: it asserts that the *previous*
rule was broken, so the fix cannot silently regress to it.

Section [7] confirms the egress filter drops outbound SMTP, RFC1918 pivots
and link-local pivots, holds a connection-rate limit, and leaves non-mesh
traffic alone.

### 2.2 `test_onebox_netns.py` — 26 assertions, all passing

| Section | What it establishes |
|---|---|
| [1] | Multi-hop DNAT works when entry and exit are the same host |
| [2] | Three nodes on one box do not erase each other's rules |
| [3] | Per-peer routes send replies to the right interface |
| [4] | IPv6 is forwarded and masqueraded, not merely configured |

[2] and [3] are both real failure modes with no symptom at configuration
time. Each meshd replaces its whole nftables table every poll, so co-located
nodes sharing a table name erase each other every 30 seconds. And three
WireGuard interfaces in one `/10` give the kernel three equally good routes
to any client, so without a `/32` per peer, replies for a client on `wg2`
can be handed to `wg0`, which has never heard of it.

[4] verifies NAT66 masquerades the v6 mesh prefix, that the v4 masquerade
survives alongside it, that the kernel accepts the dual-stack ruleset, that
both masquerade rules are live, and **that customers cannot reach each other
over v6** — peer isolation tested in the family where it is easiest to
forget.

### 2.3 `test_routing.py` — 54 assertions, all passing

Covers peer selection and the invariants around it: single-hop hands exactly
one peer, the node named is the node used, only the routing node holds the
customer's key, a node that stopped answering is not handed out, load
spreads by room left rather than declared capacity, and the IPv6 address is
issued only where it can actually go.

### 2.4 `test_meshd.py` and `test_node.py`

`test_meshd.py` boots the real daemon: peer propagation to the exit node,
multi-hop becoming a DNAT rule on the entry node, heartbeat, revocation
withdrawing a peer, survival of a control-plane outage, a malformed peer
being skipped rather than killing the whole sync, and the SOCKS5 control
channel never falling back to direct.

`test_node.py` covers enrolment end to end, including the reboot case — key
gone, node returns under the same id — IP binding, one-shot token semantics,
revocation, and that upstream DNS leaves the node encrypted or not at all.

### 2.5 `test_obfs.py` — the transport, executed

The Shadowsocks AEAD relay is built and run for real: real packets through
the real relay, the relay refusing to act as an open proxy, a wrong key
getting nothing and saying nothing, and — the important one — **the Android
app's own Kotlin transport compiled on a plain JVM and pushed against the
Go relay**. That is the mitigation for having two implementations of one
wire format, and it executes.

## 3. Active probe of the control plane

48 assertions, written for this audit, all passing. No defects found.

- **Authorization:** unauthenticated access refused; `Authorization: Bearer`
  not accepted; account B cannot delete or see account A's device; a
  customer token cannot read the peer manifest.
- **Key ingest:** a 44-character "key" containing a newline and a directive
  fragment is refused — the exact shape that would otherwise reach
  `wg syncconf` as root and break peer sync for every customer on the node.
  So are 43-char, 31-byte and 33-byte encodings, and non-base64.
- **Region and multi-hop:** stale codes (`ams`/`fra`/`lon`), traversal,
  NUL bytes and overlong values all refused; entry == exit refused.
- **Money:** every term outside `PRICING` refused; a client-supplied
  `amount_usd` never reaches the invoice.
- **Tokens:** unique over 200 draws, 16 alphabet characters in 4-char
  groups, no ambiguous `I/O/0/1`, stored only as a hash, with case and
  dashes normalised before hashing.

Everything that initially looked like a finding in this probe turned out to
be a bug in the probe, and each was verified against the code before being
dismissed. The one that deserved real scrutiny was
`GET /api/v1/payment/{id}/status` answering 200 with no credential: that is
**by design** — the invoice id is itself the bearer capability, which is
precisely why both nginx and uvicorn drop that request path from their logs.
The property that actually matters is that the id is unguessable, and the
default provider derives it from `secrets.token_urlsafe(18)` — 144 bits.

## 3b. A real `install.sh --mode test` run, end to end

Run on this container (Ubuntu 24.04, root, no systemd, no WireGuard kernel
module) against the real script — not the render path.

**Where it got to.** Packages, service user and directories, application
code and venv, fresh secrets (`api.env`, `proxy.env`, `backup.env`), the
database with all 16 tables, systemd unit files, the website, and the nginx
configuration — `nginx -t` passed on the generated config. It then stopped
at `systemctl`, loudly, with `RC=1`:

```
[+] Installing systemd units
System has not been booted with systemd as init system (PID 1). Can't operate.
```

No claim of success, no partial-success summary. Correct.

**The interesting run.** Stubbing `systemctl` to return success for
everything simulates the realistic case this maps to — an **LXC VPS, which
has systemd but no WireGuard module**. The installer completed, and did not
believe the stub:

```
[✓] 0trust-api answering, sweep + poll timers armed
[!] nginx is NOT serving on port 80
...
[!] WireGuard interface(s) NOT up: wg0 wg1 wg2
...
  The VPN is NOT up. The control plane, website, admin dashboard
  and /surf proxy all work — but meshd could not create the WireGuard
  interfaces, so `0trust connect` will hand out a config that cannot carry
  traffic.
```

It probed `ip link show` and port 80 rather than trusting a zero exit
status from the service manager. That is bug class #16 holding under a
service manager that was actively lying to it.

**The customer flow, against the installed stack.** The API was started
from `/opt/0trust/api/.venv` with the installed `api.env`, exactly as the
unit would:

| Step | Result |
|---|---|
| `GET /api/v1/config` | pricing from `PRICING`, `trial.label` "one week" |
| `GET /api/v1/status/public` | `service: down` before nodes existed — honest |
| Trial challenge → 20-bit PoW → redeem | token issued, 16 chars in 4-char groups |
| `GET /api/v1/account/status` | `plan: trial`, `max_devices: 2` — the trial cap, published not hardcoded |
| `POST /api/v1/wg/register` | `10.64.0.2/32`, DNS `10.64.0.1`, MTU 1420 |
| peers returned | **exactly one**, `allowed_ips: ["0.0.0.0/0", "::/0"]` |
| v6 address | none issued — no node reports v6 egress, which is the safe branch |

Several invariants are visible in that one response: one peer and never a
list, both families claimed, the MTU published by the server rather than
computed in the client, and the device cap coming from the API.

**`audit-verify.sh` against a real deployment** — the first chance in this
audit to run it anywhere but a bare repo:

```
PASS: 28    FAIL: 2    SKIP: 11      (bare repo was 13 / 1 / 27)
```

The nginx privacy checks now **pass against the deployed config**, not the
reference file: `nginx-anonymizes-ip`, `nginx-no-user-agent`,
`nginx-log-no-secret-paths`, `nginx-canary-no-cache`, `api-no-access-log`.
That is the gap CLAUDE.md calls the worst claim-vs-reality defect the
product has had, confirmed closed on a real install.

Both failures are the verifier working, not defects:

- `juris-public-ip-geolocate` — all three nodes share `192.0.2.2`
  (TEST-NET-1), so it reports them as placeholders rather than three
  countries. Exactly what `--mode test` says about itself.
- `cdn-disclosed` — fires in the *other* direction: privacy.html discloses
  a CDN this deployment is not behind, because it was installed without
  `--cloudflare`.

**A suspicion checked and dismissed.** After node registration,
`/status/public` reported `operational` for all three regions while the
installer had just said the VPN was not up. The heartbeat body carries only
`node_id` and `ipv6` — nothing about interface state — so a node that
cannot build its tunnel heartbeating its way to "operational" would be the
documented NAT failure all over again. It does not happen:
`bootstrap_interface()` runs **before** the loop's first `heartbeat()` and
uses `check=True`, so meshd dies rather than reporting itself alive. Run
directly, it exits 1 with `CalledProcessError` on
`ip link add wg0 type wireguard`. The `operational` reading came from the
registration timestamp and ages out after `NODE_STALE_SECS` (300s), the
same window as any node death. Safe direction, bounded window, no change
made.

## 4. Static analysis

`tests/sast/ztv.yml`, 8 rules, run over `api proxy wireguard btcpay canary
support`: **0 findings**. All eight rules mutation-tested against planted
violations; the gate itself was mutation-tested end to end.

Notably clean: no blocking call inside any `async def` (a documented
invariant here, and the cause of a past full-service freeze on `/surf`), no
`shell=True`, no disabled TLS verification, no `eval`/`exec`, no
timing-unsafe credential comparison.

## 5. What must be run on real hardware before launch

These are gates, not suggestions. Each needs a machine this environment
cannot provide.

1. **A real tunnel, end to end.** Bring up a node, connect a client, confirm
   a handshake, pass traffic. `0trust connect` already refuses to claim
   success without a handshake; confirm it on real hardware.
2. **Leak testing on a live tunnel** — DNS, IPv4, IPv6, on a dual-stack
   host. The v6 design deliberately claims `::/0` without an address when
   the exit has no v6 egress; confirm that blackholes rather than leaks.
3. **MTU under load, both transports.** The failure mode is a healthy
   tunnel that silently drops full-size packets, which reaches the customer
   as "some sites hang" and is unattributable. Test with and without the
   relay's 55-byte overhead.
4. **Kill switch on Linux.** Drop the tunnel and confirm traffic stops.
   Confirm `PreDown` cannot strand a user offline.
5. **Reboot a RAM node** and confirm it rejoins under the same id with NAT
   and the egress filter reapplied. The test suite covers the logic; the
   failure this guards against was a real outage where traffic entered the
   tunnel and died silently while the node kept heartbeating.
6. **`./gradlew assembleDebug` on a real handset.** Nothing has ever run the
   Android integration on a device. Expect the AllowedIPs routing exclusion
   to be the part that needs attention.
7. **`xcodegen generate && xcodebuild` on a Mac.** Nothing has ever compiled
   the iOS app. Expect compile errors; treat the first build as the gate.
