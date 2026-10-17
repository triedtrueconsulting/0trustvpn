# Production readiness pack

Audit date 2026-10-17. Produced by a full-codebase audit, test, repair and
hardening pass over the 0trust VPN service.

Read in this order:

| Document | What it answers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | What the system is, as built — components, trust boundaries, deliberate non-goals |
| [INITIAL-AUDIT.md](INITIAL-AUDIT.md) | Baseline state, what the first pass found, what this audit changed |
| [SECURITY-AUDIT.md](SECURITY-AUDIT.md) | Findings with severity, areas reviewed clean, residual risks that are design decisions |
| [WIREGUARD-TEST-RESULTS.md](WIREGUARD-TEST-RESULTS.md) | What was verified against a real kernel, and precisely what could not be |
| [TEST-RESULTS.md](TEST-RESULTS.md) | Every check, with the command and its output |
| [DEPLOYMENT-CHECKLIST.md](DEPLOYMENT-CHECKLIST.md) | The release gate — each item with the command that proves it |
| [ROLLBACK-AND-RECOVERY.md](ROLLBACK-AND-RECOVERY.md) | Coming back from a bad deploy; the states where the service is up and the product is not |
| [REMAINING-RISKS.md](REMAINING-RISKS.md) | What is still open, ordered by cost |

## The short version

**CONDITIONALLY READY.** The engineering is in good shape and the
verification has two holes that no amount of work in a container can close.

Three things block a public launch, none of them a code defect:

1. **Two extended public keys sit in git history** and their provenance is
   unknown. If either belongs to the operator, the funds must move — an
   xpub cannot be rotated. The detection gap that hid them is fixed; the
   exposure is not. (SECURITY-AUDIT.md SEC-1, REMAINING-RISKS.md R1)
2. **No WireGuard tunnel has ever carried a packet** in any environment
   that has run this code, because no environment had the kernel module.
   The firewall and routing layers *are* verified against a real kernel,
   but that is a different claim. (WIREGUARD-TEST-RESULTS.md §1)
3. **Legal and VAT review** — not engineering, and required before the
   first sale. (REMAINING-RISKS.md R8)

Neither mobile app has ever been compiled or run on a device, which blocks
those platforms specifically rather than a desktop-and-CLI launch.

## Verification standard used

Where this pack says something passes, there is a command behind it. Where
something could not be tested, it says so and names the gate that has to
run elsewhere — rather than reporting a skip as a pass, which is a failure
mode this codebase has been bitten by and now has a bug class for.

Every gate added during this audit was mutation-tested: the thing it guards
was broken on purpose and the gate was watched going red. Five rules and
checks written during this audit were dead on arrival and only found that
way.
