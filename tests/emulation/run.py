#!/usr/bin/env python3
"""
Run the whole emulation suite.

Each module boots a real stack — fake BTCPay, the real FastAPI control plane
under uvicorn, and where relevant the compiled Go client and the real meshd
daemon against stubbed wg/nft/ip — then drives it and asserts on the result.

    ./tests/emulation/run.py              # everything
    ./tests/emulation/run.py client meshd # only matching modules

Exit code is the number of failed modules.
"""
import os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))


def interpreter() -> str:
    """
    The Python that can import fastapi. Prefer the one running us, so an
    activated venv or a CI job wins; otherwise fall back to the repo venv that
    .claude/hooks/session-start.sh builds. Same resolution scripts/validate.sh
    uses, so both entry points behave identically.
    """
    if subprocess.call([sys.executable, "-c", "import fastapi"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        return sys.executable
    venv = os.path.join(REPO, ".venv", "bin", "python")
    if os.path.exists(venv):
        return venv
    sys.exit("fastapi is not importable, and no .venv found. "
             "Create one: python3 -m venv .venv && "
             ".venv/bin/pip install -r api/requirements-dev.txt")
MODULES = [
    ("lifecycle",    "signup, payment, devices, multi-hop, node lifecycle, sweeper"),
    ("concurrency",  "parallel writers, degenerate topologies, auth edges"),
    ("payments",     "BTC/XMR/ZEC through BTCPay and a hosted gateway"),
    ("trial",        "proof-of-work, redemption, trial limits, conversion"),
    ("client",       "the compiled 0trust binary, end to end"),
    ("meshd",        "the mesh node daemon against a live control plane"),
    ("integration",  "pubkey escaping and GUI polling pressure"),
    ("proxy_guards", "SSRF and content rails, nothing patched"),
    ("proxy",        "the visitor proxy against a real origin server"),
    ("funnel",       "trial signup in a real browser (skips without chromium)"),
    ("gui",          "the desktop GUI in a real browser (skips without chromium)"),
    ("install",      "installer flags and the nginx configs it renders"),
    ("site",         "website links, and copy that matches the code"),
    ("security",       "authorization boundaries under adversarial input"),
    ("multihop_netns", "real packets through entry->exit NAT (needs CAP_NET_ADMIN)"),
    ("admin",          "the operations backend: auth, controls, audit trail"),
    ("admin_ui",       "the operations dashboard in a real browser"),
]

def main(argv):
    wanted = argv[1:]
    picked = [m for m in MODULES if not wanted or any(w in m[0] for w in wanted)]
    if not picked:
        print(f"no module matches {wanted}; known: {[m[0] for m in MODULES]}")
        return 64

    py = interpreter()
    failed, skipped = [], []
    for name, desc in picked:
        print(f"\n{'=' * 68}\n  {name} — {desc}\n{'=' * 68}")
        t0 = time.time()
        rc = subprocess.call([py, os.path.join(HERE, f"test_{name}.py")])
        # 77 means the module's prerequisites are absent (no browser, say).
        # That's a skip, not a failure — the same convention validate.sh uses.
        label = "ok" if rc == 0 else ("skipped" if rc == 77 else "FAILED")
        print(f"  [{name}] {label} in {time.time() - t0:.0f}s")
        if rc not in (0, 77):
            failed.append(name)
        elif rc == 77:
            skipped.append(name)

    print(f"\n{'=' * 68}")
    tail = f" ({len(skipped)} skipped: {', '.join(skipped)})" if skipped else ""
    if failed:
        print(f"  emulation: {len(failed)} module(s) failed: {', '.join(failed)}{tail}")
    else:
        print(f"  emulation: all {len(picked) - len(skipped)} modules passed{tail}")
    return len(failed)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
