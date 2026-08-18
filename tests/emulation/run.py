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
    ("lifecycle",   "signup, payment, devices, multi-hop, node lifecycle, sweeper"),
    ("concurrency", "parallel writers, degenerate topologies, auth edges"),
    ("client",      "the compiled 0trust binary, end to end"),
    ("meshd",       "the mesh node daemon against a live control plane"),
    ("integration", "pubkey escaping and GUI polling pressure"),
]

def main(argv):
    wanted = argv[1:]
    picked = [m for m in MODULES if not wanted or any(w in m[0] for w in wanted)]
    if not picked:
        print(f"no module matches {wanted}; known: {[m[0] for m in MODULES]}")
        return 64

    py = interpreter()
    failed = []
    for name, desc in picked:
        print(f"\n{'=' * 68}\n  {name} — {desc}\n{'=' * 68}")
        t0 = time.time()
        rc = subprocess.call([py, os.path.join(HERE, f"test_{name}.py")])
        print(f"  [{name}] {'ok' if rc == 0 else 'FAILED'} in {time.time() - t0:.0f}s")
        if rc != 0:
            failed.append(name)

    print(f"\n{'=' * 68}")
    if failed:
        print(f"  emulation: {len(failed)} module(s) failed: {', '.join(failed)}")
    else:
        print(f"  emulation: all {len(picked)} modules passed")
    return len(failed)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
