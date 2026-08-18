#!/bin/bash
# ============================================================================
# 0trust — session bootstrap for Claude Code on the web
# ============================================================================
# Provisions the ephemeral web container so scripts/validate.sh can run without
# a setup round-trip: a Python venv holding the API deps, and a warm Go module
# cache for the six-target cross-compile.
#
# Android and the Windows MSI are deliberately not covered — they need the
# Android SDK/NDK and a Windows host with WiX, neither of which exists here.
#
# Idempotent: safe to re-run against an already-provisioned container.
# ============================================================================
set -euo pipefail

# A developer's own machine already has whatever they set up. Only the
# throwaway web container needs provisioning.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
    exit 0
fi

REPO="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
cd "$REPO"

VENV="$REPO/.venv"

# --- Python: control-plane deps + what the validators import ----------------
if [ ! -x "$VENV/bin/python" ]; then
    echo "[+] Creating $VENV"
    python3 -m venv "$VENV"
fi
echo "[+] Installing api/requirements-dev.txt"
"$VENV/bin/pip" install --quiet --disable-pip-version-check -r api/requirements-dev.txt

# --- Go: warm the module cache so cross-compiles don't need the network -----
echo "[+] Downloading Go modules"
(cd client && CGO_ENABLED=0 go mod download)

# --- Persist environment for the rest of the session ------------------------
# Putting the venv on PATH means `python3` resolves to the one that can import
# fastapi, so scripts/validate.sh and api/smoke_test.py work unqualified.
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
    {
        echo "export VIRTUAL_ENV=\"$VENV\""
        echo "export PATH=\"$VENV/bin:\$PATH\""
        echo "export CGO_ENABLED=0"
    } >> "$CLAUDE_ENV_FILE"
fi

echo "[✓] 0trust ready — run ./scripts/validate.sh"
