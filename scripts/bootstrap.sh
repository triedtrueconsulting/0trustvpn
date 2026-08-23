#!/usr/bin/env bash
# ============================================================================
# 0trust control-plane bootstrap — SUPERSEDED by scripts/install.sh
# ============================================================================
# This used to be its own installer. It is now a thin forwarder, because two
# install scripts is how a deployment ends up missing the pieces the newer one
# learned about: the /surf proxy service, the trial signing secret, and the
# payment-provider selection all landed in install.sh and were never here.
#
# Kept so the commands printed in docs/LAUNCH.md and docs/DR.md keep working.
#
#   sudo DOMAIN=0trustvpn.com ADMIN_EMAIL=you@example.com ./scripts/bootstrap.sh
#
# equivalently, and preferably:
#
#   sudo ./scripts/install.sh --mode production --domain 0trustvpn.com \
#                             --email you@example.com
# ============================================================================
set -euo pipefail

DOMAIN="${DOMAIN:?Set DOMAIN=0trustvpn.com  (or use scripts/install.sh directly)}"
ADMIN_EMAIL="${ADMIN_EMAIL:?Set ADMIN_EMAIL=you@example.com}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

printf '\033[1;33m[+] bootstrap.sh now forwards to install.sh --mode production\033[0m\n'
exec "$REPO_DIR/scripts/install.sh" \
    --mode production --domain "$DOMAIN" --email "$ADMIN_EMAIL" "$@"
