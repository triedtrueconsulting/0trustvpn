#!/usr/bin/env bash
# ============================================================================
# Canary freshness checker
# ============================================================================
# Runs daily via systemd. Alerts (via wall + the configured webhook) if the
# canary on disk is older than 7 days. Triggered before customers notice.
#
# Usage:
#   sudo /opt/0trust/canary/check.sh
#
# Env:
#   CANARY_PATH      defaults to /var/www/0trust/canary.txt
#   ALERT_WEBHOOK    optional: URL to POST to on staleness
#   ALERT_MAX_AGE    seconds, defaults to 7 days
# ============================================================================
set -euo pipefail

CANARY_PATH="${CANARY_PATH:-/var/www/0trust/canary.txt}"
ALERT_MAX_AGE="${ALERT_MAX_AGE:-604800}"  # 7 days
ALERT_WEBHOOK="${ALERT_WEBHOOK:-}"

if [[ ! -f "$CANARY_PATH" ]]; then
    msg="CRITICAL: canary missing at $CANARY_PATH"
    echo "$msg" >&2
    [[ -n "$ALERT_WEBHOOK" ]] && curl -fsS -X POST -d "$msg" "$ALERT_WEBHOOK" || true
    exit 1
fi

now=$(date +%s)
mtime=$(stat -c %Y "$CANARY_PATH" 2>/dev/null || stat -f %m "$CANARY_PATH")
age=$(( now - mtime ))

if (( age > ALERT_MAX_AGE )); then
    age_days=$(( age / 86400 ))
    msg="CRITICAL: 0trust canary is $age_days days old. Re-sign immediately: sudo ./canary/scripts/generate.sh"
    echo "$msg" >&2
    [[ -n "$ALERT_WEBHOOK" ]] && curl -fsS -X POST -d "$msg" "$ALERT_WEBHOOK" || true
    # Loud local notification too
    command -v wall >/dev/null && echo "$msg" | wall || true
    exit 2
fi

exit 0
