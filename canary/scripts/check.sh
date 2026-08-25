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

# Age the canary by what it SAYS, not by the file's mtime.
#
# mtime is the wrong question: rsyncing the site, reinstalling the host or
# restoring a backup all touch the file without re-signing it, and the check
# would then go quiet about a canary whose content is months stale. The issue
# date is the only thing that means anything here, and it is inside the
# document the operator signed.
issued=$(grep -m1 -E '^Issued at:' "$CANARY_PATH" | sed 's/^Issued at:[[:space:]]*//')
issued_epoch=""
if [[ -n "$issued" ]]; then
    issued_epoch=$(date -u -d "$issued" +%s 2>/dev/null \
                   || date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$issued" +%s 2>/dev/null \
                   || true)
fi

if [[ -n "$issued_epoch" ]]; then
    age=$(( now - issued_epoch ))
else
    # An unparseable date is itself worth saying out loud — silently falling
    # back would hide a mangled canary behind a fresh mtime.
    echo "WARNING: could not read 'Issued at:' from $CANARY_PATH — falling back to mtime" >&2
    mtime=$(stat -c %Y "$CANARY_PATH" 2>/dev/null || stat -f %m "$CANARY_PATH")
    age=$(( now - mtime ))
fi

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
