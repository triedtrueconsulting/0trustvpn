#!/usr/bin/env bash
# ============================================================================
# Canary freshness checker
# ============================================================================
# Runs daily via systemd. Alerts (via wall + the configured webhook) once the
# canary on disk is past the signing deadline it published for itself, and
# gives a quiet heads-up in the days before. Triggered before customers notice.
#
# Usage:
#   sudo /opt/0trust/canary/scripts/check.sh
#
# Env:
#   CANARY_PATH      defaults to /var/www/0trust/canary.txt
#   ALERT_WEBHOOK    optional: URL to POST to on staleness
#   ALERT_LEAD       seconds of warning before the deadline, defaults to 2 days
#   ALERT_MAX_AGE    seconds, defaults to 14 days — the fallback age limit used
#                    only when the deadline cannot be read out of the document
# ============================================================================
set -euo pipefail

CANARY_PATH="${CANARY_PATH:-/var/www/0trust/canary.txt}"
ALERT_MAX_AGE="${ALERT_MAX_AGE:-1209600}"  # 14 days — fallback only
ALERT_LEAD="${ALERT_LEAD:-172800}"         # 2 days
ALERT_WEBHOOK="${ALERT_WEBHOOK:-}"

alert() {   # alert <message>
    echo "$1" >&2
    [[ -n "$ALERT_WEBHOOK" ]] && curl -fsS -X POST -d "$1" "$ALERT_WEBHOOK" || true
    command -v wall >/dev/null && echo "$1" | wall || true
}

# Parse a date the document states. Returns empty on anything unparseable
# rather than guessing, so the caller can say so out loud.
as_epoch() {   # as_epoch <date string>
    [[ -n "$1" ]] || return 0
    date -u -d "$1" +%s 2>/dev/null \
        || date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$1" +%s 2>/dev/null \
        || date -u -j -f "%Y-%m-%d" "$1" +%s 2>/dev/null \
        || true
}

field() {   # field <label>  — the value of a "Label: value" line
    grep -m1 -E "^$1:" "$CANARY_PATH" | sed "s/^$1:[[:space:]]*//" || true
}

if [[ ! -f "$CANARY_PATH" ]]; then
    alert "CRITICAL: canary missing at $CANARY_PATH"
    exit 1
fi

now=$(date +%s)

# Judge the canary by what it SAYS, not by the file's mtime.
#
# mtime is the wrong question: rsyncing the site, reinstalling the host or
# restoring a backup all touch the file without re-signing it, and the check
# would then go quiet about a canary whose content is months stale. The dates
# that mean anything here are inside the document the operator signed.
issued_epoch=$(as_epoch "$(field 'Issued at')")

# Lateness is measured against the deadline the canary PUBLISHED, not against
# a fixed age. Those are not the same number: the deadline is the end of the
# following week, so it lands 7 to 13 days after signing, and a flat 7-day age
# limit raised CRITICAL every single week on a canary being operated exactly
# as designed. An alarm that fires when nothing is wrong is an alarm nobody
# reads — and this one guards the document customers are told to treat as a
# duress signal.
deadline_epoch=$(as_epoch "$(field 'Next signing')")
if [[ -n "$deadline_epoch" ]]; then
    # The deadline is a date, so the operator has until the end of that day.
    deadline_epoch=$(( deadline_epoch + 86399 ))
fi

if [[ -n "$deadline_epoch" ]]; then
    if (( now > deadline_epoch )); then
        over_days=$(( (now - deadline_epoch) / 86400 ))
        alert "CRITICAL: 0trust canary is $over_days day(s) past its published signing deadline ($(field 'Next signing')). Re-sign immediately: sudo ./canary/scripts/generate.sh"
        exit 2
    fi
    if (( deadline_epoch - now <= ALERT_LEAD )); then
        # Due soon is information, not an incident: exit 0 so the systemd unit
        # does not enter failed state for a canary that is still valid.
        echo "NOTICE: 0trust canary is due for re-signing by $(field 'Next signing')" >&2
    fi
    exit 0
fi

# No readable deadline — say so, and fall back to an age limit on the issue
# date, then on mtime. Silently falling back would hide a mangled canary
# behind a fresh timestamp.
echo "WARNING: could not read 'Next signing:' from $CANARY_PATH — falling back to issue age" >&2
if [[ -n "$issued_epoch" ]]; then
    age=$(( now - issued_epoch ))
else
    echo "WARNING: could not read 'Issued at:' either — falling back to mtime" >&2
    mtime=$(stat -c %Y "$CANARY_PATH" 2>/dev/null || stat -f %m "$CANARY_PATH")
    age=$(( now - mtime ))
fi

if (( age > ALERT_MAX_AGE )); then
    age_days=$(( age / 86400 ))
    alert "CRITICAL: 0trust canary is $age_days days old. Re-sign immediately: sudo ./canary/scripts/generate.sh"
    exit 2
fi

exit 0
