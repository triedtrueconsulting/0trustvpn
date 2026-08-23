#!/usr/bin/env python3
"""
Operator alerting: how the person running this finds out something broke.

Until this existed, a mesh node could die and nothing would say so. The
control plane kept routing customers into it, the status page went amber, and
whether anyone noticed depended on somebody happening to open the dashboard.
For a service people pay for, "we find out when a customer complains" is not
an operations story.

Two deliberate constraints.

**No customer data, ever.** This is the one table in the product that keeps a
running narrative of its own state over time. Put an account id in it and it
becomes an activity log — exactly the record privacy.html says does not exist.
Node ids, provider names, counts and infrastructure detail only. There is a
test that asserts this and it should stay that way.

**Transitions, not states.** Alerting on "node is down" every time the sweeper
runs produces an hourly stream nobody reads. An event is written when
something *changes*, so silence genuinely means nothing has changed.

Delivery is an optional outbound webhook (ZTV_ALERT_WEBHOOK). Deliberately
generic — a Slack incoming webhook, ntfy, Discord, or an operator's own
endpoint all take a JSON POST. There is no email here for the same reason
there is none anywhere else in this product.
"""

from __future__ import annotations

import json
import os
import shutil
import time
import urllib.error
import urllib.request

WEBHOOK_URL = "ZTV_ALERT_WEBHOOK"
WEBHOOK_TIMEOUT = 8

SEVERITIES = ("info", "warn", "critical")

# Free space below this on the database's filesystem is worth shouting about:
# SQLite failing to write is a total outage, and it arrives with no warning.
DISK_WARN_PCT = float(os.environ.get("ZTV_DISK_WARN_PCT", "10"))
DISK_CRITICAL_PCT = float(os.environ.get("ZTV_DISK_CRITICAL_PCT", "3"))


def record(conn, kind: str, severity: str, subject: str = "",
           detail: str = "") -> int:
    """Write one event. Returns its id."""
    if severity not in SEVERITIES:
        severity = "warn"
    cur = conn.execute(
        """INSERT INTO ops_events (created_at, kind, severity, subject, detail)
           VALUES (?,?,?,?,?)""",
        (int(time.time()), kind, severity, subject or "", detail or ""),
    )
    return cur.lastrowid


def recent(conn, limit: int = 50, since: int = 0) -> list[dict]:
    rows = conn.execute(
        """SELECT id, created_at, kind, severity, subject, detail, delivered
             FROM ops_events
            WHERE created_at >= ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?""",
        (since, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def unresolved_count(conn, window_secs: int = 24 * 3600) -> int:
    """How many warn/critical events in the recent window — the badge number."""
    row = conn.execute(
        """SELECT COUNT(*) AS n FROM ops_events
            WHERE created_at >= ? AND severity IN ('warn','critical')""",
        (int(time.time()) - window_secs,),
    ).fetchone()
    return int(row["n"] if hasattr(row, "keys") else row[0])


def deliver_pending(conn, limit: int = 20) -> int:
    """
    POST undelivered events to the configured webhook.

    Marked delivered even when the POST fails. A retry queue that grows
    without bound during an outage and then floods the operator's channel
    when it recovers is worse than a missed notification, and the events
    remain in the dashboard either way — the webhook is a nudge, not the
    system of record.
    """
    url = os.environ.get(WEBHOOK_URL, "").strip()
    rows = conn.execute(
        """SELECT id, created_at, kind, severity, subject, detail
             FROM ops_events WHERE delivered = 0
            ORDER BY id ASC LIMIT ?""",
        (limit,),
    ).fetchall()
    if not rows:
        return 0
    sent = 0
    for r in rows:
        event = {k: r[k] for k in
                 ("id", "created_at", "kind", "severity", "subject", "detail")}
        if url:
            body = json.dumps({
                "text": f"[0trust {event['severity']}] {event['kind']} "
                        f"{event['subject']}: {event['detail']}".strip(),
                "event": event,
            }).encode()
            req = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json",
                         "User-Agent": "0trust-ops/1"})
            try:
                urllib.request.urlopen(req, timeout=WEBHOOK_TIMEOUT).read(4096)
                sent += 1
            except Exception:
                pass          # see the docstring: no retry queue on purpose
        conn.execute("UPDATE ops_events SET delivered = 1 WHERE id = ?",
                     (r["id"],))
    return sent


def check_disk(conn, path: str) -> None:
    """
    Warn before SQLite starts failing writes.

    A full disk on the control plane is a total outage that arrives with no
    warning at all: signup, login and every register call start returning 500
    at the same moment.
    """
    try:
        usage = shutil.disk_usage(os.path.dirname(path) or "/")
    except OSError:
        return
    free_pct = 100.0 * usage.free / usage.total if usage.total else 100.0
    if free_pct <= DISK_CRITICAL_PCT:
        severity, kind = "critical", "disk.critical"
    elif free_pct <= DISK_WARN_PCT:
        severity, kind = "warn", "disk.low"
    else:
        return
    # Transition only: do not repeat the same warning every hour.
    prior = conn.execute(
        """SELECT kind FROM ops_events
            WHERE kind IN ('disk.low','disk.critical')
            ORDER BY id DESC LIMIT 1""").fetchone()
    if prior is not None and prior["kind"] == kind:
        return
    record(conn, kind, severity, "control-plane",
           f"{free_pct:.1f}% free on the database filesystem "
           f"({usage.free // (1024*1024)} MiB)")
