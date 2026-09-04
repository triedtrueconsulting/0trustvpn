#!/usr/bin/env python3
"""
0trust expiry sweeper

Runs hourly via systemd timer. Two jobs:

  1. Flip accounts whose expires_at has passed into status='expired'.
     They drop out of /api/v1/wg/peers automatically (the SQL filters
     on status='active'), so mesh nodes stop routing their traffic at
     the next sync.

  2. Garbage-collect invoices that have been Expired/Invalid for >30 days
     and have no matching settled invoice. Keeps the DB tidy and avoids
     accumulating stale BTCPay state.

  3. Drop abandoned signups: pending_payment accounts older than
     ZTV_ABANDON_SIGNUP_DAYS with no settled invoice.

  4. Prune spent trial stamps and used provisioning tokens once they can no
     longer be replayed.

  5. Warn accounts whose subscription is about to run out, and tell them once
     it has. There is no email address on file — by design, that is the
     product — so an in-app notice is the ONLY channel this service has to
     reach a customer. Without it a subscription ends in silence and the
     customer finds out when their traffic stops.

This file is the data-retention boundary. It defines what we keep, for how
long. Audit-relevant.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ops_alerts

DB_PATH = os.environ.get("ZTV_DB_PATH", "/var/lib/0trust/0trust.db")
RETAIN_FAILED_INVOICES_SECS = 30 * 86400

# An unpaid signup older than this is abandoned. Comfortably longer than any
# invoice stays payable, so a slow payer is never caught by it.
ABANDON_SIGNUP_SECS = int(os.environ.get("ZTV_ABANDON_SIGNUP_DAYS", "7")) * 86400

# How far ahead to warn that a subscription is ending. Comma-separated so an
# operator can have more than one nudge; each fires once per account per
# threshold, tracked by the notice already sitting in the table.
RENEWAL_WARN_DAYS = tuple(sorted(
    (int(d) for d in os.environ.get("ZTV_RENEWAL_WARN_DAYS", "7,1").split(",") if d.strip()),
    reverse=True,
))
# Marker prefix in notices.created_by, so a re-run recognises its own work.
# The subject line is customer-facing prose and must never be load-bearing.
RENEWAL_TAG = "sweeper:renewal"
EXPIRED_TAG = "sweeper:expired"

# How long a device survives its account expiring, before its mesh IP goes
# back to the pool. The expiry notice quotes this number at the customer, so
# it has exactly one definition — a hardcoded "7 days" in the copy would go
# stale the moment an operator changed the retention.
DEVICE_RETAIN_DAYS = int(os.environ.get("ZTV_DEVICE_RETAIN_DAYS", "7"))

# Spent trial nonces only need to outlive the challenge they belong to; the
# redemption path rejects an expired challenge regardless. A day of slack
# covers clock skew and a generous ZTV_TRIAL_CHALLENGE_TTL.
TRIAL_NONCE_RETAIN_SECS = int(os.environ.get("ZTV_TRIAL_NONCE_RETAIN_SECS", str(86400)))

log = logging.getLogger("sweep")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def main():
    if not os.path.exists(DB_PATH):
        log.error("DB missing at %s", DB_PATH)
        sys.exit(1)

    now = int(time.time())
    conn = sqlite3.connect(DB_PATH, isolation_level=None, timeout=30.0)
    # Row supports both r[0] and r["col"], so existing index access keeps
    # working while the alerting code can read columns by name.
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")

    # ---- 1a. Warn before expiry, while the account is still usable ----
    # Deliberately ahead of the flip below: an account that expires during
    # this same run should still have been warned on an earlier one, and
    # warning it here after the flip would be pointless.
    n_warned = 0
    for days in RENEWAL_WARN_DAYS:
        horizon = now + days * 86400
        rows = conn.execute(
            """SELECT a.id, a.expires_at, a.plan FROM accounts a
                WHERE a.status = 'active'
                  AND a.expires_at > ?
                  AND a.expires_at <= ?
                  AND NOT EXISTS (
                        SELECT 1 FROM notices n
                         WHERE n.account_id = a.id
                           AND n.created_by = ?)""",
            (now, horizon, f"{RENEWAL_TAG}:{days}"),
        ).fetchall()
        for r in rows:
            left = max(0, r["expires_at"] - now)
            # Round up: an account with 23h left has "1 day", not "0 days".
            days_left = -(-left // 86400)
            unit = "day" if days_left == 1 else "days"
            trial = (r["plan"] or "") == "trial"
            conn.execute(
                """INSERT INTO notices
                   (account_id, severity, subject, body, created_at,
                    expires_at, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    r["id"],
                    "warning" if days_left <= 1 else "info",
                    (f"Your trial ends in {days_left} {unit}"
                     if trial else
                     f"Your subscription ends in {days_left} {unit}"),
                    ("Top up with `0trust topup` or at 0trustvpn.com to keep "
                     "this account. Paid time stacks on whatever is left, so "
                     "topping up early costs you nothing. Your token stays the "
                     "same — there is no new account to create and nothing to "
                     "re-install."),
                    now,
                    # Pointless once the account has expired; the expiry
                    # notice takes over from there.
                    r["expires_at"],
                    f"{RENEWAL_TAG}:{days}",
                ),
            )
            n_warned += 1
    if n_warned:
        log.info("posted %d renewal warnings", n_warned)

    # ---- 1b. Expire accounts ----
    # Captured before the UPDATE: afterwards they are indistinguishable from
    # accounts expired on an earlier run, and each should be told exactly once.
    just_expired = [
        r["id"] for r in conn.execute(
            """SELECT id FROM accounts
                WHERE status = 'active'
                  AND expires_at > 0
                  AND expires_at < ?""",
            (now,),
        ).fetchall()
    ]
    cur = conn.execute(
        """UPDATE accounts
           SET status = 'expired'
           WHERE status = 'active'
             AND expires_at > 0
             AND expires_at < ?""",
        (now,),
    )
    n_expired = cur.rowcount
    if n_expired:
        log.info("expired %d accounts", n_expired)

    for account_id in just_expired:
        conn.execute(
            """INSERT INTO notices
               (account_id, severity, subject, body, created_at,
                expires_at, created_by)
               VALUES (?, 'urgent', ?, ?, ?, 0, ?)""",
            (
                account_id,
                "Your subscription has ended",
                ("Devices on this account are no longer routed. Top up at "
                 "0trustvpn.com or with `0trust topup` and the same token "
                 "works again — your devices stay registered for "
                 f"{DEVICE_RETAIN_DAYS} days, after which they are released "
                 "and will need registering again."),
                now,
                EXPIRED_TAG,
            ),
        )

    # ---- 2. GC stale invoices ----
    cutoff = now - RETAIN_FAILED_INVOICES_SECS
    cur = conn.execute(
        """DELETE FROM invoices
           WHERE status IN ('Expired', 'Invalid')
             AND created_at < ?""",
        (cutoff,),
    )
    n_invoices = cur.rowcount
    if n_invoices:
        log.info("garbage-collected %d stale invoices", n_invoices)

    # ---- 3. Drop expired hop_pairs (releases entry ports back to the pool) ----
    cur = conn.execute(
        "DELETE FROM hop_pairs WHERE expires_at < ?",
        (now,),
    )
    n_pairs = cur.rowcount
    if n_pairs:
        log.info("released %d expired hop_pairs", n_pairs)

    # ---- 4. Mark nodes that stopped heartbeating as inactive ----
    # Threshold: 5 minutes; meshd checks in every 30s, so that is ten missed
    # beats.
    #
    # This used to apply to ephemeral nodes only, on the reasoning that a
    # RAM-only node which reboots comes back with a new id and leaves a dead
    # row behind. True, but it left the more damaging case unhandled: a
    # permanent node that dies stays active = 1 forever, and every
    # /wg/register keeps routing customers into it. Nothing ever noticed,
    # because nothing else checked liveness either.
    #
    # `last_heartbeat > 0` spares rows that have never checked in at all —
    # hand-inserted nodes, and a deployment not running meshd — from being
    # deactivated on the strength of a heartbeat they were never going to
    # send. A node that recovers is reactivated by its next heartbeat.
    dead_threshold = now - 300
    # Name them before flipping them, so the operator gets "buc-01 went dark"
    # rather than a count. A count tells you something is wrong; an id tells
    # you what to go and look at.
    going_dark = [r["id"] for r in conn.execute(
        """SELECT id FROM mesh_nodes
            WHERE active = 1 AND last_heartbeat > 0 AND last_heartbeat < ?""",
        (dead_threshold,))]
    cur = conn.execute(
        """UPDATE mesh_nodes SET active = 0
           WHERE active = 1
             AND last_heartbeat > 0
             AND last_heartbeat < ?""",
        (dead_threshold,),
    )
    n_dead_nodes = cur.rowcount
    if n_dead_nodes:
        log.info("deactivated %d nodes (heartbeat stale)", n_dead_nodes)
    for node_id in going_dark:
        ops_alerts.record(
            conn, "node.down", "critical", node_id,
            "no heartbeat for 5 minutes — taken out of rotation, "
            "customers are no longer routed here")

    # And the other direction. A node that came back deserves to close the
    # loop; otherwise the operator is left wondering whether it ever did.
    for row in conn.execute(
            """SELECT m.id FROM mesh_nodes m
                WHERE m.active = 1 AND m.last_heartbeat >= ?
                  AND EXISTS (SELECT 1 FROM ops_events e
                               WHERE e.subject = m.id AND e.kind = 'node.down'
                                 AND e.created_at > (
                                     SELECT COALESCE(MAX(e2.created_at), 0)
                                       FROM ops_events e2
                                      WHERE e2.subject = m.id
                                        AND e2.kind = 'node.up'))""",
            (dead_threshold,)):
        ops_alerts.record(conn, "node.up", "info", row["id"],
                          "heartbeating again — back in rotation")

    ops_alerts.check_disk(conn, DB_PATH)

    # Garbage-collect inactive ephemeral rows older than 1 hour.
    # Customers won't be routed to them; keeping them around is just clutter.
    gc_threshold = now - 3600
    #
    # Drop the hop_pairs pointing at those nodes FIRST. A pair has a 24h TTL
    # but a node can die an hour into it, so a live pair routinely outlives
    # the node it names. hop_pairs.entry_node/exit_node reference mesh_nodes,
    # and on any database created before those refs gained ON DELETE CASCADE
    # the node DELETE below raises FOREIGN KEY constraint failed — which
    # aborted the whole sweep, so account expiry and device release silently
    # stopped running too. Doing it explicitly is also the correct behaviour
    # in its own right: a pair through a dead node cannot carry traffic.
    cur = conn.execute(
        """DELETE FROM hop_pairs
           WHERE entry_node IN (
                   SELECT id FROM mesh_nodes
                   WHERE ephemeral = 1 AND active = 0 AND last_heartbeat < ?)
              OR exit_node IN (
                   SELECT id FROM mesh_nodes
                   WHERE ephemeral = 1 AND active = 0 AND last_heartbeat < ?)""",
        (gc_threshold, gc_threshold),
    )
    n_orphan_pairs = cur.rowcount
    if n_orphan_pairs:
        log.info("released %d hop_pairs routed through dead nodes", n_orphan_pairs)

    cur = conn.execute(
        """DELETE FROM mesh_nodes
           WHERE ephemeral = 1
             AND active = 0
             AND last_heartbeat < ?""",
        (gc_threshold,),
    )
    n_gc_nodes = cur.rowcount
    if n_gc_nodes:
        log.info("garbage-collected %d dead ephemeral nodes", n_gc_nodes)

    # ---- 5. Drop devices belonging to long-dead accounts ----
    # Once an account has been expired for DEVICE_RETAIN_DAYS, drop its
    # devices so they release their mesh IPs back to the pool. The expiry
    # notice promises this window, and reads the same constant.
    retain_cutoff = now - DEVICE_RETAIN_DAYS * 86400
    cur = conn.execute(
        """DELETE FROM devices
           WHERE account_id IN (
               SELECT id FROM accounts
               WHERE status = 'expired'
                 AND expires_at < ?
           )""",
        (retain_cutoff,),
    )
    n_devices = cur.rowcount
    if n_devices:
        log.info("released %d devices from expired accounts", n_devices)

    # ---- 6. Drop abandoned signups ----
    # POST /api/v1/account is unauthenticated by necessity — you cannot ask a
    # customer to authenticate before they have an account. It is rate limited
    # at nginx, but every abandoned checkout still leaves a pending_payment
    # row and its invoice behind forever. That is both unbounded growth and a
    # quiet contradiction of the retention story in docs/AUDIT.md: we say we
    # keep the minimum for as long as it is needed, and a signup nobody
    # completed stops being needed once the invoice can no longer be paid.
    #
    # Only rows with no settled invoice are touched, so a paid account whose
    # status has not yet flipped is never at risk.
    abandoned_cutoff = now - ABANDON_SIGNUP_SECS
    cur = conn.execute(
        """DELETE FROM accounts
           WHERE status = 'pending_payment'
             AND created_at < ?
             AND id NOT IN (
                 SELECT account_id FROM invoices WHERE status = 'settled')""",
        (abandoned_cutoff,),
    )
    n_abandoned = cur.rowcount
    if n_abandoned:
        log.info("removed %d abandoned signups", n_abandoned)

    # ---- 7. Prune spent trial stamps ----
    # A redeemed nonce exists to stop the same solved proof-of-work minting a
    # second account. It only needs to outlive the challenge itself: redemption
    # rejects anything past expires_at, so a replay after the TTL fails on the
    # expiry check whether or not we still remember the nonce. Keeping them
    # forever would mean an ever-growing record of every trial ever issued.
    cur = conn.execute(
        "DELETE FROM trial_grants WHERE redeemed_at < ?",
        (now - TRIAL_NONCE_RETAIN_SECS,),
    )
    if cur.rowcount:
        log.info("pruned %d spent trial stamps", cur.rowcount)

    # ---- 8. Prune provisioning tokens that can no longer be used ----
    # "Used once, a day ago" is NOT the same as "can no longer be used". A
    # node's disk is tmpfs, so it re-presents its token on every boot to
    # rejoin under the same id — an enrolment token stays in service for as
    # long as the node does. Deleting it here would have worked perfectly for
    # a day and then, on some reboot weeks later, left the box unable to
    # register at all: the one failure this whole path exists to prevent, and
    # invisible until it happened.
    #
    # So a token goes only when nothing can present it any more: it expired,
    # it was revoked, or the node it registered is gone from the mesh.
    cutoff = now - 86400
    cur = conn.execute(
        """DELETE FROM provision_tokens
           WHERE expires_at < :cutoff
              OR (revoked_at IS NOT NULL AND revoked_at < :cutoff)
              OR (used_at IS NOT NULL AND used_at < :cutoff
                  AND (used_node_id IS NULL
                       OR used_node_id NOT IN (SELECT id FROM mesh_nodes)))""",
        {"cutoff": cutoff},
    )
    if cur.rowcount:
        log.info("pruned %d spent or expired provisioning tokens", cur.rowcount)

    # ---- 9. Drop device/node assignments with dangling references ----
    # ON DELETE CASCADE covers the normal paths; this catches rows left by a
    # node removed by hand. A stale assignment would keep disclosing a pubkey
    # to a node that no longer routes it.
    cur = conn.execute(
        """DELETE FROM device_nodes
           WHERE device_id NOT IN (SELECT id FROM devices)
              OR node_id   NOT IN (SELECT id FROM mesh_nodes)"""
    )
    if cur.rowcount:
        log.info("dropped %d stale device/node assignments", cur.rowcount)

    # ---- 10. Release hop_pairs whose node references have gone stale ----
    # Belt and braces for a control plane where a node row was removed by hand.
    cur = conn.execute(
        """DELETE FROM hop_pairs
           WHERE entry_node NOT IN (SELECT id FROM mesh_nodes)
              OR exit_node  NOT IN (SELECT id FROM mesh_nodes)"""
    )
    if cur.rowcount:
        log.info("released %d hop_pairs with dangling node refs", cur.rowcount)

    # Deliver last, once every event this run could produce has been written.
    try:
        sent = ops_alerts.deliver_pending(conn)
        if sent:
            log.info("delivered %d ops alerts to the webhook", sent)
    except Exception as e:
        # An alerting failure must never take the sweep down with it — the
        # sweep is what enforces data retention, and losing that to a broken
        # webhook URL would be a far worse outcome than a missed notification.
        log.warning("ops alert delivery failed: %s", e)

    log.info("sweep complete")
    conn.close()


if __name__ == "__main__":
    main()
