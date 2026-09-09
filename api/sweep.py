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

# How long an EXPIRED account row survives before it is deleted outright.
#
# privacy.html §8 promises this in as many words — "expired records are purged
# by an automated sweeper" — and docs/AUDIT.md §3.1 gives the retention of the
# token hash, the expiry and the status as "lifetime of subscription". Neither
# was true: the only DELETE FROM accounts here was the abandoned-signup one
# below, so a customer who let their subscription lapse kept a row forever.
# Two documents and the code disagreeing, on a retention promise.
#
# 30 days because that is the refund window in terms.html §4, which is what
# privacy.html §8 ties the purge to ("plus the refund window"). Anything paid
# for recently has an expires_at in the future and is nowhere near this.
ACCOUNT_RETAIN_SECS = int(
    os.environ.get("ZTV_ACCOUNT_RETAIN_DAYS", "30")) * 86400

# The three tables that grew forever.
#
# None of them holds customer data — ops_events is node ids and counts by
# invariant, admin_audit is the operator's own actions, admin_sessions is
# their logins — which is why they were easy to miss while every customer
# table got a boundary. Two reasons they still need one. First, docs/AUDIT.md
# §10 presents itself as the complete list of tables and their retention, and
# an auditor reconciling it against the schema finds rows with no answer.
# Second, admin_sessions keeps a session token's hash after the session has
# expired: the row is useless to the operator and is a credential at rest for
# whoever seizes the box. A successful login already clears expired rows
# (admin._issue_session), so on a busy deployment this finds nothing — which
# is exactly why it was easy to believe the table was handled. The deployment
# where it matters is the one whose operator has not logged in for months.
OPS_EVENT_RETAIN_SECS = int(
    os.environ.get("ZTV_OPS_EVENT_RETAIN_DAYS", "90")) * 86400
# Long enough to answer "who changed that, and when" a year later, which is
# the only question this table exists for.
ADMIN_AUDIT_RETAIN_SECS = int(
    os.environ.get("ZTV_ADMIN_AUDIT_RETAIN_DAYS", "365")) * 86400
# A grace period past expiry, so a session is not swept out from under an
# operator whose clock is a little behind the server's.
ADMIN_SESSION_GRACE_SECS = 86400

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

    # ---- 6b. Purge accounts that expired long enough ago ----
    #
    # The retention boundary this file says it is. An account is deleted once
    # it has been expired for longer than the refund window: after that there
    # is nothing left to enforce, nothing to refund against, and the row is
    # just a record that somebody once held a subscription.
    #
    # Dependents go first, explicitly, even though every one of these FKs
    # carries ON DELETE CASCADE. Bug class #8 in CLAUDE.md is exactly this:
    # a database created before a CASCADE was added raises FOREIGN KEY
    # constraint failed, the exception takes down the REST of the sweep, and
    # account expiry and device release silently stop running. The node
    # deletion above does the same thing for the same reason.
    #
    # Banned accounts are purged too. The policy makes no exception for them,
    # and keeping the hash of a token whose holder can mint a fresh one for
    # free buys nothing — deleting the row stops that token working just as
    # a ban did.
    purge_cutoff = now - ACCOUNT_RETAIN_SECS
    doomed = [r["id"] for r in conn.execute(
        """SELECT id FROM accounts
            WHERE expires_at > 0 AND expires_at < ?
              AND status != 'pending_payment'""",
        (purge_cutoff,))]
    if doomed:
        marks = ",".join("?" * len(doomed))
        conn.execute(
            f"""DELETE FROM hop_pairs WHERE device_id IN
                (SELECT id FROM devices WHERE account_id IN ({marks}))""",
            doomed)
        conn.execute(
            f"""DELETE FROM device_nodes WHERE device_id IN
                (SELECT id FROM devices WHERE account_id IN ({marks}))""",
            doomed)
        conn.execute(f"DELETE FROM devices WHERE account_id IN ({marks})", doomed)
        conn.execute(f"DELETE FROM notice_reads WHERE account_id IN ({marks})",
                     doomed)
        conn.execute(f"DELETE FROM notices WHERE account_id IN ({marks})", doomed)
        conn.execute(f"DELETE FROM invoices WHERE account_id IN ({marks})", doomed)
        # trial_grants is the one dependent whose FK is ON DELETE SET NULL
        # rather than CASCADE, and it was the one this block did not touch.
        # The reasoning above still applies and the omission was worse here:
        # on a database created before the clause existed the FK defaults to
        # NO ACTION, and the DELETE below raises FOREIGN KEY constraint
        # failed — taking account expiry, device release and node cleanup
        # down with it, on the schedule, silently.
        #
        # Detaching rather than deleting. The nonce has to outlive the
        # account or a stamp redeemed just before the purge could be redeemed
        # again; section 7 prunes it on its own clock, by which point the row
        # is a redemption time and a source word with nothing to attach them
        # to.
        conn.execute(
            f"UPDATE trial_grants SET account_id = NULL "
            f"WHERE account_id IN ({marks})", doomed)
        cur = conn.execute(f"DELETE FROM accounts WHERE id IN ({marks})", doomed)
        # Counts only. ops_events never holds an account id — see the note at
        # the top of api/ops_alerts.py.
        log.info("purged %d accounts expired more than %d days",
                 cur.rowcount, ACCOUNT_RETAIN_SECS // 86400)

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

    # ---- 11. Bound the three tables that had no retention at all ----
    # Done before delivery so this run's own events survive it, and last among
    # the deletes so nothing above depends on rows this removes.
    cur = conn.execute("DELETE FROM ops_events WHERE created_at < ?",
                       (now - OPS_EVENT_RETAIN_SECS,))
    if cur.rowcount:
        log.info("pruned %d ops events older than %d days",
                 cur.rowcount, OPS_EVENT_RETAIN_SECS // 86400)

    cur = conn.execute("DELETE FROM admin_audit WHERE at < ?",
                       (now - ADMIN_AUDIT_RETAIN_SECS,))
    if cur.rowcount:
        log.info("pruned %d admin audit rows older than %d days",
                 cur.rowcount, ADMIN_AUDIT_RETAIN_SECS // 86400)

    # An expired session cannot authenticate anything — current_admin checks
    # expires_at — so the row is only a token hash sitting on disk. Logging in
    # sweeps them too; this is the path that does not need anyone to log in.
    cur = conn.execute("DELETE FROM admin_sessions WHERE expires_at < ?",
                       (now - ADMIN_SESSION_GRACE_SECS,))
    if cur.rowcount:
        log.info("pruned %d expired admin sessions", cur.rowcount)

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
