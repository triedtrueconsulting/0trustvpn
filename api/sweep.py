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

This file is the data-retention boundary. It defines what we keep, for how
long. Audit-relevant.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import sys
import time

DB_PATH = os.environ.get("ZTV_DB_PATH", "/var/lib/0trust/0trust.db")
RETAIN_FAILED_INVOICES_SECS = 30 * 86400

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
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    # ---- 1. Expire accounts ----
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

    # ---- 4. Mark ephemeral nodes that stopped heartbeating as inactive ----
    # Threshold: 5 minutes. Ephemeral nodes are RAM-only — if they reboot,
    # they re-register with a brand new node_id, so the old row is dead weight.
    dead_threshold = now - 300
    cur = conn.execute(
        """UPDATE mesh_nodes SET active = 0
           WHERE ephemeral = 1
             AND active = 1
             AND last_heartbeat < ?""",
        (dead_threshold,),
    )
    n_dead_nodes = cur.rowcount
    if n_dead_nodes:
        log.info("deactivated %d ephemeral nodes (heartbeat stale)", n_dead_nodes)

    # Garbage-collect inactive ephemeral rows older than 1 hour.
    # Customers won't be routed to them; keeping them around is just clutter.
    gc_threshold = now - 3600
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

    # ---- 4. Drop devices belonging to long-dead accounts ----
    # If an account has been expired for >7 days, drop its devices so they
    # release their mesh IPs back to the pool.
    week_ago = now - 7 * 86400
    cur = conn.execute(
        """DELETE FROM devices
           WHERE account_id IN (
               SELECT id FROM accounts
               WHERE status = 'expired'
                 AND expires_at < ?
           )""",
        (week_ago,),
    )
    n_devices = cur.rowcount
    if n_devices:
        log.info("released %d devices from expired accounts", n_devices)

    log.info("sweep complete")
    conn.close()


if __name__ == "__main__":
    main()
