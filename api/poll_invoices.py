#!/usr/bin/env python3
"""
Settle watch-only invoices by asking a block explorer, on a timer.

Every other provider tells us when it has been paid, over a signed webhook.
The watch-only path has nobody to send one: the customer pays the operator's
wallet directly and no third party is involved. So we ask instead.

Polling is not a workaround here, it is what makes the provider deployable.
A webhook needs a publicly reachable callback URL, a TLS certificate and a
provider dashboard to register it in. Polling needs an outbound HTTPS request,
which a fresh VPS behind any firewall can already make. That is the difference
between "works the day you build the box" and "works after you have signed up
somewhere and configured a callback".

Runs every minute from a systemd timer. Crediting reuses exactly the guard the
webhook path uses — the UPDATE is conditional on the invoice not already being
settled — so a poll racing a manual settlement from the dashboard cannot
double-credit an account.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ops_alerts
import payments

DB_PATH = os.environ.get("ZTV_DB_PATH", "/var/lib/0trust/0trust.db")

# Stop watching an invoice nobody paid. The address stays derived and any late
# payment still arrives in the operator's wallet — it just will not credit an
# account automatically, and the dashboard can settle it by hand.
INVOICE_TTL_SECS = int(os.environ.get("ZTV_INVOICE_TTL_HOURS", "24")) * 3600

# An explorer that rate-limits us into failure is worse than a slow poll.
MAX_PER_RUN = int(os.environ.get("ZTV_POLL_BATCH", "40"))

log = logging.getLogger("poll")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")


def credit(conn, inv, now: int) -> bool:
    """
    Mark an invoice settled and extend the account. Returns False if somebody
    else already did — the same conditional UPDATE the webhook path uses.
    """
    cur = conn.execute(
        "UPDATE invoices SET status = ?, settled_at = ? WHERE id = ? AND status != ?",
        (payments.SETTLED, now, inv["id"], payments.SETTLED))
    if cur.rowcount == 0:
        return False
    acc = conn.execute("SELECT id, expires_at FROM accounts WHERE id = ?",
                       (inv["account_id"],)).fetchone()
    if acc is None:
        log.warning("invoice %s has no account", inv["id"])
        return False
    # Paid months stack on whatever is left, so converting a trial early is
    # never punished. Same rule as the webhook.
    base = max(int(acc["expires_at"] or 0), now)
    conn.execute(
        "UPDATE accounts SET status = 'active', expires_at = ?, plan = 'paid' "
        "WHERE id = ?",
        (base + int(inv["months"]) * 30 * 86400, acc["id"]))
    return True


def main() -> int:
    if payments.provider_name() != "watch":
        return 0
    if not os.path.exists(DB_PATH):
        log.warning("no database at %s", DB_PATH)
        return 0

    prov = payments.provider()
    conn = sqlite3.connect(DB_PATH, isolation_level=None, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    now = int(time.time())

    rows = conn.execute(
        """SELECT id, account_id, months, payment_address, amount_crypto,
                  created_at, pay_currency, derivation_index
             FROM invoices
            WHERE status = 'pending'
              AND payment_address IS NOT NULL
              AND payment_address != ''
              AND created_at > ?
            ORDER BY created_at ASC
            LIMIT ?""",
        (now - INVOICE_TTL_SECS, MAX_PER_RUN)).fetchall()

    settled = checked = 0
    # Per coin, so one broken backend cannot hide behind another working one.
    attempted, succeeded, failures = {}, {}, {}
    for inv in rows:
        # Atomic units per coin. This was hardcoded to 1e8, which is right for
        # Bitcoin and Zcash and wrong by four orders of magnitude for Monero:
        # a 1 XMR invoice would have been treated as owing 100 million
        # piconero, and the first dust payment would have settled it.
        coin = (inv["pay_currency"] or "BTC").upper()
        units = payments.COIN_UNITS.get(coin)
        if units is None:
            log.warning("invoice %s is in an unknown currency %r",
                        inv["id"], coin)
            continue
        try:
            atomic = int(round(float(inv["amount_crypto"] or 0) * units))
        except (TypeError, ValueError):
            log.warning("invoice %s has an unreadable amount", inv["id"])
            continue
        attempted[coin] = attempted.get(coin, 0) + 1
        try:
            result = prov.check(inv["payment_address"], atomic, coin=coin,
                                ref=inv["derivation_index"])
        except payments.PaymentError as e:
            # One unreachable explorer must not stop the rest of the batch,
            # and must not look like "nobody has paid".
            log.warning("chain check failed for %s (%s): %s", inv["id"], coin, e)
            failures.setdefault(coin, str(e)[:200])
            continue
        checked += 1
        succeeded[coin] = succeeded.get(coin, 0) + 1
        if result["status"] != payments.SETTLED:
            continue
        conn.execute("BEGIN IMMEDIATE")
        try:
            if credit(conn, inv, now):
                settled += 1
                log.info("settled %s (%d atomic %s at %s)", inv["id"],
                         result["confirmed_sats"], coin,
                         inv["payment_address"])
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    # A coin whose every check failed is not crediting, and saying nothing
    # about it looks exactly like "nobody is paying in that coin" — the most
    # expensive thing for an operator not to be told. This used to fire only
    # when the WHOLE batch failed, so a working Bitcoin explorer masked a
    # broken Zcash one indefinitely.
    #
    # Alerts fire on transitions, not states: the subject is the coin, so each
    # backend gets its own edge rather than one drowning out the others.
    dead = sorted(c for c, n in attempted.items() if n and not succeeded.get(c))
    if dead:
        try:
            conn.execute("BEGIN IMMEDIATE")
            for coin in dead:
                prior = conn.execute(
                    "SELECT kind FROM ops_events WHERE subject = ? "
                    "AND kind LIKE 'payments.%' ORDER BY id DESC LIMIT 1",
                    (coin,)).fetchone()
                if prior is not None and prior["kind"] == "payments.explorer_down":
                    continue
                ops_alerts.record(
                    conn, "payments.explorer_down", "critical", coin,
                    f"every {coin} chain check failed across "
                    f"{attempted[coin]} pending invoice(s) — {coin} payments "
                    f"are not being credited: {failures.get(coin, 'unknown')}")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
    for coin, n in sorted(succeeded.items()):
        # The recovery edge, so a resolved outage stops looking like an open
        # one on the dashboard.
        try:
            conn.execute("BEGIN IMMEDIATE")
            prior = conn.execute(
                "SELECT kind FROM ops_events WHERE subject = ? "
                "AND kind LIKE 'payments.%' ORDER BY id DESC LIMIT 1",
                (coin,)).fetchone()
            if prior is not None and prior["kind"] == "payments.explorer_down":
                ops_alerts.record(
                    conn, "payments.explorer_ok", "info", coin,
                    f"{coin} chain checks are succeeding again")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
    if settled or checked:
        log.info("checked %d pending invoice(s), settled %d", checked, settled)

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
