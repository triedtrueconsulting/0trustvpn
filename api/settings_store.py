"""
Operator-editable settings.

Payment credentials, wallet addresses and public node endpoints change as a
business runs, and making the operator edit /etc/0trust/api.env and restart
the API for each one is how a live service ends up with a stale key nobody
noticed. These live in the database instead, editable from the dashboard.

Precedence, deliberately in this order:

  1. a value set in the database  (the dashboard wrote it — most recent intent)
  2. the environment              (what the installer or systemd provided)
  3. the default passed by caller

The environment stays authoritative for things that should not be editable at
runtime — the database path, the node PSK — simply by never being read
through here.

Secrets are stored as written. That is a real limitation and worth naming:
anyone who can read the database can read the payment API keys, exactly as
anyone who can read api.env can today. The database is 0600 and owned by the
service user, and encrypting it here would only move the problem to wherever
the decryption key lived. What this does change is that a leaked backup now
carries them too, which is why docs/DR.md says to treat backups as secret.
"""

from __future__ import annotations

import os
import time
from typing import Optional

# Keys the dashboard is allowed to write, with a type and whether the value is
# a secret (masked in the UI and in the audit log). An allowlist rather than
# free-form storage: an admin endpoint that can set arbitrary keys is an admin
# endpoint that can set the ones we deliberately kept in the environment.
SETTING_SPECS: dict[str, dict] = {
    # --- payment provider selection ---
    "ZTV_PAYMENT_PROVIDER": {"type": "choice", "secret": False,
                             "choices": ["btcpay", "hosted", "stripe", "square"],
                             "group": "payments",
                             "label": "Active payment provider"},

    # --- BTCPay ---
    "BTCPAY_URL": {"type": "url", "secret": False, "group": "btcpay",
                   "label": "BTCPay server URL"},
    "BTCPAY_STORE_ID": {"type": "text", "secret": False, "group": "btcpay",
                        "label": "Store ID"},
    "BTCPAY_API_KEY": {"type": "text", "secret": True, "group": "btcpay",
                       "label": "API key"},
    "BTCPAY_WEBHOOK_SECRET": {"type": "text", "secret": True, "group": "btcpay",
                              "label": "Webhook secret"},

    # --- hosted crypto gateway ---
    "ZTV_PAYMENT_API_URL": {"type": "url", "secret": False, "group": "hosted",
                            "label": "Gateway API URL"},
    "ZTV_PAYMENT_API_KEY": {"type": "text", "secret": True, "group": "hosted",
                            "label": "Gateway API key"},
    "ZTV_PAYMENT_IPN_SECRET": {"type": "text", "secret": True, "group": "hosted",
                               "label": "IPN secret"},
    "ZTV_PAYMENT_IPN_URL": {"type": "url", "secret": False, "group": "hosted",
                            "label": "IPN callback URL"},

    # --- Stripe ---
    "STRIPE_SECRET_KEY": {"type": "text", "secret": True, "group": "stripe",
                          "label": "Secret key (sk_live_…)"},
    "STRIPE_WEBHOOK_SECRET": {"type": "text", "secret": True, "group": "stripe",
                              "label": "Webhook signing secret (whsec_…)"},
    "STRIPE_SUCCESS_URL": {"type": "url", "secret": False, "group": "stripe",
                           "label": "Return URL after payment"},

    # --- Square ---
    "SQUARE_ACCESS_TOKEN": {"type": "text", "secret": True, "group": "square",
                            "label": "Access token"},
    "SQUARE_LOCATION_ID": {"type": "text", "secret": False, "group": "square",
                           "label": "Location ID"},
    "SQUARE_WEBHOOK_KEY": {"type": "text", "secret": True, "group": "square",
                           "label": "Webhook signature key"},
    "SQUARE_ENV": {"type": "choice", "secret": False, "group": "square",
                   "choices": ["production", "sandbox"],
                   "label": "Environment"},

    # --- business wallets: where crypto actually lands ---
    "WALLET_BTC": {"type": "text", "secret": False, "group": "wallets",
                   "label": "BTC xpub / address"},
    "WALLET_ETH": {"type": "text", "secret": False, "group": "wallets",
                   "label": "ETH address"},
    "WALLET_XMR": {"type": "text", "secret": False, "group": "wallets",
                   "label": "XMR primary address"},
    "WALLET_ZEC": {"type": "text", "secret": False, "group": "wallets",
                   "label": "ZEC address"},

    # --- public chain endpoints ---
    # We host no chain data. These name whose node we borrow.
    "NODE_RPC_BTC": {"type": "url", "secret": False, "group": "chain",
                     "label": "BTC public endpoint"},
    "NODE_RPC_ETH": {"type": "url", "secret": False, "group": "chain",
                     "label": "ETH public RPC"},
    "NODE_RPC_XMR": {"type": "url", "secret": False, "group": "chain",
                     "label": "XMR public remote node"},
    "NODE_RPC_ZEC": {"type": "url", "secret": False, "group": "chain",
                     "label": "ZEC public endpoint"},

    # --- pricing / trials ---
    "ZTV_TRIAL_ENABLED": {"type": "bool", "secret": False, "group": "trial",
                          "label": "Free trials enabled"},
    "ZTV_TRIAL_DAYS": {"type": "int", "secret": False, "group": "trial",
                       "label": "Trial length (days)"},
    "ZTV_TRIAL_MAX_DEVICES": {"type": "int", "secret": False, "group": "trial",
                              "label": "Trial device limit"},
    "ZTV_TRIAL_POW_BITS": {"type": "int", "secret": False, "group": "trial",
                           "label": "Proof-of-work difficulty (bits)"},

    # --- operations ---
    # Where node-down and disk alerts get pushed. Any endpoint that accepts a
    # JSON POST: a Slack incoming webhook, ntfy, Discord, or your own. There
    # is no email alerting for the same reason there is no email anywhere
    # else in this product. Treated as a secret because the URL is the
    # credential — anyone holding it can post into the channel.
    "ZTV_ALERT_WEBHOOK": {"type": "url", "secret": True, "group": "ops",
                          "label": "Alert webhook URL"},
}

_MASK = "••••••••"


def is_secret(key: str) -> bool:
    return bool(SETTING_SPECS.get(key, {}).get("secret"))


def mask(key: str, value: str) -> str:
    """What the dashboard and the audit log are allowed to see."""
    if not value:
        return ""
    if not is_secret(key):
        return value
    # Show enough to tell two keys apart without revealing either.
    return _MASK + (value[-4:] if len(value) > 8 else "")


def get(conn, key: str, default: Optional[str] = None) -> Optional[str]:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if row is not None and row["value"] != "":
        return row["value"]
    env = os.environ.get(key)
    if env not in (None, ""):
        return env
    return default


def get_all(conn) -> dict[str, str]:
    """Every known setting, resolved through the same precedence."""
    return {k: (get(conn, k) or "") for k in SETTING_SPECS}


def set_many(conn, values: dict, username: str) -> list[str]:
    """
    Write settings. Returns the keys actually changed, so the caller can log
    exactly that and nothing more.

    A value equal to the mask means "leave it alone" — the dashboard sends
    back what it was shown, and re-saving a form should not overwrite a real
    secret with bullet characters.
    """
    now = int(time.time())
    changed = []
    for key, raw in values.items():
        if key not in SETTING_SPECS:
            continue                      # allowlist; silently ignore the rest
        value = "" if raw is None else str(raw).strip()
        if is_secret(key) and value.startswith(_MASK):
            continue
        current = conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if current is not None and current["value"] == value:
            continue
        conn.execute(
            """INSERT INTO settings (key, value, updated_at, updated_by)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(key) DO UPDATE
                 SET value = excluded.value,
                     updated_at = excluded.updated_at,
                     updated_by = excluded.updated_by""",
            (key, value, now, username),
        )
        changed.append(key)
    return changed


def apply_to_environ(conn) -> None:
    """
    Push database settings into os.environ.

    The payment providers read their configuration from the environment at
    construction time. Rather than rewrite every provider to take a database
    handle, the settings the dashboard owns are pushed into the process
    environment and the provider cache is dropped, so the next request builds
    a provider with the new values. Called after any settings write, and once
    at startup.
    """
    for key in SETTING_SPECS:
        row = conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if row is not None and row["value"] != "":
            os.environ[key] = row["value"]
