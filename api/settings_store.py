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
#
# "default" is what the service falls back to when nothing is set anywhere. It
# is here so the dashboard can SHOW it: an unset field rendered as an empty box
# tells the operator nothing, and "ZEC confirmations before crediting" left
# blank could mean 1 or 5 — the number the invariant exists to pin down. It is
# declared only for settings whose effective value the control plane publishes
# or exposes, so test_admin.py can check each one against what the running
# service actually does rather than against a second written-down copy.
SETTING_SPECS: dict[str, dict] = {
    # --- payment provider selection ---
    "ZTV_PAYMENT_PROVIDER": {"type": "choice", "secret": False, "default": "watch",
                             "choices": ["watch", "btcpay", "hosted",
                                         "stripe", "square"],
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
                   "default": "production",
                   "choices": ["production", "sandbox"],
                   "label": "Environment"},

    # --- business wallets: where crypto actually lands ---
    # An extended PUBLIC key, so a fresh address is derived per invoice. A
    # plain address is accepted and reused, which the dashboard warns about:
    # two customers owing the same amount become impossible to tell apart.
    "WALLET_BTC": {"type": "text", "secret": False, "group": "wallets",
                   "label": "BTC xpub / zpub"},
    "WALLET_ZEC": {"type": "text", "secret": False, "group": "wallets",
                   "label": "ZEC xpub (transparent t1… addresses)"},
    "WALLET_ETH": {"type": "text", "secret": False, "group": "wallets",
                   "label": "ETH address (BTCPay/hosted only)"},

    # --- Monero ---
    # Monero has no wallet field here on purpose. There is no address to
    # paste: the chain publishes neither recipient nor amount, so payment
    # detection needs the private view key and a block scan. That is a
    # wallet, and the wallet is monero-wallet-rpc — run view-only against a
    # public remote node. scripts/setup-monero-watch.sh sets one up.
    "MONERO_WALLET_RPC": {"type": "url", "secret": False, "group": "monero",
                          "label": "monero-wallet-rpc URL (view-only)"},
    "MONERO_ACCOUNT_INDEX": {"type": "int", "secret": False, "group": "monero",
                             "default": "0",
                             "label": "Wallet account index"},
    "MONERO_RPC_USER": {"type": "text", "secret": False, "group": "monero",
                        "label": "wallet-rpc username (if --rpc-login)"},
    "MONERO_RPC_PASSWORD": {"type": "text", "secret": True, "group": "monero",
                            "label": "wallet-rpc password"},
    "XMR_CONFIRMATIONS": {"type": "int", "secret": False, "group": "monero",
                          "default": "10",
                          "label": "Confirmations before crediting (10 typical)"},

    # --- public chain endpoints ---
    # We host no chain data. These name whose node we borrow.
    "NODE_RPC_BTC": {"type": "url", "secret": False, "group": "chain",
                     "label": "BTC explorer API (Esplora)"},
    "ZTV_BTC_CONFIRMATIONS": {"type": "int", "secret": False, "group": "chain",
                              "default": "1",
                              "label": "BTC confirmations before crediting"},
    "NODE_RPC_ZEC": {"type": "url", "secret": False, "group": "chain",
                     "label": "ZEC explorer API (Blockchair or Esplora)"},
    "ZTV_ZEC_CONFIRMATIONS": {"type": "int", "secret": False, "group": "chain",
                              "default": "5",
                              "label": "ZEC confirmations before crediting"},
    "ZTV_PRICE_API": {"type": "url", "secret": False, "group": "chain",
                      "label": "USD price ticker (Kraken by default)"},
    "NODE_RPC_ETH": {"type": "url", "secret": False, "group": "chain",
                     "label": "ETH public RPC (reference only — unread)"},

    # --- pricing / trials ---
    "ZTV_TRIAL_ENABLED": {"type": "bool", "secret": False, "group": "trial",
                          "default": "1",
                          "label": "Free trials enabled"},
    "ZTV_TRIAL_DAYS": {"type": "int", "secret": False, "group": "trial",
                       "default": "7",
                       "label": "Trial length (days)"},
    "ZTV_TRIAL_MAX_DEVICES": {"type": "int", "secret": False, "group": "trial",
                              "default": "2",
                              "label": "Trial device limit"},
    "ZTV_TRIAL_POW_BITS": {"type": "int", "secret": False, "group": "trial",
                           "default": "20",
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


# Sane ranges for the numeric settings. Every SETTING_SPECS entry already
# declared a "type" and nothing enforced it, so whatever an operator typed
# into a dashboard field went into the database and then into os.environ
# verbatim — and the values are read back with a bare int(). A slip in a form
# became a 500 on whichever path read it next.
#
# The bounds are not arbitrary: a trial of 0 days is not a trial, a
# proof-of-work of 0 bits is no proof of work, and one above ~26 bits is
# minutes of phone CPU, which is a denial of service against your own funnel.
INT_BOUNDS = {
    "ZTV_TRIAL_DAYS":         (1, 365),
    "ZTV_TRIAL_MAX_DEVICES":  (1, 64),
    "ZTV_TRIAL_POW_BITS":     (8, 26),
    "ZTV_BTC_CONFIRMATIONS":  (1, 20),
    "ZTV_ZEC_CONFIRMATIONS":  (1, 20),
    "XMR_CONFIRMATIONS":      (1, 60),
}


class SettingError(ValueError):
    """A value the operator typed that we will not store."""


def validate(key: str, value: str) -> str:
    """Check one value against the type its spec declares. Returns it, or
    raises SettingError with a message meant for the person who typed it."""
    spec = SETTING_SPECS.get(key)
    if spec is None:
        return value
    if value == "":
        return value                      # clearing a setting is always fine
    kind = spec.get("type")
    label = spec.get("label", key)
    if kind == "int":
        try:
            n = int(value)
        except ValueError:
            raise SettingError(f"{label}: '{value}' is not a whole number")
        lo, hi = INT_BOUNDS.get(key, (0, 2 ** 31 - 1))
        if not (lo <= n <= hi):
            raise SettingError(f"{label}: must be between {lo} and {hi}")
        return str(n)
    if kind == "bool":
        v = value.strip().lower()
        if v not in ("0", "1", "true", "false", "yes", "no", "on", "off"):
            raise SettingError(f"{label}: use 1 or 0")
        return "1" if v in ("1", "true", "yes", "on") else "0"
    if kind == "url":
        if not value.startswith(("http://", "https://")):
            raise SettingError(f"{label}: must start with http:// or https://")
    return value


def get_int(conn, key: str, default: int) -> int:
    """A numeric setting, read from the DATABASE at the moment it is used.

    Not a module constant, and not os.environ. The constants that used to
    hold these were bound at import — before apply_to_environ() had read the
    database — so a value set in the dashboard was never used at all, not on
    the next request and not after a restart either. And os.environ is
    per-process: the service runs two uvicorn workers, so a settings write
    reaches one of them and the other keeps answering with the old number.
    Half the customers seeing one trial length and half another is worse than
    everyone seeing a stale one. The database is the only copy both workers
    share.
    """
    row = None
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?",
                           (key,)).fetchone()
    except Exception:
        pass
    raw = (row["value"] if row is not None else "") or os.environ.get(key, "")
    try:
        n = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    lo, hi = INT_BOUNDS.get(key, (0, 2 ** 31 - 1))
    return n if lo <= n <= hi else default


def get_bool(conn, key: str, default: bool) -> bool:
    row = None
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?",
                           (key,)).fetchone()
    except Exception:
        pass
    raw = (row["value"] if row is not None else "") or os.environ.get(key, "")
    v = str(raw).strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default


def set_many(conn, values: dict, username: str) -> list[str]:
    """
    Write settings. Returns the keys actually changed, so the caller can log
    exactly that and nothing more.

    A value equal to the mask means "leave it alone" — the dashboard sends
    back what it was shown, and re-saving a form should not overwrite a real
    secret with bullet characters.
    """
    now = int(time.time())

    # Validate the WHOLE batch before writing any of it. Raises SettingError,
    # which the route turns into a 400. Doing it inside the write loop would
    # leave a form half-saved when the third field is the bad one, and the
    # operator with no idea which half took.
    clean = {}
    for key, raw in values.items():
        if key not in SETTING_SPECS:
            continue                      # allowlist; silently ignore the rest
        value = "" if raw is None else str(raw).strip()
        if is_secret(key) and value.startswith(_MASK):
            continue
        clean[key] = validate(key, value)

    changed = []
    for key, value in clean.items():
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
