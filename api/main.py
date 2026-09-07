"""
0trust VPN — Backend API
========================

Endpoints:
  POST   /api/v1/account            Create a new account (returns token + invoice)
  GET    /api/v1/account/status     Check subscription status
  POST   /api/v1/account/topup      Extend existing subscription
  POST   /api/v1/payment/webhook    BTCPay Server webhook (HMAC-signed)
  GET    /api/v1/devices            List devices on this account
  DELETE /api/v1/devices/{pubkey}   Deregister a device, freeing its slot
  POST   /api/v1/wg/register        Register a device, get WireGuard config
  POST   /api/v1/wg/rotate          Rotate the entry/exit pair
  GET    /api/v1/wg/peers           Mesh peer manifest (nodes only)
  GET    /api/v1/wg/forwards        DNAT table for one entry node (nodes only)
  POST   /api/v1/node/provision     One-shot ephemeral node registration
  POST   /api/v1/node/heartbeat     Node liveness
  GET    /api/v1/regions            Public region list
  GET    /api/v1/status/public      Public, sanitized service health
  GET    /api/v1/health             Liveness probe
  GET    /api/v1/config             Public offer: trial length, caps, currencies

Idempotency:
  - wg/register is idempotent on the device pubkey. A client keeps its
    keypair, so every reconnect re-presents the same key; that returns the
    device's current config rather than trying to create a second row.
  - The payment webhook credits each invoice exactly once. BTCPay retries
    deliveries, and a captured delivery stays HMAC-valid forever, so the
    settled marker is what makes crediting single-shot.

Auth model:
  - The 16-character account token IS the credential.
  - Tokens are minted from os.urandom, stored as SHA-256 hash in DB.
  - All authenticated endpoints take token via `X-Account-Token` header.
  - There is no password reset, no recovery, no email. By design.

Run:
  uvicorn main:app --host 127.0.0.1 --port 8080 --workers 2
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
import subprocess
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

import ops_alerts

# ============================================================================
# CONFIG
# ============================================================================

DB_PATH = os.environ.get("ZTV_DB_PATH", "/var/lib/0trust/0trust.db")
MESH_NETWORK = os.environ.get("MESH_NETWORK", "10.64.0.0/10")  # ~4M addresses
NODE_API_PSK = os.environ.get("NODE_API_PSK", "")  # mesh nodes auth with this
DB_TIMEOUT_SECS = float(os.environ.get("ZTV_DB_TIMEOUT", "30"))
MAX_DEVICES_PER_ACCOUNT = int(os.environ.get("ZTV_MAX_DEVICES", "8"))

# --- Free trial -------------------------------------------------------------
# One week, no payment, no identity. Trials are the whole top of the funnel:
# the web proxy hands visitors a grant, they redeem it for a working tunnel.
TRIAL_ENABLED = os.environ.get("ZTV_TRIAL_ENABLED", "1") == "1"
TRIAL_DAYS = int(os.environ.get("ZTV_TRIAL_DAYS", "7"))
TRIAL_MAX_DEVICES = int(os.environ.get("ZTV_TRIAL_MAX_DEVICES", "2"))
# Trials cost us bandwidth and there is no identity to rate-limit against, so
# redemption costs CPU instead: a hashcash-style stamp the browser grinds.
# 20 bits is about a second of JS on a phone and makes bulk minting expensive
# without touching a captcha or an email address.
TRIAL_POW_BITS = int(os.environ.get("ZTV_TRIAL_POW_BITS", "20"))
TRIAL_CHALLENGE_TTL = int(os.environ.get("ZTV_TRIAL_CHALLENGE_TTL", "900"))
# Signs trial challenges so we can verify one we issued without storing it.
TRIAL_SECRET = os.environ.get("ZTV_TRIAL_SECRET", "")

# Crockford-ish base32 alphabet: drops 0/O/1/I/L for unambiguous reading
TOKEN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
TOKEN_LENGTH = 16  # ~80 bits entropy

PRICING = {
    1: 5.00,    # 1 month
    3: 13.00,   # 3 months
    12: 48.00,  # 12 months
}


# ============================================================================
# DATABASE
# ============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash      TEXT NOT NULL UNIQUE,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'pending_payment',
                  -- pending_payment | active | expired | banned
  plan            TEXT NOT NULL DEFAULT 'paid',   -- paid | trial
  trial_started_at INTEGER NOT NULL DEFAULT 0,
  banned_reason   TEXT,                           -- set when status = 'banned'
  banned_at       INTEGER NOT NULL DEFAULT 0,
  note            TEXT,                           -- operator note, never shown
  ip_allocation   TEXT,    -- mesh IPv4 like 10.64.12.7
  notes           TEXT
);

CREATE TABLE IF NOT EXISTS devices (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id      INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  pubkey          TEXT NOT NULL UNIQUE,
  device_name     TEXT,
  created_at      INTEGER NOT NULL,
  last_seen       INTEGER NOT NULL DEFAULT 0,
  mesh_ip         TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_devices_account ON devices(account_id);

CREATE TABLE IF NOT EXISTS invoices (
  id              TEXT PRIMARY KEY,            -- provider's invoice ID
  account_id      INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  months          INTEGER NOT NULL,
  amount_usd      REAL NOT NULL,
  currency        TEXT NOT NULL,               -- pricing currency (USD)
  status          TEXT NOT NULL,               -- pending | settled | expired | invalid
  created_at      INTEGER NOT NULL,
  settled_at      INTEGER,
  payment_address TEXT,
  amount_crypto   TEXT,
  checkout_url    TEXT                         -- hosted checkout, shown to the buyer
);
CREATE INDEX IF NOT EXISTS idx_invoices_account ON invoices(account_id);
CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status);

CREATE TABLE IF NOT EXISTS mesh_nodes (
  id              TEXT PRIMARY KEY,            -- e.g. zur-01, buc-01
  hostname        TEXT NOT NULL,
  pubkey          TEXT NOT NULL,
  endpoint        TEXT NOT NULL,               -- IP:port for WireGuard
  region          TEXT NOT NULL,               -- zur, rey, buc
  role            TEXT NOT NULL DEFAULT 'both',-- entry | exit | both
  public_ip       TEXT,                        -- for entry-side DNAT rules
  capacity        INTEGER NOT NULL DEFAULT 1000,
  active          INTEGER NOT NULL DEFAULT 1,
  ephemeral       INTEGER NOT NULL DEFAULT 0,  -- 1 = RAM-only, auto-prune on heartbeat loss
  psk_hash        TEXT,                        -- SHA256 of per-node PSK
  ipv6            INTEGER NOT NULL DEFAULT 0,  -- node has working IPv6 egress
  last_heartbeat  INTEGER NOT NULL DEFAULT 0
);

-- Next unused receive-address index for the watch-only payment provider.
-- A counter row rather than MAX(index)+1 over invoices: the read and the
-- reserve have to be one atomic step or two concurrent signups derive the
-- same address, and two customers paying the same amount into it become
-- impossible to tell apart. Allocation happens inside db(write=True), which
-- opens BEGIN IMMEDIATE.
CREATE TABLE IF NOT EXISTS address_index (
  chain  TEXT PRIMARY KEY,      -- 'btc'
  next   INTEGER NOT NULL
);

-- Operational events for the operator: a node went dark, a payment provider
-- stopped answering, the disk is filling up. Nothing here identifies a
-- customer, and nothing may be added that does — this table is the one place
-- the product deliberately keeps a running narrative of its own state, and an
-- account id in it would turn that into an activity log. Node ids, counts and
-- free-text detail about infrastructure only.
CREATE TABLE IF NOT EXISTS ops_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at  INTEGER NOT NULL,
  kind        TEXT NOT NULL,       -- node.down | node.up | provider.down | ...
  severity    TEXT NOT NULL,       -- info | warn | critical
  subject     TEXT,                -- node id, provider name; never an account
  detail      TEXT,
  delivered   INTEGER NOT NULL DEFAULT 0   -- webhook delivery attempted
);
CREATE INDEX IF NOT EXISTS idx_ops_events_time ON ops_events(created_at DESC);

-- Provisioning tokens for RAM-only mesh nodes. A token authorizes a node to
-- register itself, and is scoped to one region and role so a leaked copy
-- cannot inject a node elsewhere in the mesh.
--
-- max_uses = 1 is the original one-shot token: burned on first use, for a node
-- launched by hand or from cloud-init and never expected to come back.
--
-- A node that reboots is the harder case. Its disk is tmpfs, so its WireGuard
-- key and its node id are gone, and a one-shot token cannot re-register it —
-- the box comes back up and never rejoins. An enrolment token (max_uses > 1)
-- covers that: on first use it binds to the registering node's public IP, and
-- from then on only that address can present it. A copy exfiltrated anywhere
-- else is inert, and revoked_at kills it from the dashboard.
CREATE TABLE IF NOT EXISTS provision_tokens (
  token_hash    TEXT PRIMARY KEY,             -- SHA256(plain_token)
  region        TEXT NOT NULL,                -- restricts the token to a region
  role          TEXT NOT NULL DEFAULT 'both', -- entry | exit | both
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  used_at       INTEGER,                      -- NULL = unused; else last use
  used_node_id  TEXT,                         -- the node it registered
  max_uses      INTEGER NOT NULL DEFAULT 1,
  used_count    INTEGER NOT NULL DEFAULT 0,
  bind_ip       TEXT,                         -- pinned on first use when reusable
  revoked_at    INTEGER                       -- operator killed it
);

-- Operator accounts for the admin dashboard. Separate from customer
-- accounts in every way: a real username, a slow password hash, and
-- sessions that expire. Nothing here is ever exposed to a customer.
CREATE TABLE IF NOT EXISTS admins (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,          -- scrypt, salted, see admin.hash_password
  created_at    INTEGER NOT NULL,
  last_login    INTEGER NOT NULL DEFAULT 0,
  disabled      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS admin_sessions (
  token_hash  TEXT PRIMARY KEY,
  admin_id    INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin ON admin_sessions(admin_id);

-- Every state-changing admin action. This is the counterweight to a
-- dashboard that can ban accounts and move money: whatever an operator does,
-- there is a record of who did it and when. Deliberately append-only in
-- practice — nothing in the app deletes from it.
CREATE TABLE IF NOT EXISTS admin_audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id    INTEGER,
  username    TEXT,
  action      TEXT NOT NULL,
  target      TEXT,
  detail      TEXT,
  at          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_audit_at ON admin_audit(at);

-- Operator-editable settings, so payment credentials, wallet addresses and
-- public node endpoints can be changed from the dashboard without editing
-- api.env and restarting. Values here take precedence over the environment.
CREATE TABLE IF NOT EXISTS settings (
  key         TEXT PRIMARY KEY,
  value       TEXT NOT NULL,
  updated_at  INTEGER NOT NULL,
  updated_by  TEXT
);

-- Notices to customers.
--
-- There is no email address on any account — that is the product, not an
-- oversight — so "email the customer" is not a thing this system can do.
-- What it can do is hand a message to the client the next time it checks in.
-- The CLI and GUI surface these on `status`; broadcast notices go to
-- everyone, targeted ones to a single account.
CREATE TABLE IF NOT EXISTS notices (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id  INTEGER REFERENCES accounts(id) ON DELETE CASCADE,  -- NULL = all
  severity    TEXT NOT NULL DEFAULT 'info',   -- info | warning | urgent
  subject     TEXT NOT NULL,
  body        TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL DEFAULT 0,     -- 0 = until withdrawn
  created_by  TEXT
);
CREATE INDEX IF NOT EXISTS idx_notices_account ON notices(account_id);
CREATE INDEX IF NOT EXISTS idx_notices_created ON notices(created_at);

-- Which notices an account has already been shown, so the client can mark
-- one read rather than being nagged forever.
CREATE TABLE IF NOT EXISTS notice_reads (
  notice_id   INTEGER NOT NULL REFERENCES notices(id) ON DELETE CASCADE,
  account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  read_at     INTEGER NOT NULL,
  PRIMARY KEY (notice_id, account_id)
);

-- Which nodes have been handed a given device's public key.
--
-- /wg/peers used to return every active device to every node that asked.
-- That made a single node's PSK enough to enumerate the entire customer
-- base, which is flatly at odds with "a seized node reveals nothing
-- operational". A node only ever needs to authorize the devices actually
-- routed through it, so that is all it gets.
--
-- Rewritten on every register/rotate, so a device that moves stops being
-- disclosed to the node it left at that node's next sync.
CREATE TABLE IF NOT EXISTS device_nodes (
  device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  node_id     TEXT NOT NULL REFERENCES mesh_nodes(id) ON DELETE CASCADE,
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (device_id, node_id)
);
CREATE INDEX IF NOT EXISTS idx_device_nodes_node ON device_nodes(node_id);

-- Redeemed trial stamps. A challenge is signed rather than stored, so the
-- only thing that needs persisting is the fact that one was spent — which is
-- what stops the same solved proof-of-work being replayed into many accounts.
CREATE TABLE IF NOT EXISTS trial_grants (
  nonce        TEXT PRIMARY KEY,
  issued_at    INTEGER NOT NULL,
  redeemed_at  INTEGER NOT NULL,
  account_id   INTEGER REFERENCES accounts(id) ON DELETE SET NULL,
  source       TEXT                            -- proxy | web | cli
);
CREATE INDEX IF NOT EXISTS idx_trial_grants_time ON trial_grants(redeemed_at);

-- Multi-hop: maps a device's session to an (entry, exit) pair.
-- The client's WG Endpoint points at entry's public_ip:entry_port; nftables
-- on the entry DNATs that port to the exit's WG listener. The client's
-- WG handshake uses the EXIT's pubkey, so the entry cannot decrypt.
--
-- expires_at: pairs rotate every ~24h to cap traffic-correlation windows.
-- The sweeper deletes expired rows; clients call /wg/rotate to get a fresh
-- pair before the deadline.
CREATE TABLE IF NOT EXISTS hop_pairs (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id       INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  -- ON DELETE CASCADE on the node refs too: when the sweeper reaps a dead
  -- ephemeral node, any pair still pointing at it is already unroutable.
  -- Without the cascade that DELETE raises FOREIGN KEY constraint failed and
  -- takes the whole sweep run down with it.
  entry_node      TEXT NOT NULL REFERENCES mesh_nodes(id) ON DELETE CASCADE,
  exit_node       TEXT NOT NULL REFERENCES mesh_nodes(id) ON DELETE CASCADE,
  entry_port      INTEGER NOT NULL,
  created_at      INTEGER NOT NULL,
  expires_at      INTEGER NOT NULL,
  rotation_count  INTEGER NOT NULL DEFAULT 0,
  UNIQUE (entry_node, entry_port)
);
CREATE INDEX IF NOT EXISTS idx_hop_pairs_device  ON hop_pairs(device_id);
CREATE INDEX IF NOT EXISTS idx_hop_pairs_entry   ON hop_pairs(entry_node);
CREATE INDEX IF NOT EXISTS idx_hop_pairs_exit    ON hop_pairs(exit_node);
CREATE INDEX IF NOT EXISTS idx_hop_pairs_expires ON hop_pairs(expires_at);
"""


@contextmanager
def db(write: bool = False):
    """
    Open a connection. Pass write=True for anything that allocates a scarce
    resource (a mesh IP, an entry port, a node id) and then inserts it.

    Those are read-then-write sequences, and SQLite's default deferred
    transaction lets two workers read the same free slot and race to claim it.
    The loser hits a UNIQUE constraint and the customer gets a 500. BEGIN
    IMMEDIATE takes the write lock up front so the sequence is serialized;
    busy_timeout makes the other worker wait for it instead of erroring.
    """
    conn = sqlite3.connect(DB_PATH, isolation_level=None, timeout=DB_TIMEOUT_SECS)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(f"PRAGMA busy_timeout={int(DB_TIMEOUT_SECS * 1000)}")
    conn.row_factory = sqlite3.Row
    try:
        if write:
            conn.execute("BEGIN IMMEDIATE")
        yield conn
        if write:
            conn.execute("COMMIT")
    except BaseException:
        if write:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
        raise
    finally:
        conn.close()


# Columns added after the first release. SQLite can ADD COLUMN in place, so
# each entry is applied to databases that predate it and skipped otherwise.
MIGRATIONS = [
    ("invoices", "checkout_url", "TEXT"),
    # device_nodes is created by SCHEMA; nothing to add to an existing table.
    ("accounts", "plan", "TEXT NOT NULL DEFAULT 'paid'"),
    ("accounts", "trial_started_at", "INTEGER NOT NULL DEFAULT 0"),
    ("accounts", "banned_reason", "TEXT"),
    ("accounts", "banned_at", "INTEGER NOT NULL DEFAULT 0"),
    ("accounts", "note", "TEXT"),
    ("mesh_nodes", "ipv6", "INTEGER NOT NULL DEFAULT 0"),
    ("invoices", "derivation_index", "INTEGER"),
    # Which coin the customer is paying in. The poller needs it to know which
    # chain to ask and how many atomic units a whole coin is — 1e8 for BTC and
    # ZEC, 1e12 for XMR. Rows written before this existed are Bitcoin.
    ("invoices", "pay_currency", "TEXT NOT NULL DEFAULT 'BTC'"),
    # Reusable, IP-bound enrolment tokens. Existing rows keep max_uses = 1, so
    # a database from before this change behaves exactly as it did.
    ("provision_tokens", "max_uses", "INTEGER NOT NULL DEFAULT 1"),
    ("provision_tokens", "used_count", "INTEGER NOT NULL DEFAULT 0"),
    ("provision_tokens", "bind_ip", "TEXT"),
    ("provision_tokens", "revoked_at", "INTEGER"),
]


def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(SCHEMA)
        for table, column, decl in MIGRATIONS:
            have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
            if column not in have:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


# ============================================================================
# CRYPTO / TOKEN HELPERS
# ============================================================================

def generate_token() -> str:
    """Mint a fresh account token. 16 chars in 4-char groups."""
    raw = "".join(
        TOKEN_ALPHABET[b % len(TOKEN_ALPHABET)]
        for b in secrets.token_bytes(TOKEN_LENGTH)
    )
    return "-".join(raw[i:i + 4] for i in range(0, TOKEN_LENGTH, 4))


def hash_token(token: str) -> str:
    """Constant-time-safe storage hash. Normalize before hashing."""
    normalized = token.upper().replace("-", "").replace(" ", "")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def verify_token(token: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_token(token), stored_hash)


# ============================================================================
# WIREGUARD KEY GENERATION
# ============================================================================

def wg_genkey() -> tuple[str, str]:
    """Generate a WireGuard keypair. Returns (private_key, public_key)."""
    priv = subprocess.run(
        ["wg", "genkey"], capture_output=True, check=True, text=True
    ).stdout.strip()
    pub = subprocess.run(
        ["wg", "pubkey"], input=priv, capture_output=True, check=True, text=True
    ).stdout.strip()
    return priv, pub


def mesh_ip6(v4: str) -> str:
    """The IPv6 mesh address for a device, derived from its IPv4 one."""
    net6 = ipaddress.ip_network(MESH_NETWORK6)
    return str(ipaddress.IPv6Address(
        int(net6.network_address) + int(ipaddress.IPv4Address(v4))))


def mesh_gateway6() -> str:
    """The gateway's v6 address — same derivation, so the two cannot drift."""
    return mesh_ip6(MESH_GATEWAY_IP)


def allocate_mesh_ip(conn) -> str:
    """Pick an unused IP from the mesh range. Linear scan; fine for <100k peers."""
    network = ipaddress.ip_network(MESH_NETWORK)
    used = {row["mesh_ip"] for row in conn.execute("SELECT mesh_ip FROM devices")}
    used.add(str(network.network_address))  # reserve .0
    used.add(str(network.network_address + 1))  # reserve .1 (gateway)
    for host in network.hosts():
        candidate = str(host)
        if candidate not in used:
            return candidate
    raise HTTPException(503, "Mesh address pool exhausted")


# ============================================================================
# BTCPAY INTEGRATION
# ============================================================================

import payments  # noqa: E402  (kept next to its only users)
from payments import (  # noqa: E402
    CURRENCIES, EXPIRED, INVALID, PENDING, SETTLED, PaymentError, provider,
)


def _next_address_index(chain: str = "btc") -> int:
    """
    Reserve the next receive-address index.

    Read and increment in one BEGIN IMMEDIATE transaction. Two signups landing
    together must not derive the same address: the whole point of a fresh
    address per invoice is that a payment identifies which invoice it settles,
    and a shared one destroys that as soon as two customers owe the same
    amount.
    """
    with db(write=True) as conn:
        row = conn.execute(
            "SELECT next FROM address_index WHERE chain = ?", (chain,)).fetchone()
        idx = int(row["next"]) if row else 0
        conn.execute(
            "INSERT INTO address_index (chain, next) VALUES (?, ?) "
            "ON CONFLICT(chain) DO UPDATE SET next = ?",
            (chain, idx + 1, idx + 1))
    return idx


def create_invoice(account_id: int, months: int, amount_usd: float,
                   coin: str = "") -> dict:
    """
    Open an invoice with whichever provider is configured. Returns the
    normalized shape: {id, checkout_url, status, raw}, plus payment_address
    and amount_crypto where the provider derives them itself.
    """
    kwargs = {}
    if payments.provider_name() == "watch":
        offered = payments.currencies_for("watch")
        if not offered:
            raise HTTPException(502, "Payment processor unavailable")
        coin = (coin or offered[0]).upper()
        if coin not in offered:
            # A 400, not a 502: the request asked for something this
            # deployment does not take, and the client can pick again.
            raise HTTPException(
                400, f"{coin} is not accepted here; this deployment takes "
                     f"{', '.join(offered)}")
        kwargs["coin"] = coin
        if coin != "XMR":
            # Monero's subaddress index comes from the wallet, not from us.
            # One counter per coin: sharing one would skip indices in each
            # wallet and leave gaps an operator restoring from seed has to
            # scan past.
            kwargs["index"] = _next_address_index(coin.lower())
    try:
        return provider().create_invoice(
            amount_usd=amount_usd,
            account_id=account_id,
            months=months,
            redirect_url="https://0trustvpn.com/welcome",
            **kwargs,
        )
    except HTTPException:
        raise
    except PaymentError as e:
        # Don't leak provider internals to clients
        raise HTTPException(502, "Payment processor unavailable") from e


# ============================================================================
# SCHEMAS
# ============================================================================

class AccountCreateRequest(BaseModel):
    months: int = Field(..., description="Subscription duration in months")
    # Which coin to be invoiced in. Validated against what this deployment can
    # actually issue an address for, not against a constant: offering a coin
    # with no wallet behind it sends the customer to an address that does not
    # exist, and they would have no way to know.
    currency: str = Field("", description="BTC | ZEC | XMR (provider-dependent)")

    @field_validator("currency")
    @classmethod
    def known_currency(cls, v: str) -> str:
        v = (v or "").strip().upper()
        if not v:
            return v
        if not v.isalnum() or len(v) > 8:
            raise ValueError("currency must be a short code like BTC")
        return v

    @field_validator("months")
    @classmethod
    def must_be_priced(cls, v: int) -> int:
        if v not in PRICING:
            raise ValueError(f"months must be one of {list(PRICING)}")
        return v


class AccountCreateResponse(BaseModel):
    token: str
    invoice_id: str
    checkout_url: str
    amount_usd: float


class AccountStatusResponse(BaseModel):
    status: str
    expires_at: Optional[int]
    days_remaining: Optional[int]
    device_count: int
    plan: str = "paid"
    max_devices: int = MAX_DEVICES_PER_ACCOUNT
    notices: int = 0          # unread; fetch them from /api/v1/notices


class WGRegisterRequest(BaseModel):
    pubkey: str = Field(..., min_length=44, max_length=44)
    device_name: str = Field(..., min_length=1, max_length=64)
    region: str = Field("zur", description="Preferred entry region")
    exit_region: str | None = Field(
        None,
        description="If set, enables multi-hop: entry and exit are separate nodes",
    )


class WGRegisterResponse(BaseModel):
    interface_ip: str
    # Set only when the exit node actually has IPv6 egress. AllowedIPs claims
    # ::/0 either way — that is what stops v6 leaking around the tunnel on a
    # dual-stack host — so a client without this address has v6 blackholed
    # rather than exposed, exactly as before.
    interface_ip6: str | None = None
    dns: list[str]
    peers: list[dict]
    multihop: bool = False
    entry_node: str | None = None
    exit_node: str | None = None
    expires_at: int | None = None   # epoch secs; multi-hop only
    # True when entry and exit turn out to be the same machine — a one-box
    # test deployment. The route is real; the privacy property is not.
    same_host: bool = False


# ============================================================================
# AUTH DEPENDENCY
# ============================================================================

def _device_cap(plan: str) -> int:
    """Trials get fewer slots — enough for a laptop and a phone."""
    return TRIAL_MAX_DEVICES if plan == "trial" else MAX_DEVICES_PER_ACCOUNT


def require_account(x_account_token: str = Header(...)) -> dict:
    """Resolve and authenticate an account from the X-Account-Token header."""
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM accounts WHERE token_hash = ?",
            (hash_token(x_account_token),),
        ).fetchone()
    if not row:
        raise HTTPException(401, "Invalid account token")
    if row["status"] == "banned":
        raise HTTPException(403, "Account suspended")
    return dict(row)


def require_active_account(account: dict = Depends(require_account)) -> dict:
    now = int(time.time())
    if account["status"] != "active" or account["expires_at"] < now:
        raise HTTPException(402, "Subscription inactive — top up to continue")
    return account

# ----------------------------------------------------------------------------
# MESH NODE AUTH (used by node-only endpoints below)
# ----------------------------------------------------------------------------

def require_node(x_node_psk: str = Header(...)) -> Optional[str]:
    """
    Mesh nodes authenticate with X-Node-Psk. We accept two kinds:
      1. The global NODE_API_PSK env var (legacy / non-ephemeral nodes)
      2. A per-node PSK matching psk_hash in the mesh_nodes table (ephemeral)
    The per-node form is preferred so rotating one node's PSK doesn't require
    restarting the others.

    Returns the node id when the credential identifies one, else None for the
    shared PSK. Callers use that to scope a response to the calling node.
    """
    # Match per-node PSKs first, so a node presenting its own credential is
    # identified even if it also happens to equal the shared one.
    h = hashlib.sha256(x_node_psk.encode()).hexdigest()
    with db() as conn:
        row = conn.execute(
            "SELECT id FROM mesh_nodes WHERE psk_hash = ? AND active = 1",
            (h,),
        ).fetchone()
    if row:
        return row["id"]
    if NODE_API_PSK and hmac.compare_digest(x_node_psk, NODE_API_PSK):
        return None
    raise HTTPException(401, "Invalid node credential")



# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(
    title="0trust VPN API",
    version="0.1.0",
    docs_url=None,        # disable Swagger in production
    redoc_url=None,       # disable ReDoc in production
    openapi_url=None,     # don't expose schema
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://0trustvpn.com", "https://www.0trustvpn.com"],
    allow_methods=["GET", "POST", "DELETE", "PATCH"],
    allow_headers=["Content-Type", "X-Account-Token", "X-Admin-CSRF"],
    allow_credentials=True,
)


# Mounted after the app exists so admin.py can import main without a cycle.
import admin as admin_module          # noqa: E402
import settings_store as settings     # noqa: E402

app.include_router(admin_module.router)


@app.on_event("startup")
def startup():
    init_db()
    # Settings the dashboard owns live in the database and take precedence
    # over the environment. Push them out before the first request builds a
    # payment provider, or the API runs on stale credentials until a restart.
    with db() as conn:
        settings.apply_to_environ(conn)
    _bootstrap_admin()


def _bootstrap_admin() -> None:
    """
    Create the first operator from the environment, if asked.

    ZTV_ADMIN_USER / ZTV_ADMIN_PASSWORD let the installer seed an account for
    an unattended deploy. Without them the dashboard shows a one-time setup
    screen instead, which is the better default: a password that was never in
    a config file cannot leak from one.
    """
    user = os.environ.get("ZTV_ADMIN_USER", "").strip()
    password = os.environ.get("ZTV_ADMIN_PASSWORD", "")
    if not user or not password:
        return
    with db(write=True) as conn:
        exists = conn.execute("SELECT 1 FROM admins WHERE username = ?",
                              (user,)).fetchone()
        if exists:
            return
        admin_module.ensure_admin(conn, user, password)
        admin_module.audit(conn, None, "admin.setup", user, "seeded from environment")


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "ts": int(time.time())}


def duration_label(days: int) -> str:
    """
    Say a number of days the way a person would: 7 -> "one week".

    Copy that hardcodes "free month" is copy that lies the moment an operator
    changes ZTV_TRIAL_DAYS in the dashboard. For a product whose entire pitch
    is that its claims are checkable, advertising a month and granting a week
    is exactly the drift we cannot afford, so every surface renders the offer
    from here instead of writing it out longhand.
    """
    if days <= 0:
        return "no time at all"
    words = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six"}
    for size, unit in ((365, "year"), (30, "month"), (7, "week")):
        if days % size == 0:
            n = days // size
            if n in words:
                return f"{words[n]} {unit}" + ("" if n == 1 else "s")
            return f"{n} {unit}s"
    if days in words:
        return f"{words[days]} day" + ("" if days == 1 else "s")
    return f"{days} days"


@app.get("/api/v1/config")
def public_config() -> dict:
    """
    What the offer actually is, for anything that has to describe it.

    The landing page, the trial page, the /surf banner and the desktop GUI all
    used to spell the trial length out in their own words. Read from here they
    cannot disagree with the control plane, or with each other.
    """
    prov = payments.provider_name()
    return {
        "trial": {
            "enabled": TRIAL_ENABLED,
            "days": TRIAL_DAYS,
            "label": duration_label(TRIAL_DAYS),
            "max_devices": TRIAL_MAX_DEVICES,
        },
        "max_devices": MAX_DEVICES_PER_ACCOUNT,
        "currencies": list(payments.currencies_for(prov)),
        # Per-coin confirmation depth, so no page has to restate it. Empty
        # for providers that settle on their own webhook rather than on a
        # depth this deployment chooses.
        "confirmations": payments.confirmations_for(prov),
        "takes_cards": payments.is_card_provider(prov),
        "mesh_network": MESH_NETWORK,
    }


# Mapping from region code → display name. The set of region codes that
# actually exist is determined by `mesh_nodes`; this dict just gives them
# human-readable labels. Codes not in this dict fall back to the bare code.
REGION_NAMES = {
    "zur": "Zurich, Switzerland",
    "rey": "Reykjavik, Iceland",
    "buc": "Bucharest, Romania",
}


@app.get("/api/v1/regions")
def regions():
    """
    Public list of regions where 0trust currently runs mesh nodes.
    Derived from the live `mesh_nodes` table — if you deploy a fourth
    node in a new region, it shows up here without a code change.
    """
    with db() as conn:
        rows = conn.execute(
            """SELECT DISTINCT region FROM mesh_nodes
                WHERE active = 1
                ORDER BY region"""
        ).fetchall()
    items = [
        {"code": r["region"], "name": REGION_NAMES.get(r["region"], r["region"])}
        for r in rows
    ]
    return {"regions": items}


def _validate_regions(conn, entry: str, exit_: Optional[str]) -> None:
    """
    Reject region codes that don't correspond to an active mesh node.
    Reused by both wg_register and wg_rotate so the rules can't drift.

    Raises HTTPException(400) on bad input, (503) if no nodes at all.
    """
    active = {
        r["region"]
        for r in conn.execute(
            "SELECT DISTINCT region FROM mesh_nodes WHERE active = 1"
        ).fetchall()
    }
    if not active:
        raise HTTPException(503, "No mesh nodes are currently available")
    if entry not in active:
        raise HTTPException(
            400, f"Unknown region '{entry}'. Available: {sorted(active)}"
        )
    if exit_ is not None:
        if exit_ not in active:
            raise HTTPException(
                400,
                f"Unknown exit region '{exit_}'. Available: {sorted(active)}",
            )
        if exit_ == entry:
            raise HTTPException(
                400, "Multi-hop requires entry and exit in different regions"
            )


# ----------------------------------------------------------------------------
# ACCOUNT
# ----------------------------------------------------------------------------

@app.post("/api/v1/account", response_model=AccountCreateResponse)
def create_account(req: AccountCreateRequest):
    """
    Mint a fresh account token + open a crypto invoice.
    The token is returned ONCE — never stored in plaintext, never recoverable.
    """
    token = generate_token()
    token_hash = hash_token(token)
    now = int(time.time())
    amount = PRICING[req.months]

    with db(write=True) as conn:
        cur = conn.execute(
            "INSERT INTO accounts (token_hash, created_at, status) VALUES (?, ?, 'pending_payment')",
            (token_hash, now),
        )
        account_id = cur.lastrowid

    # BTCPay is a network call — deliberately outside the transaction, since
    # holding SQLite's write lock across a 10s HTTP timeout would stall every
    # other writer. If it fails, take the account row back out rather than
    # leaving an unreachable pending_payment row behind on every outage; the
    # customer never received the token, so nothing is lost by removing it.
    try:
        invoice = create_invoice(account_id, req.months, amount,
                                 coin=req.currency)
    except BaseException:
        with db(write=True) as conn:
            conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        raise

    with db(write=True) as conn:
        conn.execute(
            """INSERT INTO invoices
                 (id, account_id, months, amount_usd, currency, status,
                  created_at, checkout_url, payment_address, amount_crypto,
                  derivation_index, pay_currency)
               VALUES (?, ?, ?, ?, 'USD', ?, ?, ?, ?, ?, ?, ?)""",
            (invoice["id"], account_id, req.months, amount, invoice["status"],
             now, invoice.get("checkout_url", ""),
             invoice.get("payment_address"), invoice.get("amount_crypto"),
             invoice.get("derivation_index"),
             invoice.get("pay_currency", "BTC")),
        )

    return AccountCreateResponse(
        token=token,
        invoice_id=invoice["id"],
        checkout_url=invoice["checkout_url"],
        amount_usd=amount,
    )


# ----------------------------------------------------------------------------
# FREE TRIAL
# ----------------------------------------------------------------------------
# Two steps so the cost lands on the client, not on us:
#
#   GET  /api/v1/trial/challenge  ->  a signed nonce + difficulty
#   POST /api/v1/trial            ->  nonce + solution, returns an account token
#
# The challenge is an HMAC over (nonce, expiry) under TRIAL_SECRET, so the
# server verifies its own issuance without storing anything. Redeemed nonces
# ARE stored, because that's the only way to stop one solved stamp minting a
# hundred accounts.

class TrialChallenge(BaseModel):
    nonce: str
    bits: int
    expires_at: int
    signature: str


class TrialRedeemRequest(BaseModel):
    nonce: str
    expires_at: int
    signature: str
    solution: str = Field(..., max_length=64)
    source: str = Field("web", max_length=16)


class TrialResponse(BaseModel):
    token: str
    plan: str
    expires_at: int
    days: int
    max_devices: int


def _trial_secret() -> str:
    if TRIAL_SECRET:
        return TRIAL_SECRET
    # Refuse rather than fall back to something guessable: an attacker who can
    # forge challenges skips the proof-of-work entirely.
    raise HTTPException(503, "Trials are not configured on this deployment")


def _sign_challenge(nonce: str, expires_at: int) -> str:
    return hmac.new(
        _trial_secret().encode(), f"{nonce}:{expires_at}".encode(), hashlib.sha256
    ).hexdigest()


def _pow_ok(nonce: str, solution: str, bits: int) -> bool:
    """Leading-zero-bit check over SHA-256(nonce:solution)."""
    digest = hashlib.sha256(f"{nonce}:{solution}".encode()).digest()
    need_bytes, need_bits = divmod(bits, 8)
    if any(digest[i] for i in range(need_bytes)):
        return False
    if need_bits and digest[need_bytes] >> (8 - need_bits):
        return False
    return True


@app.get("/api/v1/trial/challenge", response_model=TrialChallenge)
def trial_challenge():
    """Hand out a proof-of-work challenge for a free trial."""
    if not TRIAL_ENABLED:
        raise HTTPException(404, "Trials are not available")
    nonce = secrets.token_hex(16)
    expires_at = int(time.time()) + TRIAL_CHALLENGE_TTL
    return TrialChallenge(
        nonce=nonce, bits=TRIAL_POW_BITS, expires_at=expires_at,
        signature=_sign_challenge(nonce, expires_at),
    )


@app.post("/api/v1/trial", response_model=TrialResponse)
def redeem_trial(req: TrialRedeemRequest):
    """
    Redeem a solved challenge for a trial account. No payment, no email, no
    identity — same anonymous token a paying customer gets, time-limited.
    """
    if not TRIAL_ENABLED:
        raise HTTPException(404, "Trials are not available")

    now = int(time.time())
    if req.expires_at < now:
        raise HTTPException(400, "Challenge expired — request a new one")
    if req.expires_at > now + TRIAL_CHALLENGE_TTL + 60:
        raise HTTPException(400, "Challenge expiry is implausible")
    if not hmac.compare_digest(_sign_challenge(req.nonce, req.expires_at),
                               req.signature):
        raise HTTPException(400, "Challenge signature invalid")
    if not _pow_ok(req.nonce, req.solution, TRIAL_POW_BITS):
        raise HTTPException(400, "Proof of work does not meet the difficulty")

    token = generate_token()
    expires = now + TRIAL_DAYS * 86400

    with db(write=True) as conn:
        # Burning the nonce is what makes one stamp worth one account. The
        # PRIMARY KEY does the work: a replay loses the race and gets a 409.
        try:
            conn.execute(
                """INSERT INTO trial_grants (nonce, issued_at, redeemed_at, source)
                   VALUES (?, ?, ?, ?)""",
                (req.nonce, req.expires_at - TRIAL_CHALLENGE_TTL, now,
                 req.source[:16]),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "This challenge has already been redeemed")

        cur = conn.execute(
            """INSERT INTO accounts
                 (token_hash, created_at, expires_at, status, plan, trial_started_at)
               VALUES (?, ?, ?, 'active', 'trial', ?)""",
            (hash_token(token), now, expires, now),
        )
        conn.execute("UPDATE trial_grants SET account_id = ? WHERE nonce = ?",
                     (cur.lastrowid, req.nonce))

    return TrialResponse(token=token, plan="trial", expires_at=expires,
                         days=TRIAL_DAYS, max_devices=TRIAL_MAX_DEVICES)


@app.get("/api/v1/account/status", response_model=AccountStatusResponse)
def account_status(account: dict = Depends(require_account)):
    now = int(time.time())
    expires = account["expires_at"]
    with db() as conn:
        device_count = conn.execute(
            "SELECT COUNT(*) AS n FROM devices WHERE account_id = ?",
            (account["id"],),
        ).fetchone()["n"]
    plan = account["plan"] if "plan" in account.keys() else "paid"
    with db() as conn:
        unread = conn.execute(
            """SELECT COUNT(*) FROM notices n
               WHERE (n.account_id IS NULL OR n.account_id = ?)
                 AND (n.expires_at = 0 OR n.expires_at > ?)
                 AND n.id NOT IN (SELECT notice_id FROM notice_reads
                                  WHERE account_id = ?)""",
            (account["id"], now, account["id"])).fetchone()[0]
    return AccountStatusResponse(
        status=account["status"],
        expires_at=expires or None,
        # Round UP, not down. Floor division showed "0 days remaining" beside
        # status "active" for the whole final day of a subscription, and showed
        # 29 one second after a customer paid for 30. Every consumer (CLI, GUI,
        # Android) prints this straight to the customer, and expires_at is on
        # the same response for anything needing the exact instant.
        days_remaining=max(0, -((now - expires) // 86400)) if expires else None,
        device_count=device_count,
        plan=plan,
        max_devices=_device_cap(plan),
        notices=unread,
    )


class NoticeOut(BaseModel):
    id: int
    severity: str
    subject: str
    body: str
    created_at: int


@app.get("/api/v1/notices", response_model=list[NoticeOut])
def get_notices(account: dict = Depends(require_account)):
    """
    Messages waiting for this account.

    The delivery half of the admin notice system. There is no email address to
    send to, so a notice sits here until the client asks — `0trust status`,
    the GUI, or the mobile app. Broadcasts and account-specific messages come
    back together, newest first, minus anything already marked read.
    """
    now = int(time.time())
    with db() as conn:
        rows = conn.execute(
            """SELECT n.id, n.severity, n.subject, n.body, n.created_at
               FROM notices n
               WHERE (n.account_id IS NULL OR n.account_id = ?)
                 AND (n.expires_at = 0 OR n.expires_at > ?)
                 AND n.id NOT IN (SELECT notice_id FROM notice_reads
                                  WHERE account_id = ?)
               ORDER BY
                 CASE n.severity WHEN 'urgent' THEN 0
                                 WHEN 'warning' THEN 1 ELSE 2 END,
                 n.created_at DESC
               LIMIT 20""",
            (account["id"], now, account["id"]),
        ).fetchall()
    return [NoticeOut(**dict(r)) for r in rows]


@app.post("/api/v1/notices/{notice_id}/read")
def mark_notice_read(notice_id: int, account: dict = Depends(require_account)):
    """Acknowledge a notice so it stops coming back."""
    with db(write=True) as conn:
        exists = conn.execute(
            """SELECT 1 FROM notices WHERE id = ?
               AND (account_id IS NULL OR account_id = ?)""",
            (notice_id, account["id"])).fetchone()
        if not exists:
            raise HTTPException(404, "No such notice")
        conn.execute(
            """INSERT OR IGNORE INTO notice_reads (notice_id, account_id, read_at)
               VALUES (?, ?, ?)""",
            (notice_id, account["id"], int(time.time())))
    return {"ok": True}


@app.post("/api/v1/account/topup", response_model=AccountCreateResponse)
def topup(req: AccountCreateRequest, account: dict = Depends(require_account)):
    """Open another invoice for an existing account. Extends on payment."""
    amount = PRICING[req.months]
    invoice = create_invoice(account["id"], req.months, amount,
                             coin=req.currency)
    now = int(time.time())

    with db(write=True) as conn:
        conn.execute(
            """INSERT INTO invoices
                 (id, account_id, months, amount_usd, currency, status,
                  created_at, checkout_url, payment_address, amount_crypto,
                  derivation_index, pay_currency)
               VALUES (?, ?, ?, ?, 'USD', ?, ?, ?, ?, ?, ?, ?)""",
            (invoice["id"], account["id"], req.months, amount, invoice["status"],
             now, invoice.get("checkout_url", ""),
             invoice.get("payment_address"), invoice.get("amount_crypto"),
             invoice.get("derivation_index"),
             invoice.get("pay_currency", "BTC")),
        )

    return AccountCreateResponse(
        # No new token is minted on a top-up; the caller already holds theirs
        # and we never store it in a form we could echo back.
        token="",
        invoice_id=invoice["id"],
        checkout_url=invoice["checkout_url"],
        amount_usd=amount,
    )


# ----------------------------------------------------------------------------
# PAYMENT STATUS (frontend polling)
# ----------------------------------------------------------------------------

@app.get("/api/v1/payment/{invoice_id}/methods")
def payment_methods(invoice_id: str):
    """
    Return per-currency payment addresses + amounts for the checkout UI.
    Public — the invoice ID is the only secret needed to view it.
    """
    with db() as conn:
        row = conn.execute(
            """SELECT id, checkout_url, payment_address, amount_crypto,
                      pay_currency
                 FROM invoices WHERE id = ?""", (invoice_id,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Invoice not found")

    # The watch-only provider derived the address when the invoice was opened
    # and we stored it. Asking the explorer again would tell us nothing new
    # and would put a third party in the path of rendering a checkout page.
    if row["payment_address"]:
        amount = row["amount_crypto"] or ""
        coin = (row["pay_currency"] or "BTC").upper()
        # The URI scheme a wallet app recognises. Getting this wrong means the
        # customer's QR scan opens the wrong wallet, or nothing at all.
        scheme = {"BTC": "bitcoin", "ZEC": "zcash", "XMR": "monero"}.get(
            coin, coin.lower())
        # Monero's URI parameter is tx_amount, not amount. A Bitcoin-shaped
        # URI silently loses the amount in every Monero wallet that reads it.
        amount_key = "tx_amount" if coin == "XMR" else "amount"
        return {"methods": [{
            "currency": coin,
            "address": row["payment_address"],
            "amount": amount,
            "rate": None,
            "uri": f"{scheme}:{row['payment_address']}"
                   + (f"?{amount_key}={amount}" if amount else ""),
        }], "checkout_url": ""}

    try:
        methods = provider().get_payment_methods(invoice_id)
    except PaymentError:
        raise HTTPException(502, "Payment processor unavailable")

    # Providers already normalize to {currency, address, amount, rate, uri}.
    # A hosted gateway keeps the customer on its own checkout and returns
    # nothing here, so the UI falls back to checkout_url.
    return {"methods": methods, "checkout_url": row["checkout_url"] or ""}


@app.get("/api/v1/payment/{invoice_id}/status")
def payment_status(invoice_id: str):
    """
    Lightweight status poll for the frontend. Returns local DB state plus
    a sync from BTCPay so the UI updates without waiting for the webhook.
    """
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Invoice not found")

    # If a webhook already reached a terminal state, return it immediately
    if row["status"] in (SETTLED, EXPIRED, INVALID):
        return {"status": row["status"], "settled_at": row["settled_at"]}

    # Otherwise ask the provider (cheap call; rate-limited at nginx).
    #
    # Read-only on purpose: this endpoint is unauthenticated, so a poll must
    # never be able to credit an account. Settlement happens in the webhook,
    # which is signed, or in the poller for the watch-only provider. The worst
    # a forged poll achieves is a stale label.
    p = provider()
    if row["payment_address"] and hasattr(p, "check"):
        try:
            # Per-coin atomic units, and the coin and derivation ref passed
            # through. This hardcoded 1e8 and named no coin, which is the same
            # defect already fixed in the poller: an XMR invoice was compared
            # against a figure four orders of magnitude out, and a ZEC or XMR
            # address was looked up on Bitcoin's explorer because check()
            # defaults to BTC. Read-only, so it never credited anything — it
            # just told the customer something untrue about their own money.
            coin = (row["pay_currency"] or "BTC").upper()
            units = payments.COIN_UNITS.get(coin)
            if units is None:
                return {"status": row["status"], "settled_at": None}
            atomic = int(round(float(row["amount_crypto"] or 0) * units))
            live = p.check(row["payment_address"], atomic, coin=coin,
                           ref=row["derivation_index"])
        except (PaymentError, ValueError):
            return {"status": row["status"], "settled_at": None}
        # "Seen but not confirmed" is the state customers ask support about.
        # Saying it out loud stops the page looking broken while they wait for
        # a block, and stops them paying twice.
        # Also as decimal strings in the invoice's own currency. The page must
        # not have to know that BTC is 1e8 and XMR is 1e12 — that arithmetic
        # has been got wrong twice already, once in the poller and once in
        # this very handler, and duplicating it into JavaScript would be the
        # third time.
        def _amount(atomic: int) -> str:
            return f"{atomic / units:.8f}".rstrip("0").rstrip(".") or "0"

        confirmed = int(live.get("confirmed_sats", 0))
        expected = int(live.get("expected_sats", 0))
        return {"status": row["status"],
                "settled_at": None,
                "seen": live.get("seen", False),
                "currency": coin,
                "confirmed_sats": confirmed,
                "expected_sats": expected,
                "confirmed_amount": _amount(confirmed),
                "expected_amount": _amount(expected),
                # Money arrived, but not enough. Without this the customer
                # watches an unchanged page until the invoice expires and is
                # told to "start over", having already sent real coin to an
                # address we control.
                "short_by": _amount(max(0, expected - confirmed)),
                "underpaid": 0 < confirmed < expected,
                # How deep this deployment buries a payment before crediting
                # it. Zcash ships at five, so a customer whose coin is already
                # on the chain can sit on "waiting" for six minutes; a page
                # that will not say how long is a page that looks stuck, and a
                # customer who thinks it is stuck pays twice.
                "confirmations_required": int(
                    live.get("confirmations_required") or 1),
                # `seen_enough` was never a key check() returns, so the second
                # half of this condition was always true and the name promised
                # a distinction the code did not make.
                "awaiting_confirmation": bool(live.get("unconfirmed_sats"))}
    try:
        live = p.get_invoice(invoice_id)
        return {"status": live.get("status", row["status"]), "settled_at": None}
    except PaymentError:
        return {"status": row["status"], "settled_at": None}


# ----------------------------------------------------------------------------
# PAYMENT WEBHOOK
# ----------------------------------------------------------------------------

@app.post("/api/v1/payment/webhook")
async def payment_webhook(request: Request):
    """
    The provider calls this when invoice state changes. On settlement we
    extend the account's expiry by `months` and mark it active.
    """
    body = await request.body()
    pv = provider()
    if not pv.verify_webhook(body, request.headers):
        raise HTTPException(401, "Invalid webhook signature")

    try:
        invoice_id, event_type = pv.parse_webhook(body)
    except ValueError:
        raise HTTPException(400, "Malformed webhook body")

    if not invoice_id or not event_type:
        return {"ok": False}

    with db(write=True) as conn:
        inv = conn.execute(
            "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
        ).fetchone()
        if not inv:
            return {"ok": False, "reason": "unknown invoice"}

        if event_type == SETTLED:
            # Credit each invoice EXACTLY once. BTCPay retries a delivery it
            # didn't get a 2xx for, and re-sends on redelivery, so this handler
            # sees duplicates in normal operation — and anyone who captured one
            # signed delivery could otherwise replay it for unlimited free
            # months, since the HMAC stays valid forever. The settled_at
            # marker, not the signature, is what makes crediting single-shot.
            if inv["status"] == SETTLED:
                return {"ok": True, "duplicate": True}

            now = int(time.time())
            acc = conn.execute(
                "SELECT * FROM accounts WHERE id = ?", (inv["account_id"],)
            ).fetchone()
            if not acc:
                return {"ok": False, "reason": "unknown account"}
            base = max(acc["expires_at"], now)
            new_expiry = base + inv["months"] * 30 * 86400
            # Guard the credit on the invoice still being uncredited, so two
            # concurrent deliveries of the same invoice can't both apply.
            cur = conn.execute(
                """UPDATE invoices SET status = ?, settled_at = ?
                   WHERE id = ? AND status != ?""",
                (SETTLED, now, invoice_id, SETTLED),
            )
            if cur.rowcount == 0:
                return {"ok": True, "duplicate": True}
            # Paying converts a trial to paid, and the paid months stack on
            # whatever the trial had left (that's what max(expires_at, now)
            # above computes). Starting the paid term from settlement instead
            # would punish converting early, which is exactly the behaviour we
            # want to encourage.
            conn.execute(
                """UPDATE accounts
                   SET status = 'active', expires_at = ?, plan = 'paid'
                   WHERE id = ?""",
                (new_expiry, acc["id"]),
            )
        elif event_type in (EXPIRED, INVALID):
            # Never walk a settled invoice backwards — providers can emit an
            # expiry for an invoice that settled late.
            conn.execute(
                "UPDATE invoices SET status = ? WHERE id = ? AND status != ?",
                (event_type, invoice_id, SETTLED),
            )

    return {"ok": True}


# ----------------------------------------------------------------------------
# WIREGUARD
# ----------------------------------------------------------------------------

# Multi-hop entry-port allocation range. 8000 slots per entry node is plenty —
# at 1 slot per active device, that's 8000 simultaneous sessions per entry.
# How long after its last heartbeat a node is still considered live.
# meshd checks in every 30s, so five minutes is ten missed beats — long enough
# to ride out a blip, short enough that customers stop being routed into a
# corpse within one rotation.
NODE_STALE_SECS = int(os.environ.get("ZTV_NODE_STALE_SECS", "300"))

# The resolver address every client config names. Something has to answer here
# or a connected customer resolves nothing; scripts/node-runtime.sh puts
# dnsmasq on it. Keep the two in step.
MESH_GATEWAY_IP = os.environ.get("ZTV_MESH_GATEWAY_IP", "10.64.0.1")

# --- IPv6 inside the tunnel -------------------------------------------------
# A ULA prefix (RFC 4193), generated randomly once and fixed here. It never
# appears outside the mesh: the exit masquerades v6 the same way it does v4,
# so what a website sees is the node's address, not this.
#
# A device's v6 address is its v4 address embedded in the low 32 bits, so
# 10.64.0.5 becomes fd0e:5f7a:c21b::a40:5. That is deliberate. A second
# allocator would mean a second read-then-write race to get wrong under
# multiple workers, a second uniqueness constraint, and a second thing that
# can drift out of step with the first. Derivation has none of those and is
# reversible by eye once you know the trick.
MESH_NETWORK6 = os.environ.get("ZTV_MESH_NETWORK6", "fd0e:5f7a:c21b::/48")

MULTIHOP_PORT_MIN = 52000
MULTIHOP_PORT_MAX = 59999
HOP_PAIR_TTL_SECS = 24 * 3600  # rotate every 24h


def _allocate_entry_port(conn, entry_node: str) -> int:
    """Pick a free UDP port on this entry node. Linear scan."""
    used = {
        row["entry_port"]
        for row in conn.execute(
            "SELECT entry_port FROM hop_pairs WHERE entry_node = ?",
            (entry_node,),
        )
    }
    for p in range(MULTIHOP_PORT_MIN, MULTIHOP_PORT_MAX + 1):
        if p not in used:
            return p
    raise HTTPException(503, "Entry node at capacity")


# Pick the node a customer's traffic will actually use.
#
#   SELECT ... ORDER BY capacity DESC
#
# was the whole of node selection, which had two problems. `capacity` is a
# static number an operator types in, so it ranked nodes by how big they were
# declared to be, never by how much room they had left — the largest node won
# every request until it fell over. And nothing checked liveness, so a node
# that stopped answering kept being handed out indefinitely; only *ephemeral*
# nodes were ever deactivated.
_NODE_SELECT = """
    SELECT m.*,
           m.capacity - (SELECT COUNT(*) FROM device_nodes d
                          WHERE d.node_id = m.id) AS headroom,
           (m.last_heartbeat > :fresh) AS live
      FROM mesh_nodes m
     WHERE m.active = 1
       AND (m.role = :role OR m.role = 'both')
       {region_clause}
     ORDER BY live DESC, headroom DESC, m.id ASC
     LIMIT 1
"""


def _pick_node(conn, region: str | None, role: str) -> sqlite3.Row | None:
    """
    The best node for this role: live before stale, roomiest first.

    Ordering by `live DESC` rather than filtering on it is deliberate. A
    control plane that hands out nothing because every heartbeat is late has
    turned a monitoring problem into an outage; better to route into a node
    we are unsure about and let the client's handshake check catch it.

    Region is a preference, not a constraint — a customer whose chosen region
    is down gets a working tunnel somewhere else rather than an error.
    """
    args = {"role": role, "fresh": int(time.time()) - NODE_STALE_SECS}
    in_region = None
    if region:
        in_region = conn.execute(
            _NODE_SELECT.format(region_clause="AND m.region = :region"),
            {**args, "region": region},
        ).fetchone()
    anywhere = conn.execute(
        _NODE_SELECT.format(region_clause=""), args
    ).fetchone()

    # Order of preference, and why it is this way round:
    #
    #   1. a live node in the region they asked for   — what they wanted
    #   2. a live node somewhere else                 — a working tunnel
    #   3. the in-region node even though it is quiet — its heartbeat may
    #      simply be late, and the response names it either way
    #   4. anything at all
    #
    # Taking the requested region first regardless of liveness — the obvious
    # reading — routes customers into a node that stopped answering while a
    # healthy one sits idle next door. Jurisdiction still wins between two
    # live nodes, which is the case that actually matters to someone who
    # picked a country on purpose; the response always names the node it
    # chose, so a fallback is visible rather than silent.
    for candidate in (in_region, anywhere):
        if candidate is not None and candidate["live"]:
            return candidate
    return in_region or anywhere


def _allocate_hop_pair(
    conn,
    device_id: int,
    entry_region: str,
    exit_region: str,
    prior_pair_id: int | None = None,
) -> dict:
    """
    Allocate a fresh (entry, exit) pair for a device. If prior_pair_id is
    given, that row is deleted first (so the entry port becomes available
    again and capacity bookkeeping stays clean). Returns the new pair row
    plus the chosen entry/exit node rows for response construction.
    """
    # Read prior counter BEFORE deleting (otherwise the SELECT returns nothing)
    prior_rotation = 0
    if prior_pair_id is not None:
        row = conn.execute(
            "SELECT rotation_count FROM hop_pairs WHERE id = ?", (prior_pair_id,)
        ).fetchone()
        if row:
            prior_rotation = row["rotation_count"]
        conn.execute("DELETE FROM hop_pairs WHERE id = ?", (prior_pair_id,))

    entry = _pick_node(conn, entry_region, "entry")
    exit_ = _pick_node(conn, exit_region, "exit")
    if not entry or not exit_:
        raise HTTPException(503, "No nodes available for that route")
    if entry["id"] == exit_["id"]:
        raise HTTPException(400, "Entry and exit cannot be the same node")
    if not entry["public_ip"]:
        raise HTTPException(500, "Entry node missing public_ip; register it first")

    port = _allocate_entry_port(conn, entry["id"])
    now = int(time.time())

    cur = conn.execute(
        """INSERT INTO hop_pairs
             (device_id, entry_node, exit_node, entry_port,
              created_at, expires_at, rotation_count)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            device_id, entry["id"], exit_["id"], port,
            now, now + HOP_PAIR_TTL_SECS, prior_rotation + 1,
        ),
    )
    return {
        "pair_id": cur.lastrowid,
        "entry": entry,
        "exit": exit_,
        "port": port,
        "expires_at": now + HOP_PAIR_TTL_SECS,
    }


def _multihop_response(mesh_ip: str, pair: dict) -> WGRegisterResponse:
    entry, exit_, port = pair["entry"], pair["exit"], pair["port"]
    # The exit terminates the tunnel and does the masquerading, so its
    # capability is the one that decides whether v6 works. The entry only
    # forwards UDP it cannot read.
    v6 = bool(exit_["ipv6"]) if "ipv6" in exit_.keys() else False
    # On a single-VPS test deployment all three "regions" are one machine, so
    # the exit sees the client's real address and multi-hop hides nothing.
    # The client prints that privacy claim on every multi-hop connect; tell it
    # when the claim does not hold rather than letting it say so anyway.
    same_host = bool(entry["public_ip"]) and entry["public_ip"] == exit_["public_ip"]
    return WGRegisterResponse(
        interface_ip=f"{mesh_ip}/32",
        interface_ip6=f"{mesh_ip6(mesh_ip)}/128" if v6 else None,
        dns=[MESH_GATEWAY_IP] + ([mesh_gateway6()] if v6 else []),
        peers=[{
            "id": f"{entry['id']}→{exit_['id']}",
            "public_key": exit_["pubkey"],
            "endpoint": f"{entry['public_ip']}:{port}",
            "allowed_ips": ["0.0.0.0/0", "::/0"],
            "persistent_keepalive": 25,
        }],
        multihop=True,
        entry_node=entry["id"],
        exit_node=exit_["id"],
        expires_at=pair["expires_at"],
        same_host=same_host,
    )


def _assign_nodes(conn, device_id: int, node_ids) -> None:
    """
    Record exactly which nodes may see this device's pubkey, replacing any
    previous assignment. Replacing rather than adding matters: a device that
    rotates away from a node should stop being disclosed to it.
    """
    now = int(time.time())
    conn.execute("DELETE FROM device_nodes WHERE device_id = ?", (device_id,))
    for nid in dict.fromkeys(node_ids):        # de-duplicate, keep order
        conn.execute(
            """INSERT OR REPLACE INTO device_nodes (device_id, node_id, updated_at)
               VALUES (?, ?, ?)""",
            (device_id, nid, now),
        )


def _single_hop_peer(conn, region: str):
    """
    The one exit node this device will use.

    It used to return three, "so a single dead node doesn't strand the
    customer". WireGuard does not work that way. AllowedIPs is a routing
    table, not a list of alternatives: when a second peer claims 0.0.0.0/0 the
    kernel takes that prefix away from the first. Three peers each claiming
    the default route left the last one holding all of it and the other two
    inert — no failover at all, the API reporting a node the client was not
    using, and the customer's public key sitting in three nodes' peer
    manifests when only one was ever routing them. That last part quietly
    tripled what a single seized node gives up.

    Failover belongs where it can actually work: pick a live node here, and
    let the client reconnect (and land somewhere else) when the handshake
    check tells it this one is not answering.
    """
    node = _pick_node(conn, region, "exit")
    if node is None:
        # _validate_regions only proves the region has SOME active node. If
        # every one of them is entry-only there is nothing to terminate a
        # tunnel, and returning 200 with an empty peer list just moves the
        # failure into the client — where `resp.Peers[0]` panics.
        raise HTTPException(503, "No exit nodes are currently available")
    return node


def _single_hop_response(mesh_ip: str, node) -> WGRegisterResponse:
    v6 = bool(node["ipv6"]) if "ipv6" in node.keys() else False
    return WGRegisterResponse(
        interface_ip=f"{mesh_ip}/32",
        interface_ip6=f"{mesh_ip6(mesh_ip)}/128" if v6 else None,
        dns=[MESH_GATEWAY_IP] + ([mesh_gateway6()] if v6 else []),
        peers=[{
            "id": node["id"],
            "public_key": node["pubkey"],
            "endpoint": node["endpoint"],
            # ::/0 with no IPv6 address on the interface is deliberate: it
            # captures v6 into a tunnel that cannot carry it, so v6 traffic
            # fails closed instead of leaking around us on a dual-stack host.
            "allowed_ips": ["0.0.0.0/0", "::/0"],
            "persistent_keepalive": 25,
        }],
        multihop=False,
        entry_node=node["id"],
        exit_node=node["id"],
    )


@app.post("/api/v1/wg/register", response_model=WGRegisterResponse)
def wg_register(
    req: WGRegisterRequest,
    account: dict = Depends(require_active_account),
):
    """
    Register a device. Two modes:

      Single-hop: exit_region is None. Client gets up to 3 entry-node peers;
                  the chosen one is BOTH entry and exit.

      Multi-hop:  exit_region is set. Client gets ONE peer whose Endpoint is
                  the entry node's public IP at an allocated UDP port, but
                  whose PublicKey is the EXIT node's pubkey. The entry node
                  forwards that UDP port to the exit's WireGuard listener.
                  Entry cannot decrypt; exit cannot see client IP.
    """
    with db(write=True) as conn:
        # Validate the requested region(s) actually exist as active nodes.
        # Without this, a malformed client could register a device pinned to
        # a nonexistent region, which then silently fails to connect.
        _validate_regions(conn, req.region, req.exit_region)

        # Registration is idempotent on the pubkey. The client keeps its
        # keypair in state.json, so every `0trust connect` after the first
        # re-sends the same key — which used to hit the UNIQUE index on
        # devices.pubkey and surface as a 500. A device re-presenting its key
        # is asking for its current config, so hand it back and keep the
        # existing mesh IP (changing it would break the running tunnel).
        existing = conn.execute(
            "SELECT * FROM devices WHERE pubkey = ?", (req.pubkey,)
        ).fetchone()

        now = int(time.time())
        if existing:
            if existing["account_id"] != account["id"]:
                # Someone else's key. Never leak that it exists elsewhere.
                raise HTTPException(409, "Device key already in use")
            device_id = existing["id"]
            mesh_ip = existing["mesh_ip"]
            conn.execute(
                "UPDATE devices SET device_name = ?, last_seen = ? WHERE id = ?",
                (req.device_name, now, device_id),
            )
        else:
            n_devices = conn.execute(
                "SELECT COUNT(*) AS n FROM devices WHERE account_id = ?",
                (account["id"],),
            ).fetchone()["n"]
            cap = _device_cap(account["plan"] if "plan" in account.keys() else "paid")
            if n_devices >= cap:
                hint = (
                    " Upgrade to a paid plan for more."
                    if cap < MAX_DEVICES_PER_ACCOUNT else
                    f" Remove one with DELETE /api/v1/devices/{{pubkey}}."
                )
                raise HTTPException(409, f"Device limit reached ({cap}).{hint}")
            mesh_ip = allocate_mesh_ip(conn)
            cur = conn.execute(
                """INSERT INTO devices
                     (account_id, pubkey, device_name, created_at, last_seen, mesh_ip)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (account["id"], req.pubkey, req.device_name, now, now, mesh_ip),
            )
            device_id = cur.lastrowid

        # ------------- MULTI-HOP -------------
        if req.exit_region:
            prior = conn.execute(
                "SELECT id FROM hop_pairs WHERE device_id = ?", (device_id,)
            ).fetchone()
            pair = _allocate_hop_pair(
                conn, device_id, req.region, req.exit_region,
                prior_pair_id=prior["id"] if prior else None,
            )
            # Only the exit terminates the tunnel; the entry just DNATs UDP
            # and reads /wg/forwards, so it never needs the pubkey.
            _assign_nodes(conn, device_id, [pair["exit"]["id"]])
            return _multihop_response(mesh_ip, pair)

        # ------------- SINGLE-HOP (default) -------------
        # Re-registering single-hop retires any multi-hop pair, otherwise the
        # entry node keeps a DNAT rule for a session the client abandoned.
        conn.execute("DELETE FROM hop_pairs WHERE device_id = ?", (device_id,))
        node = _single_hop_peer(conn, req.region)
        # Only the node actually carrying this device gets its key.
        _assign_nodes(conn, device_id, [node["id"]])
        return _single_hop_response(mesh_ip, node)


class DeviceInfo(BaseModel):
    pubkey: str
    device_name: str
    mesh_ip: str
    created_at: int
    last_seen: int
    multihop: bool = False
    entry_node: str | None = None
    exit_node: str | None = None


@app.get("/api/v1/devices", response_model=list[DeviceInfo])
def list_devices(account: dict = Depends(require_account)):
    """
    The devices on this account. Needed to make the device cap survivable:
    without a way to see what is registered, a customer who hits the limit
    has no way to work out which slot to free.
    """
    with db() as conn:
        rows = conn.execute(
            """SELECT d.pubkey, d.device_name, d.mesh_ip, d.created_at, d.last_seen,
                      hp.entry_node, hp.exit_node
               FROM devices d
               LEFT JOIN hop_pairs hp ON hp.device_id = d.id
               WHERE d.account_id = ?
               ORDER BY d.created_at""",
            (account["id"],),
        ).fetchall()
    return [
        DeviceInfo(
            pubkey=r["pubkey"],
            device_name=r["device_name"] or "",
            mesh_ip=r["mesh_ip"],
            created_at=r["created_at"],
            last_seen=r["last_seen"],
            multihop=r["entry_node"] is not None,
            entry_node=r["entry_node"],
            exit_node=r["exit_node"],
        )
        for r in rows
    ]


@app.delete("/api/v1/devices/{pubkey:path}")
def delete_device(pubkey: str, account: dict = Depends(require_account)):
    """
    Deregister a device and release its mesh IP and any hop pair.

    Note the {pubkey:path} converter — WireGuard public keys are standard
    base64 and routinely contain '/', which a normal path segment would split.
    """
    with db(write=True) as conn:
        row = conn.execute(
            "SELECT id FROM devices WHERE pubkey = ? AND account_id = ?",
            (pubkey, account["id"]),
        ).fetchone()
        if not row:
            raise HTTPException(404, "Device not found")
        # hop_pairs has ON DELETE CASCADE from devices, but be explicit so the
        # entry port is released even on a DB created before that was added.
        conn.execute("DELETE FROM hop_pairs WHERE device_id = ?", (row["id"],))
        conn.execute("DELETE FROM devices WHERE id = ?", (row["id"],))
    return {"ok": True, "deleted": pubkey}


class WGRotateRequest(BaseModel):
    pubkey: str = Field(..., min_length=44, max_length=44)
    region: str = Field("zur")
    exit_region: str | None = None


@app.post("/api/v1/wg/rotate", response_model=WGRegisterResponse)
def wg_rotate(
    req: WGRotateRequest,
    account: dict = Depends(require_active_account),
):
    """
    Rotate this device's hop-pair atomically. The old pair is deleted in the
    same transaction the new one is allocated in, so there's no window where
    the device has two pairs (and no window where it has zero, modulo the
    brief tunnel flap as the client reloads its wg config).

    Use cases:
      - Cron-driven daily rotation from the client
      - Manual rotation if you suspect a node is compromised
      - Re-routing through a different entry/exit region

    For single-hop devices (no existing hop_pair), this is a no-op that
    returns the current single-hop config.
    """
    with db(write=True) as conn:
        device = conn.execute(
            "SELECT * FROM devices WHERE pubkey = ? AND account_id = ?",
            (req.pubkey, account["id"]),
        ).fetchone()
        if not device:
            raise HTTPException(404, "Device not registered")

        # Same region validation as wg_register — see that handler for rationale
        _validate_regions(conn, req.region, req.exit_region)

        existing = conn.execute(
            "SELECT * FROM hop_pairs WHERE device_id = ?",
            (device["id"],),
        ).fetchone()

        # If they're rotating into multi-hop OR refreshing an existing one
        if req.exit_region or existing:
            exit_region = req.exit_region
            if exit_region is None and existing:
                # Refresh the existing pair's exit region
                exit_node = conn.execute(
                    "SELECT region FROM mesh_nodes WHERE id = ?",
                    (existing["exit_node"],),
                ).fetchone()
                exit_region = exit_node["region"] if exit_node else "buc"

            pair = _allocate_hop_pair(
                conn,
                device_id=device["id"],
                entry_region=req.region,
                exit_region=exit_region,
                prior_pair_id=existing["id"] if existing else None,
            )
            _assign_nodes(conn, device["id"], [pair["exit"]["id"]])
            return _multihop_response(device["mesh_ip"], pair)

        # No prior pair and no exit_region: fall back to single-hop.
        # Shares _single_hop_peer with register so the "no exit node" case
        # 503s here too instead of returning an empty peer list.
        conn.execute(
            "UPDATE devices SET last_seen = ? WHERE id = ?",
            (int(time.time()), device["id"]),
        )
        node = _single_hop_peer(conn, req.region)
        _assign_nodes(conn, device["id"], [node["id"]])
        return _single_hop_response(device["mesh_ip"], node)


# ----------------------------------------------------------------------------
# NODE PROVISIONING (ephemeral RAM-only nodes)
# ----------------------------------------------------------------------------

class NodeProvisionRequest(BaseModel):
    pubkey: str
    public_ip: str
    # Shape-constrained, not enumerated: the set of live regions comes from
    # mesh_nodes, so a future region code has to be accepted — but a node
    # names its own region when it registers, and that string is rendered on
    # the PUBLIC status page. Unbounded free text there is somebody else's
    # markup on our page, and a typo is a node nothing can ever route to.
    region: str = Field(..., pattern=r"^[a-z]{2,8}$")
    role: Literal["entry", "exit", "both"] = "both"
    ipv6: bool = False
    # The port the node's WireGuard interface actually listens on. This used
    # to be assumed to be 51820 and written into the endpoint regardless, so a
    # node brought up on any other port was registered at an address nothing
    # was listening on: handshakes from every client it was handed to timed
    # out, and the control plane went on believing the node was fine because
    # meshd's heartbeat is a separate outbound HTTPS call that kept working.
    wg_port: int = 51820


class NodeProvisionResponse(BaseModel):
    node_id: str
    node_psk: str
    # True when this call replaced an existing registration rather than
    # creating one — a node that rebooted and came back. The installer prints
    # a different line for each, because "rejoined as zur-01" and "joined as
    # zur-04" mean different things to an operator watching a mesh.
    rejoined: bool = False


def _next_node_id(conn, region: str) -> str:
    """Pick the next available NN suffix for this region."""
    rows = conn.execute(
        "SELECT id FROM mesh_nodes WHERE id LIKE ?", (f"{region}-%",),
    ).fetchall()
    used = set()
    for r in rows:
        suffix = r["id"][len(region) + 1:]
        if suffix.isdigit():
            used.add(int(suffix))
    n = 1
    while n in used:
        n += 1
    return f"{region}-{n:02d}"


@app.post("/api/v1/node/provision", response_model=NodeProvisionResponse)
def node_provision(req: NodeProvisionRequest, request: Request):
    """
    One-shot endpoint called by an ephemeral node's cloud-init on first boot.
    Validates a single-use provisioning token (passed in X-Provision-Token),
    allocates a node_id, mints a per-node PSK, and inserts the row.
    """
    token = request.headers.get("X-Provision-Token", "")
    if not token:
        raise HTTPException(401, "Missing X-Provision-Token")

    if req.role not in ("entry", "exit", "both"):
        raise HTTPException(400, "role must be entry|exit|both")
    if not 1 <= req.wg_port <= 65535:
        raise HTTPException(400, "wg_port out of range")

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time())

    # write=True: _next_node_id reads the existing ids and then inserts one,
    # and burning the token has to land in the same transaction as the insert
    # or a crash between them leaves a spent token with no node.
    with db(write=True) as conn:
        row = conn.execute(
            "SELECT * FROM provision_tokens WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if not row:
            raise HTTPException(401, "Invalid provisioning token")
        if row["revoked_at"]:
            raise HTTPException(401, "Token revoked")
        if row["expires_at"] < now:
            raise HTTPException(401, "Token expired")
        if row["region"] != req.region or row["role"] != req.role:
            raise HTTPException(400, "Token / request mismatch")

        max_uses = row["max_uses"] or 1
        # Rows written before used_count existed record a spent one-shot token
        # as used_at alone, so count that as the one use it was.
        used = max(row["used_count"] or 0, 1 if row["used_at"] else 0)

        # An enrolment token pins itself to the first address that presents
        # it. That is what makes it safe to leave one on a node's disk: the
        # copy is worthless anywhere except the box it is already on, and the
        # attacker who has that box has the box.
        if row["bind_ip"] and row["bind_ip"] != req.public_ip:
            raise HTTPException(401, "Token is bound to another address")

        # A node that rebooted re-registers under the id it already had, with
        # the fresh key it generated on boot. Allocating a new id each time
        # would leave the mesh accumulating dead rows for one box, and the
        # operator reading a node count that means nothing.
        prior = None
        if row["used_node_id"]:
            prior = conn.execute(
                "SELECT * FROM mesh_nodes WHERE id = ?", (row["used_node_id"],),
            ).fetchone()
        rejoin = prior is not None and prior["public_ip"] == req.public_ip

        if not rejoin and used >= max_uses:
            raise HTTPException(401, "Token already used")

        node_psk = secrets.token_hex(32)
        psk_hash = hashlib.sha256(node_psk.encode()).hexdigest()
        endpoint = f"{req.public_ip}:{req.wg_port}"

        if rejoin:
            node_id = prior["id"]
            conn.execute(
                """UPDATE mesh_nodes
                      SET pubkey = ?, endpoint = ?, role = ?, ipv6 = ?,
                          psk_hash = ?, last_heartbeat = ?, active = 1
                    WHERE id = ?""",
                (req.pubkey, endpoint, req.role, 1 if req.ipv6 else 0,
                 psk_hash, now, node_id),
            )
            # Its old peers pointed at a key that no longer exists. Clearing
            # the assignments makes the next /wg/register place those devices
            # somewhere live instead of onto a node that cannot answer them.
            conn.execute("DELETE FROM device_nodes WHERE node_id = ?", (node_id,))
            conn.execute(
                "DELETE FROM hop_pairs WHERE entry_node = ? OR exit_node = ?",
                (node_id, node_id),
            )
        else:
            node_id = _next_node_id(conn, req.region)
            conn.execute(
                """INSERT INTO mesh_nodes
                     (id, hostname, pubkey, endpoint, region, role, public_ip,
                      ephemeral, psk_hash, last_heartbeat, active, ipv6)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 1, ?)""",
                (
                    node_id, f"{node_id}.0trust",
                    req.pubkey, endpoint,
                    req.region, req.role, req.public_ip,
                    psk_hash, now, 1 if req.ipv6 else 0,
                ),
            )

        conn.execute(
            """UPDATE provision_tokens
                  SET used_at = ?, used_node_id = ?, used_count = ?,
                      bind_ip = COALESCE(bind_ip, ?)
                WHERE token_hash = ?""",
            (now, node_id, used if rejoin else used + 1,
             req.public_ip if max_uses > 1 else None, token_hash),
        )

        ops_alerts.record(
            conn, "node.rejoin" if rejoin else "node.provision", "info",
            node_id,
            f"{req.region}/{req.role} at {req.public_ip}:{req.wg_port}"
            + (" (rebooted)" if rejoin else ""))

    return NodeProvisionResponse(node_id=node_id, node_psk=node_psk,
                                 rejoined=rejoin)


class NodeHeartbeatRequest(BaseModel):
    node_id: str | None = None
    # Whether this node can actually route IPv6 to the internet. Reported by
    # the node rather than configured centrally, because it is a property of
    # the VPS the operator bought and can change under them — a provider
    # enabling or withdrawing v6 should not need a database edit.
    ipv6: bool | None = None


@app.post("/api/v1/node/heartbeat")
def node_heartbeat(
    request: Request,
    body: NodeHeartbeatRequest | None = None,
    _: Optional[str] = Depends(require_node),
):
    """
    Ephemeral nodes call this every ~60s. If a node hasn't checked in for
    5 minutes, the sweeper marks it inactive and customers stop being
    routed through it on the next /wg/register.
    """
    # Identify the node by matching the PSK against psk_hash.
    psk = request.headers.get("X-Node-Psk", "")
    psk_hash = hashlib.sha256(psk.encode()).hexdigest()
    node_id_hint = body.node_id if body else None
    v6 = body.ipv6 if body else None
    with db(write=True) as conn:
        # Note who was out of rotation before this beat, so coming back can be
        # reported the moment it happens rather than whenever the sweeper next
        # runs — up to an hour later, by which time the operator has already
        # been staring at a red dashboard.
        was_down = {r["id"] for r in conn.execute(
            "SELECT id FROM mesh_nodes WHERE active = 0")}
        cur = conn.execute(
            # active = 1 as well: the sweeper deactivates a node whose
            # heartbeat went stale, and without this a node that recovers
            # stays out of rotation until someone notices by hand.
            "UPDATE mesh_nodes SET last_heartbeat = ?, active = 1 WHERE psk_hash = ?",
            (int(time.time()), psk_hash),
        )
        if cur.rowcount == 0:
            # A node authenticating with the shared NODE_API_PSK has no
            # psk_hash row to match, so this UPDATE used to hit nothing and
            # still answer {"ok": true} — a node could "heartbeat" forever
            # while the control plane recorded nothing. Let it name itself.
            node_id = (node_id_hint or "").strip()
            if not node_id:
                raise HTTPException(
                    400,
                    "Heartbeat could not be attributed to a node. Send a "
                    "per-node PSK, or pass node_id when using the shared PSK.",
                )
            cur = conn.execute(
                "UPDATE mesh_nodes SET last_heartbeat = ?, active = 1 WHERE id = ?",
                (int(time.time()), node_id),
            )
            if cur.rowcount == 0:
                raise HTTPException(404, "Unknown node")

        # Record v6 capability alongside the beat. Whichever branch above
        # matched has already identified the node, so reuse that.
        if v6 is not None:
            if psk_hash:
                conn.execute(
                    "UPDATE mesh_nodes SET ipv6 = ? WHERE psk_hash = ?",
                    (1 if v6 else 0, psk_hash))
            if node_id_hint:
                conn.execute(
                    "UPDATE mesh_nodes SET ipv6 = ? WHERE id = ?",
                    (1 if v6 else 0, node_id_hint.strip()))

        if was_down:
            for row in conn.execute(
                    "SELECT id FROM mesh_nodes WHERE active = 1 AND id IN "
                    "(%s)" % ",".join("?" * len(was_down)), tuple(was_down)):
                ops_alerts.record(conn, "node.up", "info", row["id"],
                                  "heartbeating again — back in rotation")
    return {"ok": True}


@app.get("/api/v1/wg/peers")
def list_peers(node_id: Optional[str] = None,
               caller: Optional[str] = Depends(require_node)):
    """
    Mesh nodes call this periodically to sync their WireGuard peer list.

    Scoped to the calling node. This used to return every active device to
    anything holding a node credential, which made one node's PSK enough to
    enumerate the whole customer base — hard to square with the claim that a
    seized node reveals nothing operational. A node only needs the devices
    routed through it, and that is now all it can see.

    The node must identify itself: implicitly by presenting its own PSK, or
    explicitly via node_id when using the shared NODE_API_PSK.
    """
    node = caller or (node_id or "").strip()
    if not node:
        raise HTTPException(
            400,
            "Identify the node: send a per-node PSK, or pass node_id when "
            "using the shared PSK.",
        )
    if caller is not None and node_id and node_id != caller:
        raise HTTPException(403, "A node may only read its own peers")

    with db() as conn:
        rows = conn.execute(
            """SELECT d.pubkey, d.mesh_ip
               FROM devices d
               JOIN accounts a     ON a.id = d.account_id
               JOIN device_nodes n ON n.device_id = d.id
               WHERE n.node_id = ?
                 AND a.status = 'active' AND a.expires_at > ?""",
            (node, int(time.time())),
        ).fetchall()
    return {
        # Both families, always. A node without v6 egress simply never has
        # traffic arrive on the v6 half, and listing it keeps the manifest the
        # same shape everywhere rather than making a node's peer list depend
        # on its own capability.
        "peers": [{"public_key": r["pubkey"],
                   "allowed_ips": f"{r['mesh_ip']}/32, {mesh_ip6(r['mesh_ip'])}/128"}
                  for r in rows],
        "generated_at": int(time.time()),
    }


@app.get("/api/v1/wg/forwards")
def list_forwards(node_id: str, caller: Optional[str] = Depends(require_node)):
    """
    Multi-hop DNAT rules for an entry node.

    Returns: [{ entry_port, exit_endpoint }, ...]
    The entry node uses these to set up nftables rules:
        udp dport <entry_port> dnat to <exit_endpoint>

    Only active subscriptions are returned, so expired devices' forwards
    fall out of the rule set on the next sync.
    """
    # A node identified by its own PSK may only read its own DNAT table.
    # Otherwise any one node could enumerate every other entry node's live
    # sessions and their exit endpoints.
    if caller is not None and caller != node_id:
        raise HTTPException(403, "A node may only read its own forwards")

    with db() as conn:
        rows = conn.execute(
            """SELECT hp.entry_port, mn.endpoint AS exit_endpoint
               FROM hop_pairs hp
               JOIN devices d        ON d.id          = hp.device_id
               JOIN accounts a       ON a.id          = d.account_id
               JOIN mesh_nodes mn    ON mn.id         = hp.exit_node
               WHERE hp.entry_node = ?
                 AND hp.expires_at > ?
                 AND a.status      = 'active'
                 AND a.expires_at  > ?
                 AND mn.active     = 1""",
            (node_id, int(time.time()), int(time.time())),
        ).fetchall()
    return {
        "forwards": [
            {"entry_port": r["entry_port"], "exit_endpoint": r["exit_endpoint"]}
            for r in rows
        ],
        "generated_at": int(time.time()),
    }


# ----------------------------------------------------------------------------
# PUBLIC STATUS PAGE
# ----------------------------------------------------------------------------
# Sanitized health view for /status. Deliberately coarse-grained — we
# expose per-region availability counts (so customers can see if their region
# is healthy) but never expose specific node IDs, IPs, capacity numbers,
# customer counts, or anything else an adversary could use for targeting.
#
# Cache TTL is short (60s) so the status page doesn't lie about an outage,
# but long enough that a /status flash crowd doesn't pound the DB.

_STATUS_CACHE: dict = {"ts": 0, "data": None}
_STATUS_CACHE_TTL = 60  # seconds


@app.get("/api/v1/status/public")
def public_status() -> dict:
    """Public, sanitized service status. Cached 60s."""
    now = int(time.time())
    if _STATUS_CACHE["data"] and (now - _STATUS_CACHE["ts"]) < _STATUS_CACHE_TTL:
        return _STATUS_CACHE["data"]

    with db() as conn:
        # Per-region health: count active nodes that heartbeat'd recently
        heartbeat_threshold = now - 300  # 5 min
        rows = conn.execute(
            """SELECT region,
                      SUM(CASE WHEN role IN ('entry','both') AND active=1
                               AND (ephemeral=0 OR last_heartbeat > ?)
                               THEN 1 ELSE 0 END) AS entries,
                      SUM(CASE WHEN role IN ('exit','both') AND active=1
                               AND (ephemeral=0 OR last_heartbeat > ?)
                               THEN 1 ELSE 0 END) AS exits
               FROM mesh_nodes
               GROUP BY region
               ORDER BY region""",
            (heartbeat_threshold, heartbeat_threshold),
        ).fetchall()

        regions = []
        any_unhealthy = False
        for r in rows:
            # Status bucket — we never expose raw counts, only a 3-state health.
            #
            # The bar is "can this region carry traffic", not "does it have a
            # spare". Three nodes, one per region, is the locked production
            # topology, so a redundancy floor of 2 marked every region degraded
            # forever — a status page that always cries wolf is worse than none,
            # and for a product selling verifiable honesty it reads as broken.
            entries = r["entries"]
            exits = r["exits"]
            if entries == 0 and exits == 0:
                state = "down"
                any_unhealthy = True
            elif entries == 0 or exits == 0:
                # Half a region: can be an entry but not an exit, or vice
                # versa. Multi-hop may still route through it; single-hop
                # customers here cannot terminate a tunnel.
                state = "degraded"
                any_unhealthy = True
            else:
                state = "operational"
            regions.append({"region": r["region"], "state": state})

    # Overall service state. Don't check BTCPay here — its outage doesn't
    # break service for already-paying customers, only signup.
    overall = "operational" if regions and not any_unhealthy else \
              ("degraded" if regions else "down")

    data = {
        "service": overall,
        "regions": regions,
        "as_of": now,
    }
    _STATUS_CACHE["ts"] = now
    _STATUS_CACHE["data"] = data
    return data


# ----------------------------------------------------------------------------
# ENTRY
# ----------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    init_db()
    uvicorn.run(app, host="127.0.0.1", port=8080)
