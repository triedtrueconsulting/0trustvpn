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
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

# ============================================================================
# CONFIG
# ============================================================================

DB_PATH = os.environ.get("ZTV_DB_PATH", "/var/lib/0trust/0trust.db")
BTCPAY_URL = os.environ.get("BTCPAY_URL", "https://btcpay.example.com")
BTCPAY_STORE_ID = os.environ.get("BTCPAY_STORE_ID", "")
BTCPAY_API_KEY = os.environ.get("BTCPAY_API_KEY", "")
BTCPAY_WEBHOOK_SECRET = os.environ.get("BTCPAY_WEBHOOK_SECRET", "")
MESH_NETWORK = os.environ.get("MESH_NETWORK", "10.64.0.0/10")  # ~4M addresses
NODE_API_PSK = os.environ.get("NODE_API_PSK", "")  # mesh nodes auth with this
DB_TIMEOUT_SECS = float(os.environ.get("ZTV_DB_TIMEOUT", "30"))
MAX_DEVICES_PER_ACCOUNT = int(os.environ.get("ZTV_MAX_DEVICES", "8"))

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
  id              TEXT PRIMARY KEY,            -- BTCPay invoice ID
  account_id      INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  months          INTEGER NOT NULL,
  amount_usd      REAL NOT NULL,
  currency        TEXT NOT NULL,               -- BTC | XMR | ETH | LTC
  status          TEXT NOT NULL,               -- New | Processing | Settled | Expired | Invalid
  created_at      INTEGER NOT NULL,
  settled_at      INTEGER,
  payment_address TEXT,
  amount_crypto   TEXT
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
  last_heartbeat  INTEGER NOT NULL DEFAULT 0
);

-- One-time provisioning tokens for ephemeral RAM nodes. Each row authorizes
-- exactly one node registration. Burned after use.
CREATE TABLE IF NOT EXISTS provision_tokens (
  token_hash    TEXT PRIMARY KEY,             -- SHA256(plain_token)
  region        TEXT NOT NULL,                -- restricts the token to a region
  role          TEXT NOT NULL DEFAULT 'both', -- entry | exit | both
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  used_at       INTEGER,                      -- NULL = unused
  used_node_id  TEXT
);

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


def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(SCHEMA)


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

from btcpay import BTCPayClient, BTCPayError

_btcpay: BTCPayClient | None = None


def btcpay() -> BTCPayClient:
    """Lazy singleton so missing env vars don't crash module import."""
    global _btcpay
    if _btcpay is None:
        _btcpay = BTCPayClient(
            base_url=BTCPAY_URL,
            store_id=BTCPAY_STORE_ID,
            api_key=BTCPAY_API_KEY,
        )
    return _btcpay


def btcpay_create_invoice(account_id: int, months: int, amount_usd: float) -> dict:
    try:
        return btcpay().create_invoice(
            amount_usd=amount_usd,
            account_id=account_id,
            months=months,
            redirect_url="https://0trustvpn.com/welcome",
        )
    except BTCPayError as e:
        # Don't leak BTCPay internals to clients
        raise HTTPException(502, f"Payment processor unavailable") from e


def btcpay_verify_webhook(payload: bytes, signature: str) -> bool:
    """BTCPay signs webhooks with HMAC-SHA256 using the webhook secret."""
    if not BTCPAY_WEBHOOK_SECRET:
        return False
    expected = "sha256=" + hmac.new(
        BTCPAY_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature or "")


# ============================================================================
# SCHEMAS
# ============================================================================

class AccountCreateRequest(BaseModel):
    months: int = Field(..., description="Subscription duration in months")

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
    dns: list[str]
    peers: list[dict]
    multihop: bool = False
    entry_node: str | None = None
    exit_node: str | None = None
    expires_at: int | None = None   # epoch secs; multi-hop only


# ============================================================================
# AUTH DEPENDENCY
# ============================================================================

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
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Account-Token"],
)


@app.on_event("startup")
def startup():
    init_db()


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "ts": int(time.time())}


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
        invoice = btcpay_create_invoice(account_id, req.months, amount)
    except BaseException:
        with db(write=True) as conn:
            conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        raise

    with db(write=True) as conn:
        conn.execute(
            """INSERT INTO invoices
                 (id, account_id, months, amount_usd, currency, status, created_at)
               VALUES (?, ?, ?, ?, 'USD', ?, ?)""",
            (invoice["id"], account_id, req.months, amount, invoice["status"], now),
        )

    return AccountCreateResponse(
        token=token,
        invoice_id=invoice["id"],
        checkout_url=invoice["checkoutLink"],
        amount_usd=amount,
    )


@app.get("/api/v1/account/status", response_model=AccountStatusResponse)
def account_status(account: dict = Depends(require_account)):
    now = int(time.time())
    expires = account["expires_at"]
    with db() as conn:
        device_count = conn.execute(
            "SELECT COUNT(*) AS n FROM devices WHERE account_id = ?",
            (account["id"],),
        ).fetchone()["n"]
    return AccountStatusResponse(
        status=account["status"],
        expires_at=expires or None,
        days_remaining=max(0, (expires - now) // 86400) if expires else None,
        device_count=device_count,
    )


@app.post("/api/v1/account/topup", response_model=AccountCreateResponse)
def topup(req: AccountCreateRequest, account: dict = Depends(require_account)):
    """Open another invoice for an existing account. Extends on payment."""
    amount = PRICING[req.months]
    invoice = btcpay_create_invoice(account["id"], req.months, amount)
    now = int(time.time())

    with db(write=True) as conn:
        conn.execute(
            """INSERT INTO invoices
                 (id, account_id, months, amount_usd, currency, status, created_at)
               VALUES (?, ?, ?, ?, 'USD', ?, ?)""",
            (invoice["id"], account["id"], req.months, amount, invoice["status"], now),
        )

    return AccountCreateResponse(
        # No new token is minted on a top-up; the caller already holds theirs
        # and we never store it in a form we could echo back.
        token="",
        invoice_id=invoice["id"],
        checkout_url=invoice["checkoutLink"],
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
            "SELECT id FROM invoices WHERE id = ?", (invoice_id,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Invoice not found")

    try:
        methods = btcpay().get_payment_methods(invoice_id)
    except BTCPayError:
        raise HTTPException(502, "Payment processor unavailable")

    # Reshape to what the frontend needs — drop BTCPay-internal fields
    return {
        "methods": [
            {
                "currency": m.get("paymentMethod", "").replace("-LightningNetwork", "-LN"),
                "address": m.get("destination"),
                "amount": m.get("amount"),
                "rate": m.get("rate"),
                "uri": m.get("paymentLink"),
            }
            for m in methods
            if m.get("destination")
        ]
    }


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

    # If the webhook already settled this, return immediately
    if row["status"] in ("Settled", "Expired", "Invalid"):
        return {"status": row["status"], "settled_at": row["settled_at"]}

    # Otherwise check BTCPay live (cheap call; rate-limited at nginx)
    try:
        live = btcpay().get_invoice(invoice_id)
        return {"status": live.get("status", row["status"]), "settled_at": None}
    except BTCPayError:
        return {"status": row["status"], "settled_at": None}


# ----------------------------------------------------------------------------
# PAYMENT WEBHOOK
# ----------------------------------------------------------------------------

@app.post("/api/v1/payment/webhook")
async def btcpay_webhook(request: Request):
    """
    BTCPay calls this when invoice state changes. On Settled, we extend the
    account's expiry by `months` and mark it active.
    """
    body = await request.body()
    signature = request.headers.get("BTCPay-Sig", "")
    if not btcpay_verify_webhook(body, signature):
        raise HTTPException(401, "Invalid webhook signature")

    event = json.loads(body)
    invoice_id = event.get("invoiceId")
    event_type = event.get("type")  # InvoiceSettled, InvoiceExpired, ...

    if not invoice_id or not event_type:
        return {"ok": False}

    with db(write=True) as conn:
        inv = conn.execute(
            "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
        ).fetchone()
        if not inv:
            return {"ok": False, "reason": "unknown invoice"}

        if event_type == "InvoiceSettled":
            # Credit each invoice EXACTLY once. BTCPay retries a delivery it
            # didn't get a 2xx for, and re-sends on redelivery, so this handler
            # sees duplicates in normal operation — and anyone who captured one
            # signed delivery could otherwise replay it for unlimited free
            # months, since the HMAC stays valid forever. The settled_at
            # marker, not the signature, is what makes crediting single-shot.
            if inv["status"] == "Settled":
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
                """UPDATE invoices SET status = 'Settled', settled_at = ?
                   WHERE id = ? AND status != 'Settled'""",
                (now, invoice_id),
            )
            if cur.rowcount == 0:
                return {"ok": True, "duplicate": True}
            conn.execute(
                """UPDATE accounts
                   SET status = 'active', expires_at = ?
                   WHERE id = ?""",
                (new_expiry, acc["id"]),
            )
        elif event_type in ("InvoiceExpired", "InvoiceInvalid"):
            # Never walk a settled invoice backwards — BTCPay can emit an
            # Expired event for an invoice that settled late.
            conn.execute(
                "UPDATE invoices SET status = ? WHERE id = ? AND status != 'Settled'",
                (event_type.replace("Invoice", ""), invoice_id),
            )

    return {"ok": True}


# ----------------------------------------------------------------------------
# WIREGUARD
# ----------------------------------------------------------------------------

# Multi-hop entry-port allocation range. 8000 slots per entry node is plenty —
# at 1 slot per active device, that's 8000 simultaneous sessions per entry.
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


def _pick_node(conn, region: str, role: str) -> sqlite3.Row | None:
    """Pick the best (active, in-region, role-compatible) mesh node."""
    return conn.execute(
        """SELECT * FROM mesh_nodes
           WHERE active = 1
             AND region = ?
             AND (role = ? OR role = 'both')
           ORDER BY capacity DESC
           LIMIT 1""",
        (region, role),
    ).fetchone() or conn.execute(
        # fallback: any active node with compatible role
        """SELECT * FROM mesh_nodes
           WHERE active = 1
             AND (role = ? OR role = 'both')
           ORDER BY capacity DESC
           LIMIT 1""",
        (role,),
    ).fetchone()


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
    return WGRegisterResponse(
        interface_ip=f"{mesh_ip}/32",
        dns=["10.64.0.1"],
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
    )


def _single_hop_peers(conn, region: str) -> list:
    """
    Up to 3 exit-capable peers, preferring the requested region and falling
    back to any region so a single dead node doesn't strand the customer.
    """
    peers = conn.execute(
        """SELECT id, pubkey, endpoint, region
           FROM mesh_nodes
           WHERE active = 1
             AND region = ?
             AND (role = 'exit' OR role = 'both')
           ORDER BY capacity DESC
           LIMIT 3""",
        (region,),
    ).fetchall()
    if not peers:
        peers = conn.execute(
            """SELECT id, pubkey, endpoint, region
               FROM mesh_nodes
               WHERE active = 1 AND (role = 'exit' OR role = 'both')
               ORDER BY capacity DESC
               LIMIT 3"""
        ).fetchall()
    if not peers:
        # _validate_regions only proves the region has SOME active node. If
        # every one of them is entry-only there is nothing to terminate a
        # tunnel, and returning 200 with an empty peer list just moves the
        # failure into the client — where `resp.Peers[0]` panics.
        raise HTTPException(503, "No exit nodes are currently available")
    return peers


def _single_hop_response(mesh_ip: str, peers: list) -> WGRegisterResponse:
    return WGRegisterResponse(
        interface_ip=f"{mesh_ip}/32",
        dns=["10.64.0.1"],
        peers=[
            {
                "id": p["id"],
                "public_key": p["pubkey"],
                "endpoint": p["endpoint"],
                "allowed_ips": ["0.0.0.0/0", "::/0"],
                "persistent_keepalive": 25,
            }
            for p in peers
        ],
        multihop=False,
        entry_node=peers[0]["id"],
        exit_node=peers[0]["id"],
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
            if n_devices >= MAX_DEVICES_PER_ACCOUNT:
                raise HTTPException(
                    409,
                    f"Device limit reached ({MAX_DEVICES_PER_ACCOUNT}). "
                    f"Remove one with DELETE /api/v1/devices/{{pubkey}}.",
                )
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
            return _multihop_response(mesh_ip, pair)

        # ------------- SINGLE-HOP (default) -------------
        # Re-registering single-hop retires any multi-hop pair, otherwise the
        # entry node keeps a DNAT rule for a session the client abandoned.
        conn.execute("DELETE FROM hop_pairs WHERE device_id = ?", (device_id,))
        return _single_hop_response(mesh_ip, _single_hop_peers(conn, req.region))


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
            return _multihop_response(device["mesh_ip"], pair)

        # No prior pair and no exit_region: fall back to single-hop.
        # Shares _single_hop_peers with register so the "no exit node" case
        # 503s here too instead of returning an empty peer list.
        conn.execute(
            "UPDATE devices SET last_seen = ? WHERE id = ?",
            (int(time.time()), device["id"]),
        )
        return _single_hop_response(
            device["mesh_ip"], _single_hop_peers(conn, req.region)
        )


# ----------------------------------------------------------------------------
# NODE PROVISIONING (ephemeral RAM-only nodes)
# ----------------------------------------------------------------------------

class NodeProvisionRequest(BaseModel):
    pubkey: str
    public_ip: str
    region: str
    role: str = "both"


class NodeProvisionResponse(BaseModel):
    node_id: str
    node_psk: str


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
        if row["used_at"]:
            raise HTTPException(401, "Token already used")
        if row["expires_at"] < now:
            raise HTTPException(401, "Token expired")
        if row["region"] != req.region or row["role"] != req.role:
            raise HTTPException(400, "Token / request mismatch")

        node_id = _next_node_id(conn, req.region)
        node_psk = secrets.token_hex(32)
        psk_hash = hashlib.sha256(node_psk.encode()).hexdigest()

        conn.execute(
            """INSERT INTO mesh_nodes
                 (id, hostname, pubkey, endpoint, region, role, public_ip,
                  ephemeral, psk_hash, last_heartbeat, active)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 1)""",
            (
                node_id, f"{node_id}.0trust",
                req.pubkey, f"{req.public_ip}:51820",
                req.region, req.role, req.public_ip,
                psk_hash, now,
            ),
        )

        conn.execute(
            "UPDATE provision_tokens SET used_at=?, used_node_id=? WHERE token_hash=?",
            (now, node_id, token_hash),
        )

    return NodeProvisionResponse(node_id=node_id, node_psk=node_psk)


class NodeHeartbeatRequest(BaseModel):
    node_id: str | None = None


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
    with db(write=True) as conn:
        cur = conn.execute(
            "UPDATE mesh_nodes SET last_heartbeat = ? WHERE psk_hash = ?",
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
                "UPDATE mesh_nodes SET last_heartbeat = ? WHERE id = ?",
                (int(time.time()), node_id),
            )
            if cur.rowcount == 0:
                raise HTTPException(404, "Unknown node")
    return {"ok": True}


@app.get("/api/v1/wg/peers")
def list_peers(_: Optional[str] = Depends(require_node)):
    """
    Mesh nodes call this periodically to sync their peer list.
    Returns all active devices so the node can authorize their pubkeys.
    """
    with db() as conn:
        rows = conn.execute(
            """SELECT d.pubkey, d.mesh_ip
               FROM devices d
               JOIN accounts a ON a.id = d.account_id
               WHERE a.status = 'active' AND a.expires_at > ?""",
            (int(time.time()),),
        ).fetchall()
    return {
        "peers": [{"public_key": r["pubkey"], "allowed_ips": f"{r['mesh_ip']}/32"} for r in rows],
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
