"""
Admin backend for the 0trust dashboard.

Everything an operator needs to run the service and the business behind it:
accounts, devices, mesh nodes, payments and settings — plus an audit trail of
who did what.

SECURITY POSTURE
----------------
This surface can ban customers, extend subscriptions and change where money
lands, so it is treated as a different class of thing from the customer API:

  * Separate credentials. A username and a password, not a bearer token, and
    the password is stored as salted scrypt — slow on purpose.
  * Sessions expire, and are stored as hashes. A stolen database gives an
    attacker no usable session cookie.
  * Cookies are HttpOnly, SameSite=Strict and (behind TLS) Secure, and every
    state-changing call needs a matching CSRF header. A dashboard reachable
    from a browser is reachable from a malicious page in the same browser.
  * Failed logins are rate limited per username and per address, so the
    password cannot be ground down over a weekend.
  * Every mutation lands in admin_audit before the response is returned.

nginx should also keep /api/v1/admin and /admin off the public internet where
that is practical — see docs/ADMIN.md. Defence in depth: none of the above
stops being necessary because of it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field

import ops_alerts
import payments
import settings_store as st

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

SESSION_COOKIE = "ztv_admin"
SESSION_TTL = int(os.environ.get("ZTV_ADMIN_SESSION_TTL", str(8 * 3600)))
LOGIN_MAX_ATTEMPTS = int(os.environ.get("ZTV_ADMIN_MAX_LOGIN_ATTEMPTS", "8"))
LOGIN_WINDOW = int(os.environ.get("ZTV_ADMIN_LOGIN_WINDOW", "900"))
# n=2^15, r=8, p=1 is the usual "interactive login" scrypt parameter set:
# roughly 32 MB and a fraction of a second per attempt, which is what makes
# guessing expensive. That is a hair over OpenSSL's default 32 MB ceiling, so
# maxmem is raised explicitly rather than weakening the parameters to fit —
# scrypt's whole point is the memory cost.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
SCRYPT_MAXMEM = 96 * 1024 * 1024

# In-process, per-worker. Good enough to blunt online guessing; the durable
# control is the slow hash. A distributed lockout would need shared state we
# deliberately do not have.
_login_attempts: dict[str, list[float]] = {}

# Peers whose forwarded-for headers we believe. nginx runs on the same host and
# sets X-Real-IP from the address it actually saw, so loopback is the default.
TRUSTED_PROXIES = {
    a.strip() for a in
    os.environ.get("ZTV_TRUSTED_PROXIES", "127.0.0.1,::1").split(",")
    if a.strip()
}


def client_addr(request: Request) -> str:
    """The address the request really came from.

    `request.client.host` is the TCP peer, and behind the reverse proxy that is
    always 127.0.0.1. Rate limiting on it put the entire internet in one
    bucket, which is worse than not having it: it could not tell an attacker
    from anyone else, and eight failed guesses from a stranger locked the real
    operator out of the dashboard for the whole window — an admin-lockout DoS
    available to anyone who can reach the login endpoint. It also meant the
    admin audit log recorded "from 127.0.0.1" for every failed login, on the
    one record an operator would read after an intrusion attempt.

    A forwarded header is only believed when the peer is a proxy we trust;
    otherwise anyone could set it and pick a fresh bucket per attempt.
    X-Real-IP is preferred because nginx sets it from $remote_addr and a client
    cannot influence it. X-Forwarded-For is the fallback, taking the LAST
    element: nginx appends the address it saw to whatever the client sent, so
    with one proxy in front the last entry is the only trustworthy one.
    """
    peer = request.client.host if request.client else ""
    if peer not in TRUSTED_PROXIES:
        return peer or "?"
    real = (request.headers.get("X-Real-IP") or "").strip()
    if real:
        return real
    xff = request.headers.get("X-Forwarded-For") or ""
    hops = [h.strip() for h in xff.split(",") if h.strip()]
    return hops[-1] if hops else (peer or "?")


# ---------------------------------------------------------------------------
# Passwords and sessions
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                        p=SCRYPT_P, dklen=32, maxmem=SCRYPT_MAXMEM)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, want = stored.split("$")
        if scheme != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                            n=int(n), r=int(r), p=int(p), dklen=len(want) // 2,
                            maxmem=SCRYPT_MAXMEM)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), want)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _rate_limited(key: str) -> bool:
    now = time.time()
    hits = [t for t in _login_attempts.get(key, []) if now - t < LOGIN_WINDOW]
    _login_attempts[key] = hits
    return len(hits) >= LOGIN_MAX_ATTEMPTS


def _record_attempt(key: str) -> None:
    _login_attempts.setdefault(key, []).append(time.time())


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

def _db(write: bool = False):
    import main
    return main.db(write=write)


def current_admin(request: Request) -> dict:
    """Resolve the session cookie to an admin, or 401."""
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        raise HTTPException(401, "Not signed in")
    now = int(time.time())
    with _db(write=True) as conn:
        row = conn.execute(
            """SELECT s.token_hash, s.expires_at, a.id, a.username, a.disabled
               FROM admin_sessions s
               JOIN admins a ON a.id = s.admin_id
               WHERE s.token_hash = ?""",
            (_hash_token(token),),
        ).fetchone()
        if not row or row["expires_at"] < now or row["disabled"]:
            raise HTTPException(401, "Session expired")
        conn.execute("UPDATE admin_sessions SET last_seen = ? WHERE token_hash = ?",
                     (now, row["token_hash"]))
    return {"id": row["id"], "username": row["username"]}


def csrf_guard(request: Request, admin: dict = Depends(current_admin)) -> dict:
    """
    Every mutation must carry X-Admin-CSRF matching the session cookie.

    The cookie is SameSite=Strict, which already stops most cross-site posts,
    but not a same-site injection, and browsers disagree on edge cases. A
    header the attacker's page cannot set is the part that actually holds.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return admin
    sent = request.headers.get("X-Admin-CSRF", "")
    cookie = request.cookies.get(SESSION_COOKIE, "")
    if not sent or not hmac.compare_digest(sent, _hash_token(cookie)[:32]):
        raise HTTPException(403, "Missing or invalid CSRF token")
    return admin


def audit(conn, admin: Optional[dict], action: str, target: str = "",
          detail: str = "") -> None:
    conn.execute(
        """INSERT INTO admin_audit (admin_id, username, action, target, detail, at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        ((admin or {}).get("id"), (admin or {}).get("username", "-"),
         action, target[:200], detail[:1000], int(time.time())),
    )


# ---------------------------------------------------------------------------
# Bootstrap and auth
# ---------------------------------------------------------------------------

def ensure_admin(conn, username: str, password: str) -> None:
    conn.execute(
        """INSERT INTO admins (username, password_hash, created_at)
           VALUES (?, ?, ?)
           ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash""",
        (username, hash_password(password), int(time.time())),
    )


def admin_count(conn) -> int:
    return conn.execute(
        "SELECT COUNT(*) AS n FROM admins WHERE disabled = 0").fetchone()["n"]


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=512)


class SetupRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=12, max_length=512)


@router.get("/state")
def admin_state(request: Request):
    """
    Unauthenticated, and deliberately tells a stranger almost nothing: whether
    the first operator account still needs creating, and whether this browser
    is signed in. The dashboard needs both before it can render anything.
    """
    with _db() as conn:
        needs_setup = admin_count(conn) == 0
    signed_in, username, csrf = False, None, None
    try:
        admin = current_admin(request)
        signed_in, username = True, admin["username"]
        csrf = _hash_token(request.cookies.get(SESSION_COOKIE, ""))[:32]
    except HTTPException:
        pass
    return {"needs_setup": needs_setup, "signed_in": signed_in,
            "username": username, "csrf": csrf}


@router.post("/setup")
def admin_setup(req: SetupRequest, request: Request, response: Response):
    """
    Create the first operator. Only possible while none exists — otherwise
    anyone who found the dashboard could mint themselves an account.
    """
    with _db(write=True) as conn:
        if admin_count(conn) > 0:
            raise HTTPException(409, "An administrator already exists")
        ensure_admin(conn, req.username, req.password)
        audit(conn, None, "admin.setup", req.username, "first operator created")
    return _issue_session(req.username, request, response)


@router.post("/login")
def admin_login(req: LoginRequest, request: Request, response: Response):
    client = client_addr(request)

    # Address first, before doing any work: a single source that has already
    # burned its attempts gets nothing, and cannot make us compute scrypt.
    if _rate_limited(f"a:{client}"):
        raise HTTPException(429, "Too many attempts. Wait, then try again.")

    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM admins WHERE username = ?", (req.username,)).fetchone()

    # Hash even when the user does not exist, so response time does not
    # separate "no such account" from "wrong password".
    stored = row["password_hash"] if row else hash_password("decoy")
    ok = verify_password(req.password, stored) and row is not None and not row["disabled"]

    # A correct password is honoured even if the username is over its limit.
    #
    # Locking an account after N failures hands anyone who can reach this
    # endpoint an admin-lockout: the username is not a secret, and the only
    # recovery from a locked dashboard — the place bans and refunds live — is
    # to wait or to have shell on the box. Rate limiting exists to make
    # guessing expensive, and a correct password is not a guess. The controls
    # that survive are the per-address block above, nginx's limit_req, and
    # scrypt making every attempt cost real CPU.
    if not ok:
        for key in (f"u:{req.username}", f"a:{client}"):
            _record_attempt(key)
        with _db(write=True) as conn:
            audit(conn, None, "admin.login.failed", req.username, f"from {client}")
        if _rate_limited(f"u:{req.username}"):
            raise HTTPException(429, "Too many attempts. Wait, then try again.")
        raise HTTPException(401, "Invalid credentials")

    # Signing in clears the counters, so a fumbled password followed by the
    # right one does not leave the operator part-way to a lockout.
    for key in (f"u:{req.username}", f"a:{client}"):
        _login_attempts.pop(key, None)
    return _issue_session(req.username, request, response)


def _issue_session(username: str, request: Request, response: Response) -> dict:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with _db(write=True) as conn:
        admin = conn.execute(
            "SELECT * FROM admins WHERE username = ?", (username,)).fetchone()
        conn.execute(
            """INSERT INTO admin_sessions (token_hash, admin_id, created_at, expires_at)
               VALUES (?, ?, ?, ?)""",
            (_hash_token(token), admin["id"], now, now + SESSION_TTL))
        conn.execute("UPDATE admins SET last_login = ? WHERE id = ?", (now, admin["id"]))
        # Housekeeping while we hold the write lock.
        conn.execute("DELETE FROM admin_sessions WHERE expires_at < ?", (now,))
        audit(conn, {"id": admin["id"], "username": username}, "admin.login", username)

    secure = request.url.scheme == "https" or \
        request.headers.get("X-Forwarded-Proto") == "https"
    response.set_cookie(
        SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True,
        samesite="strict", secure=secure, path="/")
    return {"ok": True, "username": username,
            "csrf": _hash_token(token)[:32], "expires_at": now + SESSION_TTL}


@router.post("/logout")
def admin_logout(request: Request, response: Response,
                 admin: dict = Depends(csrf_guard)):
    token = request.cookies.get(SESSION_COOKIE, "")
    with _db(write=True) as conn:
        conn.execute("DELETE FROM admin_sessions WHERE token_hash = ?",
                     (_hash_token(token),))
        audit(conn, admin, "admin.logout", admin["username"])
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


class PasswordChange(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=512)
    new_password: str = Field(..., min_length=12, max_length=512)


@router.post("/password")
def change_password(req: PasswordChange, admin: dict = Depends(csrf_guard)):
    with _db(write=True) as conn:
        row = conn.execute("SELECT * FROM admins WHERE id = ?",
                           (admin["id"],)).fetchone()
        if not verify_password(req.current_password, row["password_hash"]):
            raise HTTPException(403, "Current password is incorrect")
        conn.execute("UPDATE admins SET password_hash = ? WHERE id = ?",
                     (hash_password(req.new_password), admin["id"]))
        # Every other session for this operator dies with the old password.
        conn.execute("DELETE FROM admin_sessions WHERE admin_id = ?", (admin["id"],))
        audit(conn, admin, "admin.password.changed", admin["username"])
    return {"ok": True, "note": "All sessions signed out. Sign in again."}


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------

@router.get("/overview")
def overview(admin: dict = Depends(current_admin)):
    """Everything the dashboard's front page needs, in one query round."""
    now = int(time.time())
    with _db() as conn:
        def one(sql, *a):
            return conn.execute(sql, a).fetchone()[0]

        accounts = {
            "active": one("SELECT COUNT(*) FROM accounts WHERE status='active' AND expires_at > ?", now),
            "trial": one("SELECT COUNT(*) FROM accounts WHERE status='active' AND plan='trial' AND expires_at > ?", now),
            "expired": one("SELECT COUNT(*) FROM accounts WHERE status='expired'"),
            "banned": one("SELECT COUNT(*) FROM accounts WHERE status='banned'"),
            "pending": one("SELECT COUNT(*) FROM accounts WHERE status='pending_payment'"),
        }
        revenue = {
            "settled_30d": one(
                "SELECT COALESCE(SUM(amount_usd),0) FROM invoices WHERE status='settled' AND settled_at > ?",
                now - 30 * 86400),
            "settled_all": one(
                "SELECT COALESCE(SUM(amount_usd),0) FROM invoices WHERE status='settled'"),
            "invoices_open": one(
                "SELECT COUNT(*) FROM invoices WHERE status='pending'"),
        }
        nodes = [dict(r) for r in conn.execute(
            """SELECT id, region, role, active, ephemeral, public_ip,
                      last_heartbeat, capacity
               FROM mesh_nodes ORDER BY region, id""")]
        devices = one("SELECT COUNT(*) FROM devices")
        recent = [dict(r) for r in conn.execute(
            "SELECT username, action, target, at FROM admin_audit ORDER BY at DESC LIMIT 10")]
        provider = st.get(conn, "ZTV_PAYMENT_PROVIDER", payments.DEFAULT_PROVIDER)

    stale = now - 300
    for n in nodes:
        n["healthy"] = bool(n["active"]) and (
            not n["ephemeral"] or n["last_heartbeat"] > stale)
    return {"accounts": accounts, "revenue": revenue, "devices": devices,
            "nodes": nodes, "provider": provider, "recent_activity": recent,
            "now": now}


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------

@router.get("/accounts")
def list_accounts(q: str = "", status: str = "", plan: str = "",
                  limit: int = 50, offset: int = 0,
                  admin: dict = Depends(current_admin)):
    """
    Search accounts.

    There is no name or email to search by — that is the product. What an
    operator actually has when a customer writes in is the token itself, so
    the search box accepts one and matches on its hash. It also accepts an
    account id, a mesh IP, or a device pubkey, because those are the other
    things that turn up in an abuse report.
    """
    import main
    limit = max(1, min(limit, 200))
    where, args = ["1=1"], []
    if status:
        where.append("a.status = ?"); args.append(status)
    if plan:
        where.append("a.plan = ?"); args.append(plan)

    raw = q or ""
    q = raw.strip()
    if q:
        # A WireGuard public key is base64 and routinely contains '+', which
        # decodes to a space in a query string. An operator pasting a key into
        # the search box (or a URL) would otherwise get no result and no clue
        # why, so try the space-restored forms as well. Every one of these is
        # an exact-match lookup against an indexed column, so an extra
        # candidate cannot broaden the result into someone else's account.
        #
        # Restoring from the UNSTRIPPED value matters: a key whose base64
        # begins with '+' arrives as a leading space, and .strip() removes it
        # before there is anything left to put back. That is roughly one key
        # in sixty-four — rare enough to pass twenty-three CI runs and fail
        # the twenty-fourth, and rare enough in production to look like the
        # operator mistyping rather than the search being broken, on the one
        # key an abuse report actually named.
        candidates = {q, q.replace(" ", "+"), raw.replace(" ", "+").strip()}
        candidates.discard("")
        clauses = ["a.id = ?"]
        args_q = [q if q.isdigit() else -1]
        # A full token: match the hash, never store or log the token itself.
        clauses.append("a.token_hash = ?"); args_q.append(main.hash_token(q))
        clauses.append("a.id IN (SELECT account_id FROM devices WHERE mesh_ip = ?)")
        args_q.append(q)
        for cand in sorted(candidates):
            clauses.append(
                "a.id IN (SELECT account_id FROM devices WHERE pubkey = ?)")
            args_q.append(cand)
        clauses.append("a.note LIKE ?"); args_q.append(f"%{q}%")
        where.append("(" + " OR ".join(clauses) + ")")
        args.extend(args_q)

    sql = f"""SELECT a.id, a.status, a.plan, a.created_at, a.expires_at,
                     a.banned_reason, a.banned_at, a.note,
                     (SELECT COUNT(*) FROM devices d WHERE d.account_id = a.id) AS devices
              FROM accounts a
              WHERE {' AND '.join(where)}
              ORDER BY a.created_at DESC LIMIT ? OFFSET ?"""
    with _db() as conn:
        rows = [dict(r) for r in conn.execute(sql, (*args, limit, offset))]
        total = conn.execute(
            f"SELECT COUNT(*) FROM accounts a WHERE {' AND '.join(where)}",
            tuple(args)).fetchone()[0]
    return {"accounts": rows, "total": total, "limit": limit, "offset": offset}


@router.get("/accounts/{account_id}")
def get_account(account_id: int, admin: dict = Depends(current_admin)):
    with _db() as conn:
        acct = conn.execute("SELECT * FROM accounts WHERE id = ?",
                            (account_id,)).fetchone()
        if not acct:
            raise HTTPException(404, "No such account")
        acct = dict(acct)
        acct.pop("token_hash", None)   # nothing is served by echoing it
        devices = [dict(r) for r in conn.execute(
            """SELECT d.id, d.pubkey, d.device_name, d.mesh_ip, d.created_at,
                      d.last_seen, hp.entry_node, hp.exit_node, hp.expires_at AS pair_expires
               FROM devices d
               LEFT JOIN hop_pairs hp ON hp.device_id = d.id
               WHERE d.account_id = ? ORDER BY d.created_at""", (account_id,))]
        invoices = [dict(r) for r in conn.execute(
            """SELECT id, months, amount_usd, status, created_at, settled_at
               FROM invoices WHERE account_id = ? ORDER BY created_at DESC""",
            (account_id,))]
        notices = [dict(r) for r in conn.execute(
            """SELECT id, severity, subject, created_at FROM notices
               WHERE account_id = ? ORDER BY created_at DESC LIMIT 20""",
            (account_id,))]
    return {"account": acct, "devices": devices, "invoices": invoices,
            "notices": notices}


class BanRequest(BaseModel):
    reason: str = Field("", max_length=500)


@router.post("/accounts/{account_id}/ban")
def ban_account(account_id: int, req: BanRequest,
                admin: dict = Depends(csrf_guard)):
    """
    Ban an account and cut it off now.

    Removing the devices is the part that actually stops traffic: the peer
    manifest is built from live devices, so the nodes drop the keys at their
    next sync. Flipping status alone would leave them connected until expiry.
    """
    with _db(write=True) as conn:
        acct = conn.execute("SELECT id, status FROM accounts WHERE id = ?",
                            (account_id,)).fetchone()
        if not acct:
            raise HTTPException(404, "No such account")
        conn.execute(
            """UPDATE accounts SET status='banned', banned_reason=?, banned_at=?
               WHERE id = ?""",
            (req.reason[:500], int(time.time()), account_id))
        n = conn.execute("SELECT COUNT(*) FROM devices WHERE account_id = ?",
                         (account_id,)).fetchone()[0]
        conn.execute("DELETE FROM devices WHERE account_id = ?", (account_id,))
        audit(conn, admin, "account.ban", f"account:{account_id}",
              f"reason={req.reason[:200]!r} devices_removed={n}")
    return {"ok": True, "devices_removed": n}


@router.post("/accounts/{account_id}/unban")
def unban_account(account_id: int, admin: dict = Depends(csrf_guard)):
    now = int(time.time())
    with _db(write=True) as conn:
        acct = conn.execute("SELECT * FROM accounts WHERE id = ?",
                            (account_id,)).fetchone()
        if not acct:
            raise HTTPException(404, "No such account")
        # Back to whatever the clock says it should be, not blindly 'active'.
        status = "active" if acct["expires_at"] > now else "expired"
        conn.execute(
            "UPDATE accounts SET status=?, banned_reason=NULL, banned_at=0 WHERE id=?",
            (status, account_id))
        audit(conn, admin, "account.unban", f"account:{account_id}",
              f"restored to {status}")
    return {"ok": True, "status": status}


class ExtendRequest(BaseModel):
    days: int = Field(..., ge=-3650, le=3650)
    reason: str = Field("", max_length=300)


@router.post("/accounts/{account_id}/extend")
def extend_account(account_id: int, req: ExtendRequest,
                   admin: dict = Depends(csrf_guard)):
    """
    Add or remove days. Used for comping a trial, honouring support, or
    correcting a payment that settled late. Every use is logged with its
    reason, because a dashboard that can hand out free service without a
    record is the one an auditor asks about first.
    """
    now = int(time.time())
    with _db(write=True) as conn:
        acct = conn.execute("SELECT * FROM accounts WHERE id = ?",
                            (account_id,)).fetchone()
        if not acct:
            raise HTTPException(404, "No such account")
        base = max(acct["expires_at"], now)
        new_expiry = max(0, base + req.days * 86400)
        status = acct["status"]
        if status in ("pending_payment", "expired") and new_expiry > now:
            status = "active"
        elif status == "active" and new_expiry <= now:
            status = "expired"
        conn.execute("UPDATE accounts SET expires_at=?, status=? WHERE id=?",
                     (new_expiry, status, account_id))
        audit(conn, admin, "account.extend", f"account:{account_id}",
              f"days={req.days} reason={req.reason[:200]!r} -> {new_expiry}")
    return {"ok": True, "expires_at": new_expiry, "status": status}


class NoteRequest(BaseModel):
    note: str = Field("", max_length=2000)


@router.post("/accounts/{account_id}/note")
def set_note(account_id: int, req: NoteRequest, admin: dict = Depends(csrf_guard)):
    with _db(write=True) as conn:
        conn.execute("UPDATE accounts SET note = ? WHERE id = ?",
                     (req.note, account_id))
        audit(conn, admin, "account.note", f"account:{account_id}")
    return {"ok": True}


@router.delete("/accounts/{account_id}")
def delete_account(account_id: int, admin: dict = Depends(csrf_guard)):
    """
    Erase an account and everything hanging off it.

    Irreversible, and meant to be: it is how a deletion request is honoured.
    The audit row records that account N was deleted and by whom — that is
    the one trace left, and it holds no customer data.
    """
    with _db(write=True) as conn:
        acct = conn.execute("SELECT id FROM accounts WHERE id = ?",
                            (account_id,)).fetchone()
        if not acct:
            raise HTTPException(404, "No such account")
        conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        audit(conn, admin, "account.delete", f"account:{account_id}",
              "cascaded: devices, invoices, notices, hop_pairs")
    return {"ok": True}


@router.delete("/devices/{device_id}")
def admin_delete_device(device_id: int, admin: dict = Depends(csrf_guard)):
    with _db(write=True) as conn:
        row = conn.execute("SELECT account_id FROM devices WHERE id = ?",
                           (device_id,)).fetchone()
        if not row:
            raise HTTPException(404, "No such device")
        conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        audit(conn, admin, "device.delete", f"device:{device_id}",
              f"account:{row['account_id']}")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Mesh nodes
# ---------------------------------------------------------------------------

class NodeRequest(BaseModel):
    id: str = Field(..., min_length=3, max_length=32,
                    pattern=r"^[a-z]{3}-[0-9]{2,3}$")
    region: str = Field(..., min_length=2, max_length=8)
    role: str = Field("both", pattern=r"^(entry|exit|both)$")
    pubkey: str = Field(..., min_length=44, max_length=44)
    public_ip: str = Field(..., min_length=3, max_length=64)
    wg_port: int = Field(51820, ge=1, le=65535)
    capacity: int = Field(1000, ge=1, le=1000000)
    hostname: str = Field("", max_length=128)


@router.get("/nodes")
def list_nodes(admin: dict = Depends(current_admin)):
    now = int(time.time())
    with _db() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM mesh_nodes ORDER BY region, id")]
        counts = {r["node_id"]: r["n"] for r in conn.execute(
            "SELECT node_id, COUNT(*) AS n FROM device_nodes GROUP BY node_id")}
    for r in rows:
        r.pop("psk_hash", None)
        r["healthy"] = bool(r["active"]) and (
            not r["ephemeral"] or r["last_heartbeat"] > now - 300)
        r["devices"] = counts.get(r["id"], 0)
    return {"nodes": rows, "now": now}


@router.post("/nodes")
def add_node(req: NodeRequest, admin: dict = Depends(csrf_guard)):
    """
    Register a static mesh node.

    Until now this meant opening sqlite3 and writing the INSERT by hand, which
    is both unpleasant and the kind of thing that goes wrong at 2am. The
    region is checked against the jurisdiction allowlist, because a node in
    the wrong country is not a typo — it is a broken promise, and
    audit-verify.sh will fail the next day.
    """
    import main
    allowed = set(main.REGION_NAMES)
    if req.region not in allowed:
        raise HTTPException(
            400,
            f"Region {req.region!r} is not one of {sorted(allowed)}. Add it to "
            f"REGION_NAMES first, and check the jurisdiction commitment in "
            f"docs/AUDIT.md before you do.")
    if not req.id.startswith(req.region + "-"):
        raise HTTPException(400, f"Node id should start with '{req.region}-'")

    endpoint = f"{req.public_ip}:{req.wg_port}"
    if ":" in req.public_ip and not req.public_ip.startswith("["):
        endpoint = f"[{req.public_ip}]:{req.wg_port}"   # IPv6 literal

    with _db(write=True) as conn:
        if conn.execute("SELECT 1 FROM mesh_nodes WHERE id = ?",
                        (req.id,)).fetchone():
            raise HTTPException(409, f"Node {req.id} already exists")
        conn.execute(
            """INSERT INTO mesh_nodes
                 (id, hostname, pubkey, endpoint, region, role, public_ip,
                  capacity, active, ephemeral, last_heartbeat)
               VALUES (?,?,?,?,?,?,?,?,1,0,?)""",
            (req.id, req.hostname or f"{req.id}.0trustvpn.com", req.pubkey,
             endpoint, req.region, req.role, req.public_ip, req.capacity,
             int(time.time())))
        audit(conn, admin, "node.add", req.id,
              f"region={req.region} role={req.role} endpoint={endpoint}")
    return {"ok": True, "id": req.id, "endpoint": endpoint}


class NodeUpdate(BaseModel):
    role: Optional[str] = Field(None, pattern=r"^(entry|exit|both)$")
    capacity: Optional[int] = Field(None, ge=1, le=1000000)
    active: Optional[bool] = None


@router.patch("/nodes/{node_id}")
def update_node(node_id: str, req: NodeUpdate, admin: dict = Depends(csrf_guard)):
    fields, args, changed = [], [], []
    if req.role is not None:
        fields.append("role = ?"); args.append(req.role); changed.append(f"role={req.role}")
    if req.capacity is not None:
        fields.append("capacity = ?"); args.append(req.capacity); changed.append(f"capacity={req.capacity}")
    if req.active is not None:
        fields.append("active = ?"); args.append(1 if req.active else 0)
        changed.append(f"active={req.active}")
    if not fields:
        raise HTTPException(400, "Nothing to change")
    with _db(write=True) as conn:
        if not conn.execute("SELECT 1 FROM mesh_nodes WHERE id = ?",
                            (node_id,)).fetchone():
            raise HTTPException(404, "No such node")
        conn.execute(f"UPDATE mesh_nodes SET {', '.join(fields)} WHERE id = ?",
                     (*args, node_id))
        audit(conn, admin, "node.update", node_id, ", ".join(changed))
    return {"ok": True}


@router.delete("/nodes/{node_id}")
def remove_node(node_id: str, admin: dict = Depends(csrf_guard)):
    """
    Remove a node. Sessions routed through it are released first — a hop pair
    naming a node that no longer exists is unroutable anyway, and leaving the
    rows behind is what used to make the sweeper fall over.
    """
    with _db(write=True) as conn:
        if not conn.execute("SELECT 1 FROM mesh_nodes WHERE id = ?",
                            (node_id,)).fetchone():
            raise HTTPException(404, "No such node")
        pairs = conn.execute(
            "SELECT COUNT(*) FROM hop_pairs WHERE entry_node=? OR exit_node=?",
            (node_id, node_id)).fetchone()[0]
        conn.execute("DELETE FROM hop_pairs WHERE entry_node=? OR exit_node=?",
                     (node_id, node_id))
        conn.execute("DELETE FROM device_nodes WHERE node_id = ?", (node_id,))
        conn.execute("DELETE FROM mesh_nodes WHERE id = ?", (node_id,))
        audit(conn, admin, "node.remove", node_id, f"released {pairs} hop pairs")
    return {"ok": True, "pairs_released": pairs}


class ProvisionTokenRequest(BaseModel):
    region: str = Field(..., min_length=2, max_length=8)
    role: str = Field("both", pattern=r"^(entry|exit|both)$")
    # A year, not a week. A one-shot token is used minutes after it is minted,
    # but an enrolment token has to still work the night the VPS reboots
    # unattended, which is the whole reason it exists.
    ttl_hours: int = Field(1, ge=1, le=8784)
    # 1 = the original one-shot token. More than 1 mints an enrolment token:
    # it pins itself to the first node's public IP and can re-register that
    # node after a reboot, when its tmpfs disk has forgotten everything.
    uses: int = Field(1, ge=1, le=50)


@router.post("/nodes/provision-token")
def mint_provision_token(req: ProvisionTokenRequest,
                         admin: dict = Depends(csrf_guard)):
    """
    Mint a token for a RAM-only node to register itself.
    Shown once; only its hash is stored.
    """
    import main
    if req.region not in set(main.REGION_NAMES):
        raise HTTPException(400, f"Unknown region {req.region!r}")
    token = "ztvp-" + secrets.token_urlsafe(24)
    now = int(time.time())
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with _db(write=True) as conn:
        conn.execute(
            """INSERT INTO provision_tokens
                 (token_hash, region, role, created_at, expires_at, max_uses)
               VALUES (?,?,?,?,?,?)""",
            (token_hash, req.region, req.role,
             now, now + req.ttl_hours * 3600, req.uses))
        audit(conn, admin, "node.provision_token", f"{req.region}/{req.role}",
              f"ttl={req.ttl_hours}h uses={req.uses}")
    return {"token": token, "region": req.region, "role": req.role,
            "expires_at": now + req.ttl_hours * 3600,
            "uses": req.uses, "id": token_hash[:12],
            "note": ("Shown once. Pass as --provision-token to "
                     "install.sh --mode node, or ZTV_PROVISION_TOKEN in "
                     "cloud-init.")}


@router.get("/nodes/provision-tokens")
def list_provision_tokens(admin: dict = Depends(current_admin)):
    """
    Outstanding tokens, so an operator can see what can still register a node
    and kill anything they do not recognise. The token itself is not stored
    and cannot be shown again — rows are identified by a hash prefix.
    """
    now = int(time.time())
    with _db() as conn:
        rows = conn.execute(
            """SELECT token_hash, region, role, created_at, expires_at,
                      used_at, used_node_id, max_uses, used_count, bind_ip,
                      revoked_at
                 FROM provision_tokens
                ORDER BY created_at DESC, rowid DESC LIMIT 100""").fetchall()
    out = []
    for r in rows:
        used = max(r["used_count"] or 0, 1 if r["used_at"] else 0)
        max_uses = r["max_uses"] or 1
        if r["revoked_at"]:
            state = "revoked"
        elif r["expires_at"] < now:
            state = "expired"
        elif used >= max_uses:
            state = "spent"
        else:
            state = "live"
        out.append({"id": r["token_hash"][:12], "region": r["region"],
                    "role": r["role"], "created_at": r["created_at"],
                    "expires_at": r["expires_at"], "node_id": r["used_node_id"],
                    "uses": used, "max_uses": max_uses,
                    "bound_to": r["bind_ip"], "state": state})
    return {"tokens": out}


@router.post("/nodes/provision-tokens/{token_id}/revoke")
def revoke_provision_token(token_id: str, admin: dict = Depends(csrf_guard)):
    """
    Kill a token. The node it already registered keeps running — it holds its
    own PSK — but it cannot re-register, and nothing else can use the token.
    """
    if not re.fullmatch(r"[0-9a-f]{6,64}", token_id or ""):
        raise HTTPException(400, "Bad token id")
    now = int(time.time())
    with _db(write=True) as conn:
        rows = conn.execute(
            "SELECT token_hash FROM provision_tokens WHERE token_hash LIKE ?",
            (token_id + "%",)).fetchall()
        if not rows:
            raise HTTPException(404, "No such token")
        if len(rows) > 1:
            raise HTTPException(409, "Ambiguous token id")
        conn.execute(
            "UPDATE provision_tokens SET revoked_at = ? WHERE token_hash = ?",
            (now, rows[0]["token_hash"]))
        audit(conn, admin, "node.provision_token_revoke", token_id, "")
    return {"ok": True, "id": token_id}


# ---------------------------------------------------------------------------
# Payments
# ---------------------------------------------------------------------------

@router.get("/invoices")
def list_invoices(status: str = "", limit: int = 50, offset: int = 0,
                  admin: dict = Depends(current_admin)):
    limit = max(1, min(limit, 200))
    where, args = ["1=1"], []
    if status:
        where.append("status = ?"); args.append(status)
    with _db() as conn:
        rows = [dict(r) for r in conn.execute(
            f"""SELECT id, account_id, months, amount_usd, currency, status,
                       created_at, settled_at, checkout_url
                FROM invoices WHERE {' AND '.join(where)}
                ORDER BY created_at DESC LIMIT ? OFFSET ?""",
            (*args, limit, offset))]
        total = conn.execute(
            f"SELECT COUNT(*) FROM invoices WHERE {' AND '.join(where)}",
            tuple(args)).fetchone()[0]
    return {"invoices": rows, "total": total}


@router.post("/invoices/{invoice_id}/settle")
def manual_settle(invoice_id: str, admin: dict = Depends(csrf_guard)):
    """
    Credit an invoice by hand.

    For the case every crypto operator eventually hits: the payment landed on
    chain but the webhook never arrived. Goes through the same
    credit-exactly-once path as a webhook, so using it twice cannot double an
    account's expiry, and it is logged as a manual action because it is the
    single most abusable control on this dashboard.
    """
    import main
    now = int(time.time())
    with _db(write=True) as conn:
        inv = conn.execute("SELECT * FROM invoices WHERE id = ?",
                           (invoice_id,)).fetchone()
        if not inv:
            raise HTTPException(404, "No such invoice")
        if inv["status"] == main.SETTLED:
            return {"ok": True, "duplicate": True,
                    "note": "Already settled; nothing credited."}
        acct = conn.execute("SELECT * FROM accounts WHERE id = ?",
                            (inv["account_id"],)).fetchone()
        if not acct:
            raise HTTPException(404, "Invoice has no account")
        cur = conn.execute(
            "UPDATE invoices SET status=?, settled_at=? WHERE id=? AND status!=?",
            (main.SETTLED, now, invoice_id, main.SETTLED))
        if cur.rowcount == 0:
            return {"ok": True, "duplicate": True}
        new_expiry = max(acct["expires_at"], now) + inv["months"] * 30 * 86400
        conn.execute(
            "UPDATE accounts SET status='active', expires_at=?, plan='paid' WHERE id=?",
            (new_expiry, acct["id"]))
        audit(conn, admin, "invoice.manual_settle", invoice_id,
              f"account:{acct['id']} months={inv['months']} -> {new_expiry}")
    return {"ok": True, "account_id": acct["id"], "expires_at": new_expiry}


@router.get("/payments/health")
def payment_health(admin: dict = Depends(current_admin)):
    """
    Can we reach the payment provider right now?

    Worth its own button: a signup returning 502 tells the customer nothing
    and the operator less. This says which provider is configured, whether
    its credentials are present, and whether it answers.
    """
    import payments
    with _db() as conn:
        name = st.get(conn, "ZTV_PAYMENT_PROVIDER", payments.DEFAULT_PROVIDER)
        missing = [k for k in payments.required_settings(name)
                   if not st.get(conn, k)]
    result = {"provider": name, "missing_settings": missing,
              "currencies": list(payments.currencies_for(name))}
    if missing:
        result["reachable"] = False
        result["detail"] = "Configuration incomplete"
        return result
    try:
        payments.reset_provider()
        ok, detail = payments.provider().health()
        result["reachable"], result["detail"] = ok, detail
    except Exception as e:                       # never 500 a health check
        result["reachable"], result["detail"] = False, str(e)[:300]
    return result


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@router.get("/settings")
def get_settings(admin: dict = Depends(current_admin)):
    """Current settings, with secrets masked and each field's spec attached."""
    with _db() as conn:
        values = st.get_all(conn)
        sources = {r["key"]: {"updated_at": r["updated_at"],
                              "updated_by": r["updated_by"]}
                   for r in conn.execute(
                       "SELECT key, updated_at, updated_by FROM settings")}
    out = {}
    for key, spec in st.SETTING_SPECS.items():
        out[key] = {
            "value": st.mask(key, values.get(key, "")),
            "set": bool(values.get(key)),
            "secret": spec.get("secret", False),
            "type": spec.get("type", "text"),
            "choices": spec.get("choices"),
            "group": spec.get("group", "other"),
            "label": spec.get("label", key),
            "from_db": key in sources,
            **({"updated": sources[key]} if key in sources else {}),
        }
    return {"settings": out}


class SettingsUpdate(BaseModel):
    values: dict


@router.post("/settings")
def update_settings(req: SettingsUpdate, admin: dict = Depends(csrf_guard)):
    """
    Write settings and make them live.

    Providers read configuration from the environment when they are built, so
    the new values are pushed there and the cached provider dropped. The next
    request constructs a fresh one — no restart, and no window where the
    dashboard says one thing and the API does another.
    """
    import payments
    with _db(write=True) as conn:
        changed = st.set_many(conn, req.values, admin["username"])
        if changed:
            # Log which keys moved, never their values: half of these are
            # payment credentials and the audit log is not the place for them.
            audit(conn, admin, "settings.update", ",".join(sorted(changed)),
                  f"{len(changed)} setting(s) changed")
        st.apply_to_environ(conn)
    payments.reset_provider()
    return {"ok": True, "changed": sorted(changed)}


# ---------------------------------------------------------------------------
# Notices — the closest thing to "emailing customers" this design allows
# ---------------------------------------------------------------------------

class NoticeRequest(BaseModel):
    subject: str = Field(..., min_length=1, max_length=120)
    body: str = Field(..., min_length=1, max_length=4000)
    severity: str = Field("info", pattern=r"^(info|warning|urgent)$")
    account_id: Optional[int] = None      # None = everyone
    expires_days: int = Field(30, ge=1, le=365)


@router.get("/notices")
def list_notices(limit: int = 50, admin: dict = Depends(current_admin)):
    with _db() as conn:
        rows = [dict(r) for r in conn.execute(
            """SELECT n.*, (SELECT COUNT(*) FROM notice_reads r
                            WHERE r.notice_id = n.id) AS reads
               FROM notices n ORDER BY n.created_at DESC LIMIT ?""",
            (max(1, min(limit, 200)),))]
    return {"notices": rows}


@router.post("/notices")
def create_notice(req: NoticeRequest, admin: dict = Depends(csrf_guard)):
    """
    Post a notice to one customer or to everyone.

    This is what "email the customers" turns into when there are no email
    addresses. Nothing is sent anywhere; the message waits, and the client
    picks it up on its next status check — `0trust status`, the GUI, or the
    mobile app. A customer who never runs the client never sees it, which is
    a real limitation and the honest cost of holding no contact details.
    """
    now = int(time.time())
    with _db(write=True) as conn:
        if req.account_id is not None:
            if not conn.execute("SELECT 1 FROM accounts WHERE id = ?",
                                (req.account_id,)).fetchone():
                raise HTTPException(404, "No such account")
        cur = conn.execute(
            """INSERT INTO notices
                 (account_id, severity, subject, body, created_at, expires_at, created_by)
               VALUES (?,?,?,?,?,?,?)""",
            (req.account_id, req.severity, req.subject, req.body, now,
             now + req.expires_days * 86400, admin["username"]))
        target = f"account:{req.account_id}" if req.account_id else "all"
        audit(conn, admin, "notice.create", target,
              f"[{req.severity}] {req.subject[:120]}")
        # How many accounts could actually see it, so the operator is not
        # guessing at reach.
        if req.account_id:
            reach = 1
        else:
            reach = conn.execute(
                "SELECT COUNT(*) FROM accounts WHERE status IN ('active','expired')"
            ).fetchone()[0]
    return {"ok": True, "id": cur.lastrowid, "reach": reach}


@router.delete("/notices/{notice_id}")
def withdraw_notice(notice_id: int, admin: dict = Depends(csrf_guard)):
    with _db(write=True) as conn:
        conn.execute("DELETE FROM notices WHERE id = ?", (notice_id,))
        audit(conn, admin, "notice.withdraw", f"notice:{notice_id}")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@router.get("/events")
def get_events(limit: int = 100, hours: int = 168,
               admin: dict = Depends(current_admin)):
    """
    Operational events: what broke, and when.

    Distinct from /audit, which records what an operator did. This is what the
    system did on its own — a node going dark, a payment provider refusing to
    answer, the disk filling up. Before it existed, the only way to learn a
    node had died was to notice the status page had gone amber.
    """
    limit = max(1, min(limit, 500))
    since = int(time.time()) - max(1, min(hours, 24 * 90)) * 3600
    with _db() as conn:
        return {
            "events": ops_alerts.recent(conn, limit=limit, since=since),
            "unresolved": ops_alerts.unresolved_count(conn),
            "webhook_configured": bool(
                os.environ.get(ops_alerts.WEBHOOK_URL, "").strip()),
        }


@router.get("/audit")
def get_audit(limit: int = 100, offset: int = 0, action: str = "",
              admin: dict = Depends(current_admin)):
    limit = max(1, min(limit, 500))
    where, args = ["1=1"], []
    if action:
        where.append("action LIKE ?"); args.append(f"{action}%")
    with _db() as conn:
        rows = [dict(r) for r in conn.execute(
            f"""SELECT id, username, action, target, detail, at FROM admin_audit
                WHERE {' AND '.join(where)}
                ORDER BY at DESC LIMIT ? OFFSET ?""", (*args, limit, offset))]
        total = conn.execute(
            f"SELECT COUNT(*) FROM admin_audit WHERE {' AND '.join(where)}",
            tuple(args)).fetchone()[0]
    return {"entries": rows, "total": total}
