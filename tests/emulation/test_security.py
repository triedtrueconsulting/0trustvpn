#!/usr/bin/env python3
"""
Adversarial probe: try to break the authorization boundaries.

Every case here is an attack someone would actually try — forging a
proof-of-work challenge, reaching another account's devices, crediting a
subscription from someone else's invoice, getting SQL through a region code.
Passing means the boundary held, not that it was never tested.
"""
import base64, hashlib, json, os, shutil, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

def solve(nonce, bits):
    wb, rb = divmod(bits, 8)
    i = 0
    while True:
        d = hashlib.sha256(f"{nonce}:{i}".encode()).digest()
        if not any(d[k] for k in range(wb)) and (not rb or not d[wb] >> (8 - rb)):
            return str(i)
        i += 1

TMP = H.tempdir("sec-"); DB = os.path.join(TMP, "0trust.db")
os.environ.update(ZTV_DB_PATH=DB, ZTV_TRIAL_SECRET="sec-secret",
                  ZTV_TRIAL_POW_BITS="10", ZTV_TRIAL_MAX_DEVICES="2")
sys.path.insert(0, os.path.join(H.REPO, "api"))
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=2)

try:
    print("[trial] forging around the proof of work")
    st, ch = H.call("GET", "/api/v1/trial/challenge")
    # Extend the expiry to buy unlimited time, keeping the original signature.
    st1, r1 = H.call("POST", "/api/v1/trial", {
        "nonce": ch["nonce"], "expires_at": ch["expires_at"] + 86400,
        "signature": ch["signature"], "solution": solve(ch["nonce"], 10)})
    check("cannot extend a challenge's expiry (signature covers it)", st1 == 400, f"{st1} {r1}")

    # Swap in a nonce that is easier to solve, keeping a real signature.
    st2, r2 = H.call("POST", "/api/v1/trial", {
        "nonce": "0" * 32, "expires_at": ch["expires_at"],
        "signature": ch["signature"], "solution": solve("0" * 32, 10)})
    check("cannot substitute the nonce", st2 == 400, f"{st2} {r2}")

    # A solution for a DIFFERENT nonce.
    st3, ch3 = H.call("GET", "/api/v1/trial/challenge")
    st4, r4 = H.call("POST", "/api/v1/trial", {
        "nonce": ch3["nonce"], "expires_at": ch3["expires_at"],
        "signature": ch3["signature"], "solution": solve("unrelated", 10)})
    check("a solution for another nonce is rejected", st4 == 400, f"{st4} {r4}")

    # Enormous solution string -> the field is length-capped.
    st5, r5 = H.call("POST", "/api/v1/trial", {
        "nonce": ch3["nonce"], "expires_at": ch3["expires_at"],
        "signature": ch3["signature"], "solution": "A" * 100000})
    check("over-long solution rejected without work", st5 in (400, 422), st5)

    print("\n[devices] cross-account access")
    tokA, _ = H.paid_account()
    tokB, _ = H.paid_account()
    pkA = H.genkey()
    H.call("POST", "/api/v1/wg/register",
           {"pubkey": pkA, "device_name": "a", "region": "zur"},
           headers={"X-Account-Token": tokA})
    st, devsB = H.call("GET", "/api/v1/devices", headers={"X-Account-Token": tokB})
    check("B cannot see A's devices", st == 200 and not devsB, devsB)
    st, r = H.call("DELETE", f"/api/v1/devices/{pkA.replace('/','%2F').replace('+','%2B')}",
                   headers={"X-Account-Token": tokB})
    check("B cannot delete A's device", st == 404, f"{st} {r}")
    st, devsA = H.call("GET", "/api/v1/devices", headers={"X-Account-Token": tokA})
    check("A's device survived", any(d["pubkey"] == pkA for d in devsA), devsA)
    st, r = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": pkA, "device_name": "steal", "region": "zur"},
                   headers={"X-Account-Token": tokB})
    check("B cannot hijack A's pubkey", st == 409, f"{st} {r}")
    st, r = H.call("POST", "/api/v1/wg/rotate", {"pubkey": pkA, "region": "rey"},
                   headers={"X-Account-Token": tokB})
    check("B cannot rotate A's device", st == 404, f"{st} {r}")

    print("\n[payments] invoice binding")
    st, acct = H.call("POST", "/api/v1/account", {"months": 1})
    # Settling someone else's invoice must credit THAT account, not the caller's.
    H.settle(acct["invoice_id"])
    st, sA = H.call("GET", "/api/v1/account/status", headers={"X-Account-Token": tokA})
    check("settling an unrelated invoice does not credit another account",
          sA["days_remaining"] <= 31, sA)
    st, r = H.call("POST", "/api/v1/account", {"months": 999})
    check("unpriced month count rejected", st == 422, st)
    st, r = H.call("POST", "/api/v1/account", {"months": -1})
    check("negative months rejected", st == 422, st)

    print("\n[peer manifest] a node sees only what it routes")
    # One node's PSK used to be enough to enumerate every customer, which is
    # not compatible with "a seized node reveals nothing operational".
    tokC, _ = H.paid_account()
    pk_single = H.genkey()
    H.call("POST", "/api/v1/wg/register",
           {"pubkey": pk_single, "device_name": "s", "region": "zur"},
           headers={"X-Account-Token": tokC})
    pk_multi = H.genkey()
    H.call("POST", "/api/v1/wg/register",
           {"pubkey": pk_multi, "device_name": "m", "region": "zur",
            "exit_region": "buc"},
           headers={"X-Account-Token": tokC})

    def at(node):
        st, b = H.call("GET", f"/api/v1/wg/peers?node_id={node}",
                       headers={"X-Node-Psk": H.NODE_PSK})
        return st, {p["public_key"] for p in b.get("peers", [])}

    _, zur = at("zur-01")
    _, buc = at("buc-01")
    _, rey = at("rey-01")
    check("a node cannot enumerate the whole customer base",
          not (pk_single in buc and pk_multi in buc), f"buc={buc}")
    check("the exit of a multi-hop session gets that key", pk_multi in buc, buc)
    check("the entry of a multi-hop session does not", pk_multi not in zur, zur)
    check("an uninvolved node gets nothing", not rey, rey)

    st, r = H.call("GET", "/api/v1/wg/peers", headers={"X-Node-Psk": H.NODE_PSK})
    check("an unidentified node is refused rather than served everything",
          st == 400, f"{st} {r}")

    print("\n[input] hostile field values")
    long_name = "x" * 100000
    st, r = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": H.genkey(), "device_name": long_name, "region": "zur"},
                   headers={"X-Account-Token": tokA})
    check("over-long device name rejected", st == 422, st)
    st, r = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": "short", "device_name": "d", "region": "zur"},
                   headers={"X-Account-Token": tokA})
    check("malformed pubkey rejected", st == 422, st)
    st, r = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": H.genkey(), "device_name": "d",
                    "region": "zur'; DROP TABLE accounts;--"},
                   headers={"X-Account-Token": tokA})
    check("SQL metacharacters in region are rejected, not executed",
          st == 400, f"{st} {r}")
    st, chk = H.call("GET", "/api/v1/regions")
    check("accounts table still exists after that", st == 200 and chk["regions"], chk)
finally:
    H.shutdown()

# --------------------------------------------------------------------------
# The admin lockout's bookkeeping is attacker-sized unless something bounds it.
#
# _login_attempts is keyed by source address and by attempted username, both
# chosen by whoever is knocking. Nothing removed a key: the per-key prune only
# touches the key being looked up, and an address seen once is never looked up
# again. The per-IP limit caps attempts FROM an address, not the number OF
# addresses, and one IPv6 /64 is 2^64 of them — so the dict grew forever on a
# 2GB box that also runs nginx, the API and SQLite.
#
# In-process rather than over HTTP: filling the dict through the API would
# take as long as the attack does. What matters is the eviction policy, and
# these are the three things it has to get right.
# --------------------------------------------------------------------------
print("\n[admin] the login-attempt table cannot grow without bound")
import admin as admin_mod

_saved_cap, _saved_hits = admin_mod._ATTEMPTS_SOFT_CAP, dict(admin_mod._login_attempts)
try:
    admin_mod._ATTEMPTS_SOFT_CAP = 100
    admin_mod._login_attempts.clear()
    for i in range(500):
        admin_mod._record_attempt(f"a:198.51.100.{i}")
    check("a spray from 500 addresses does not keep 500 counters",
          len(admin_mod._login_attempts) <= 100, len(admin_mod._login_attempts))

    # Aged-out counters go first: they cannot rate-limit anything any more,
    # while the fresh ones are the whole point of the table.
    admin_mod._login_attempts.clear()
    stale = time.time() - admin_mod.LOGIN_WINDOW - 60
    for i in range(150):
        admin_mod._login_attempts[f"a:stale{i}"] = [stale]
    for i in range(20):
        admin_mod._login_attempts[f"a:fresh{i}"] = [time.time()]
    admin_mod._record_attempt("a:trigger")
    survivors = [k for k in admin_mod._login_attempts if k.startswith("a:fresh")]
    check("the sweep drops aged-out counters, not live ones",
          len(survivors) == 20 and len(admin_mod._login_attempts) <= 100,
          f"{len(survivors)} of 20 live counters survived, "
          f"table is {len(admin_mod._login_attempts)}")

    # And the lockout still locks out.
    admin_mod._login_attempts.clear()
    for _ in range(admin_mod.LOGIN_MAX_ATTEMPTS):
        admin_mod._record_attempt("a:203.0.113.9")
    check("an address that used its attempts is still rate limited",
          admin_mod._rate_limited("a:203.0.113.9"))
finally:
    admin_mod._ATTEMPTS_SOFT_CAP = _saved_cap
    admin_mod._login_attempts.clear()
    admin_mod._login_attempts.update(_saved_hits)


# --------------------------------------------------------------------------
# The request path is a secret. Two routes carry one:
#
#   DELETE /api/v1/devices/{pubkey}          the customer's WireGuard key
#   GET    /api/v1/payment/{invoice_id}/…    a bearer capability
#
# uvicorn's access line is the path, so at --log-level info the key went
# into journald percent-encoded, and stayed the seven days MaxRetentionSec
# keeps — while web/privacy.html said device keys never appear in our
# application logs. The audit pack's own api-log-no-pubkeys check could not
# see it: it matched the JSON shape "pubkey": "…", which is the one place
# the key is never logged, because bodies are not.
#
# This runs the stack twice. Once with the access log on, to prove the leak
# is real and not a story about a flag; once with it off, the way
# 0trust-api.service ships, to prove the flag is what closes it.
# --------------------------------------------------------------------------
print("\n[logs] the request path never reaches the journal")
import urllib.parse

def _pubkey_with(chars):
    """A valid 44-char WireGuard pubkey containing every character in `chars`.

    H.genkey() draws at random, and about half of all keys happen to contain
    a '/'. That mattered: urllib re-normalises the path it is handed, so a
    '/' this test carefully encoded as %2F arrives at the server as a bare
    '/' while a '+' stays %2B — one line, two different encodings. The
    original check looked for quote(key, safe="") and therefore missed
    exactly the keys with a slash in them, which is a coin flip per run:
    green alone, red in CI, for a reason the output never stated. Same
    family as the admin-search bug in CLAUDE.md's list. Construct the
    property instead of hoping for it.
    """
    for _ in range(20000):
        k = base64.b64encode(os.urandom(32)).decode()
        if all(c in k for c in chars) and not any(
                c in k for c in set("+/") - set(chars)):
            return k
    raise AssertionError(f"could not build a pubkey containing {chars!r}")


def _exercise(access_log, pub):
    """Boot, delete a device and poll an invoice, return (log, invoice)."""
    H.boot(DB, workers=1, log_level="info", access_log=access_log)
    try:
        tok, inv = H.paid_account(1)
        hdr = {"X-Account-Token": tok}
        st, _ = H.call("POST", "/api/v1/wg/register",
                       {"pubkey": pub, "device_name": "laptop", "region": "zur"}, hdr)
        assert st == 200, st
        st, _ = H.call("DELETE", "/api/v1/devices/" + urllib.parse.quote(pub, safe=""),
                       None, hdr)
        assert st == 200, st
        H.call("GET", f"/api/v1/payment/{urllib.parse.quote(inv, safe='')}/status")
        time.sleep(0.8)
    finally:
        H.shutdown()
    return open(f"{H.RUN}/api.log").read(), inv


def _leaked(log, pub, inv):
    """Is the key or the capability in the log, in ANY encoding?

    Decode the log rather than encode the needle: one line can mix raw and
    percent-encoded characters, so there is no single encoding of the key to
    search for. unquote() collapses every variant to the same string.
    """
    plain = urllib.parse.unquote(log)
    return [n for n, v in (("pubkey", pub), ("invoice id", inv))
            if v in log or v in plain]

try:
    # Both encodings of the awkward characters, in one key.
    pub = _pubkey_with("+/")

    leaky, inv_a = _exercise(access_log=True, pub=pub)
    # Not an assertion about the product — an assertion about this test. If
    # the access log stops carrying the path, the check below proves nothing
    # and should say so rather than passing for free.
    check("with the access log on, the path really does leak (control)",
          _leaked(leaky, pub, inv_a) == ["pubkey", "invoice id"],
          f"leaked={_leaked(leaky, pub, inv_a)}; the control case no longer "
          f"reproduces, so the case below has nothing to prove")

    quiet, inv_b = _exercise(access_log=False, pub=pub)
    check("as shipped, no device pubkey or invoice id in the API log",
          not _leaked(quiet, pub, inv_b),
          f"leaked={_leaked(quiet, pub, inv_b)}\n{quiet[-1200:]}")
    check("the log is still useful — startup is reported",
          "Application startup complete" in quiet, quiet[-600:])

    # The audit pack's grep has to see the same line this test just proved is
    # there. That is the specific thing that failed before: the check looked
    # for a JSON shape and the leak was a URL, so it reported green on a
    # leaking host. Run the shipped regex against the shipped leak.
    import re as _re
    pat = _re.compile(r"([A-Za-z0-9]|%2[BbFf]|[+/]){43}(=|%3[Dd])")
    check("audit-verify's pubkey regex matches the real leaked line",
          bool(pat.search(leaky)),
          "the grep in scripts/audit-verify.sh cannot see a leak this test "
          "can — that is how the last one went unnoticed for months")
    check("and it does not fire on the clean log",
          not pat.search(quiet), pat.search(quiet).group(0) if pat.search(quiet) else "")
finally:
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
