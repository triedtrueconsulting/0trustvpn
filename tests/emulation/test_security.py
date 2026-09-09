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

    # The two fields BESIDE solution were unbounded while it was capped, which
    # is the shape of an oversight rather than a decision. This is the only
    # unauthenticated endpoint that takes a body, and _sign_challenge HMACs
    # the nonce — so an over-long one was hashed before anything questioned
    # it. Both are now pinned to the exact shape the server issues.
    for field, bad, why in (
            ("nonce", "f" * 100000, "a megabyte-scale nonce"),
            ("nonce", "zz" * 16, "32 characters that are not hex"),
            ("nonce", "f" * 31, "one hex digit short"),
            ("signature", "a" * 100000, "an enormous signature"),
            ("signature", "a" * 63, "one hex digit short"),
            ("signature", "A" * 64, "upper-case hex the server never emits"),
    ):
        payload = {"nonce": ch3["nonce"], "expires_at": ch3["expires_at"],
                   "signature": ch3["signature"], "solution": "0"}
        payload[field] = bad
        stx, rx = H.call("POST", "/api/v1/trial", payload)
        check(f"{why} is refused by the schema, not the handler",
              stx == 422, f"{stx} {str(rx)[:200]}")

    # ...and the well-formed request is still accepted, so the patterns are
    # not simply refusing everything.
    st6, ch6 = H.call("GET", "/api/v1/trial/challenge")
    st7, r7 = H.call("POST", "/api/v1/trial", {
        "nonce": ch6["nonce"], "expires_at": ch6["expires_at"],
        "signature": ch6["signature"], "solution": solve(ch6["nonce"], 10)})
    check("a genuine challenge still redeems", st7 == 200, f"{st7} {r7}")

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

    # A node holding its OWN per-node PSK must not be able to read another
    # node's peers or its live DNAT table (which exposes every multi-hop
    # session's exit endpoint) by naming a different node_id. The shared PSK
    # is the legacy trust boundary; a per-node credential is scoped to itself.
    # Mint a per-node PSK for rey-01 and try to read buc-01 through it.
    import hashlib as _h, sqlite3 as _sql, os as _os
    rey_psk = "rey-secret-" + _os.urandom(6).hex()
    _c = _sql.connect(DB)
    _c.execute("UPDATE mesh_nodes SET psk_hash=? WHERE id=?",
               (_h.sha256(rey_psk.encode()).hexdigest(), "rey-01"))
    _c.commit(); _c.close()
    st, r = H.call("GET", "/api/v1/wg/peers?node_id=buc-01",
                   headers={"X-Node-Psk": rey_psk})
    check("a per-node PSK cannot read another node's peers", st == 403, f"{st} {r}")
    st, r = H.call("GET", "/api/v1/wg/forwards?node_id=buc-01",
                   headers={"X-Node-Psk": rey_psk})
    check("a per-node PSK cannot read another node's forwards", st == 403, f"{st} {r}")
    st, r = H.call("GET", "/api/v1/wg/forwards?node_id=rey-01",
                   headers={"X-Node-Psk": rey_psk})
    check("but it can read its own forwards", st == 200, f"{st} {r}")
    st, r = H.call("GET", "/api/v1/wg/peers?node_id=buc-01",
                   headers={"X-Node-Psk": "totally-wrong-psk"})
    check("an invalid node credential is refused outright", st == 401, f"{st} {r}")

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

    # A device pubkey becomes a line in a WireGuard config that `wg syncconf`
    # parses AS ROOT on the exit node. The guard used to be length-only, so 44
    # characters carrying a newline and a wg directive fragment passed — and
    # since syncconf is atomic and meshd runs it with check=True, one such
    # device broke peer sync for EVERY customer on that node. These are the
    # shapes that must never reach the node: each is 44 chars (or close) but
    # not a real base64-encoded 32-byte key.
    import base64 as _b64
    for label, pk in (
        ("a newline mid-key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nListenPort=1"),
        ("spaces and brackets", ("[Peer]PublicKey= AllowedIPs=0/0 " + "A" * 44)[:44]),
        ("44 chars of non-base64", "!!!!" + "A" * 39 + "="),
        ("valid base64 but 16 bytes, not 32", _b64.b64encode(b"x" * 16).decode()),
    ):
        st, r = H.call("POST", "/api/v1/wg/register",
                       {"pubkey": pk, "device_name": "d", "region": "zur"},
                       headers={"X-Account-Token": tokA})
        check(f"pubkey rejected at ingest: {label}", st == 422, f"{st} {r}")
    # The node's own pubkey and public_ip flow into wg configs and an nft
    # ruleset loaded as root; both are validated at /node/provision too.
    ptok = H.mint_provision_token(DB, "zur", "both")
    st, r = H.call("POST", "/api/v1/node/provision",
                   {"pubkey": H.genkey(), "public_ip": "1.2.3.4; nft flush ruleset",
                    "region": "zur", "role": "both", "wg_port": 51820},
                   headers={"X-Provision-Token": ptok})
    check("a node public_ip that is not a literal IP is rejected", st == 422, f"{st} {r}")
    # And a real device key still registers, so the guard is not just refusing
    # everything.
    st, r = H.call("POST", "/api/v1/wg/register",
                   {"pubkey": H.genkey(), "device_name": "real", "region": "zur"},
                   headers={"X-Account-Token": tokA})
    check("a genuine WireGuard key still registers", st == 200, f"{st} {r}")

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
        enc_pub = urllib.parse.quote(pub, safe="")
        st, _ = H.call("DELETE", "/api/v1/devices/" + enc_pub, None, hdr)
        assert st == 200, st
        H.call("GET", f"/api/v1/payment/{urllib.parse.quote(inv, safe='')}/status")
        # uvicorn flushes its access log asynchronously, so a fixed sleep races
        # the flush — the control assertion then intermittently sees the
        # invoice line but not the (later) delete line, and fails for a reason
        # that has nothing to do with what it tests. Wait for the delete line
        # to land, up to a bound; the quiet case has no line to wait for, so
        # it just spends the bound and returns (which is correct — it is
        # asserting ABSENCE).
        deadline = time.time() + 5.0
        while time.time() < deadline:
            try:
                blob = open(f"{H.RUN}/api.log").read()
            except FileNotFoundError:
                blob = ""
            if not access_log or "/api/v1/devices/" in blob:
                break
            time.sleep(0.1)
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

    def _shipped_regex(check_id):
        """The pattern scripts/audit-verify.sh actually greps with.

        Not a copy of it. A test carrying its own copy proves the copy works
        and says nothing about the deployed script, which is the drift that
        let the old pubkey check sit green for months — so read the bytes
        that ship. The `\\b` in the file is a bash double-quoted escape;
        one round of unescaping gives the regex the shell hands to grep.
        """
        root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
        src = open(os.path.join(root, "scripts", "audit-verify.sh")).read()
        cur, found = None, {}
        for line in src.splitlines():
            m = _re.match(r"\s*check\s+(\S+)\s", line)
            if m:
                cur = m.group(1)
            g = _re.search(r"grep -oE '(.*)'\s*\\?\s*$", line)
            if g and cur and cur not in found:
                found[cur] = g.group(1).replace("\\\\", "\\")
        assert check_id in found, (
            f"no grep -oE found under `check {check_id}` in audit-verify.sh — "
            f"the extractor has drifted from the script and this test would "
            f"otherwise prove nothing")
        return _re.compile(found[check_id])

    pat = _shipped_regex("api-log-no-pubkeys")
    check("audit-verify's pubkey regex matches the real leaked line",
          bool(pat.search(leaky)),
          "the grep in scripts/audit-verify.sh cannot see a leak this test "
          "can — that is how the last one went unnoticed for months")
    check("and it does not fire on the clean log",
          not pat.search(quiet), pat.search(quiet).group(0) if pat.search(quiet) else "")

    # ------------------------------------------------------------------
    # Its sibling, api-log-no-tokens, had no such test at all: nothing had
    # ever run that regex against a real account token. It could not have
    # seen one in the spelling a client now sends, either — hash_token()
    # strips the separators before hashing, so the CLI, the GUI, the iOS app
    # and the Android app all forward a dashless paste as-is, and the check
    # matched only XXXX-XXXX-XXXX-XXXX. Its comment also called the alphabet
    # Crockford base32, which it is not (Crockford drops L and U; these
    # tokens use them) — a comment that invites exactly the "fix" that would
    # blind it to two tokens in three.
    #
    # No route puts a token in a URL, so there is no leak to reproduce the
    # way the pubkey case does. What is testable, and what actually failed
    # before, is the matcher: mint real tokens, spell them every way the
    # server accepts, and require the shipped regex to see each one.
    # ------------------------------------------------------------------
    tok_pat = _shipped_regex("api-log-no-tokens")

    H.boot(DB, workers=1)
    try:
        minted = [H.paid_account(1)[0] for _ in range(8)]
        # An L and a U are in the alphabet but not in Crockford's. Draw until
        # one turns up rather than trusting the draw (bug class #13): with
        # eight tokens the chance of none is under one in a thousand, but
        # "under one in a thousand" is how #13 reads in CI.
        for _ in range(200):
            if any("L" in t or "U" in t for t in minted):
                break
            minted.append(H.paid_account(1)[0])
        else:
            raise AssertionError("no token with an L or a U in 200 draws")
    finally:
        H.shutdown()

    misses = []
    for t in minted:
        bare = t.replace("-", "")
        for label, spelling in (
                ("canonical", t),
                ("dashless", bare),
                ("mixed", bare[:4] + "-" + bare[4:12] + "-" + bare[12:]),
        ):
            line = f'INFO: something logged the token {spelling} by mistake'
            if not tok_pat.search(line):
                misses.append(f"{label}:{spelling}")
    check("audit-verify's token regex sees a real token in every spelling "
          "a client can send",
          not misses, f"invisible to the check: {misses}")

    awkward = [t for t in minted if "L" in t or "U" in t]
    check("...including the letters Crockford drops and this alphabet keeps",
          bool(awkward) and all(tok_pat.search(t) for t in awkward),
          f"L/U tokens the regex could not see: "
          f"{[t for t in awkward if not tok_pat.search(t)]}")

    check("and it does not fire on the clean API log",
          not tok_pat.search(quiet),
          tok_pat.search(quiet).group(0) if tok_pat.search(quiet) else "")
finally:
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
