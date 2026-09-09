#!/usr/bin/env python3
"""Drive the REAL compiled 0trust binary against the live stack."""
import json, os, re, shutil, sqlite3, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS, SKIP = [], [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

def skip(n, why):
    SKIP.append(n)
    print(f"  SKIP  {n} ({why})")

# `0trust connect` refuses to run without euid 0, and rightly so: it creates a
# network interface. The netlink side is stubbed here, but that check is real
# product behaviour we are not going to weaken for a test, so the tunnel path
# only runs when the suite itself has root. CI does not, which is why every
# connect-dependent assertion used to fail there while passing locally.
ROOT = os.geteuid() == 0
NEEDS_ROOT = "needs root; the client refuses to touch netlink without it"

EMU  = os.path.dirname(os.path.abspath(__file__))
TMP  = H.tempdir("0trust-cli-")
DB   = os.path.join(TMP, "0trust.db")
HOME = os.path.join(TMP, "home"); os.makedirs(HOME)
BIN  = os.path.join(TMP, "0trust")

sys.path.insert(0, os.path.join(H.REPO, "api"))
os.environ["ZTV_DB_PATH"] = DB
import main as api_main; api_main.init_db()
H.seed_nodes(DB)

subprocess.run(["go", "build", "-o", BIN, "./cmd/0trust"],
               cwd=os.path.join(H.REPO, "client"), check=True,
               env={**os.environ, "CGO_ENABLED": "0"})
H.boot(DB, workers=2)

CLI_ENV = {
    **os.environ,
    "HOME": HOME,
    "XDG_CONFIG_HOME": os.path.join(HOME, ".config"),
    "ZTV_API_BASE": H.API,
    "PATH": os.path.join(EMU, "bin") + ":" + os.environ["PATH"],
    "STUB_LOG": os.path.join(TMP, "stub.log"),
    "STUB_STATE": TMP,
    # Keep the real binary's config writes inside the temp dir. Without this
    # the suite writes into the host's /etc/wireguard when run as root.
    "ZTV_WG_CONFIG_DIR": TMP,
}

def cli(*args, stdin=None, env=None):
    r = subprocess.run([BIN, *args], env={**CLI_ENV, **(env or {})},
                       capture_output=True, text=True, input=stdin, timeout=90)
    return r.returncode, (r.stdout + r.stderr)

try:
    print("[1] login / status")
    token, _ = H.paid_account(3)
    rc, out = cli("login", stdin=token + "\n")
    check("login accepts the token", rc == 0, out)
    rc, out = cli("status")
    check("status shows active subscription", rc == 0 and "active" in out, out)
    check("status shows days remaining", "89" in out or "90" in out or "days" in out, out)

    # help.html tells customers `0trust status` will say which they have, so
    # it has to actually say it.
    check("status reports the IPv6 situation", "ipv6" in out.lower(), out)
    check("status reports the kill switch", "kill switch" in out.lower(), out)
    check("status shows the paid device cap", "/ 8" in out, out)

    # The cap is per-plan, and the CLI used to print a constant 8. A trial
    # customer with a cap of 2 was told they had six devices spare, and found
    # out otherwise when the next register returned 409. The GUI reads
    # max_devices off the same response; so must this.
    c = sqlite3.connect(DB)
    c.execute("UPDATE accounts SET plan = 'trial' WHERE plan != 'trial'")
    c.commit(); c.close()
    rc, out = cli("status")
    check("a trial account is shown the TRIAL device cap, not the paid one",
          "/ 2" in out and "/ 8" not in out, out)
    c = sqlite3.connect(DB)
    c.execute("UPDATE accounts SET plan = 'paid' WHERE plan = 'trial'")
    c.commit(); c.close()

    # A notice is the ONLY channel this service has — there is no email
    # address on the account. Before this the feature was write-only: the
    # operator dashboard could broadcast and no client on any platform ever
    # displayed one, so a renewal warning reached nobody.
    print("\n[1b] messages from the service reach the customer")
    nc = sqlite3.connect(DB)
    acct_id = nc.execute("SELECT id FROM accounts ORDER BY id DESC LIMIT 1").fetchone()[0]
    nc.execute("""INSERT INTO notices
                  (account_id, severity, subject, body, created_at, expires_at, created_by)
                  VALUES (?, 'warning', 'Your subscription ends in 3 days',
                          'Top up with 0trust topup to keep this account.',
                          ?, 0, 'sweeper:renewal:7')""",
               (acct_id, int(__import__("time").time())))
    nc.commit(); nc.close()

    rc, out = cli("status")
    check("status surfaces a waiting notice", "ends in 3 days" in out, out[-600:])
    check("and its body, not just the subject",
          "0trust topup" in out, out[-600:])

    rc, out = cli("notices")
    check("the notices command lists it", rc == 0 and "ends in 3 days" in out, out)
    rc, out = cli("notices", "--read")
    check("--read clears it", rc == 0 and "marked" in out.lower(), out)
    rc, out = cli("notices")
    check("and it stays cleared", "no unread messages" in out, out)
    rc, out = cli("status")
    check("status is quiet once nothing is waiting",
          "ends in 3 days" not in out, out[-400:])

    print("\n[2] regions")
    rc, out = cli("regions")
    check("regions lists zur/rey/buc",
          rc == 0 and all(r in out for r in ("zur", "rey", "buc")), out)

    if not ROOT:
        print("\n[3] connect without root — the refusal itself")
        # Worth asserting rather than skipping: a customer who forgets sudo
        # should get a usable instruction, not a stack trace or a silent no-op.
        rc, out = cli("connect", "zur")
        check("connect without root fails", rc != 0, out)
        check("and tells you to use sudo", "sudo" in out.lower(), out)
        rc, out = cli("devices")
        check("devices still works unprivileged", rc == 0, out)
        check("and reports none registered", "no devices" in out, out)
        for name in ("second connect does not 500", "multi-hop connect + rotate",
                     "device removal and reconnect", "disconnect"):
            skip(name, NEEDS_ROOT)
    else:
        print("\n[3] connect (single-hop) — the real binary, stubbed netlink")
        rc, out = cli("connect", "zur")
        check("first connect succeeds", rc == 0, out)
        check("wrote a wg config", "config written" in out, out)

        # `wg-quick up` configures an interface and returns; it never talks to
        # the node. Reporting success on its exit code told the user they were
        # protected whether or not anything got through — and since AllowedIPs
        # captures the default route, the symptom is "my internet broke".
        check("connect reports a verified handshake",
              "handshake" in out and "✓" in out, out)

        print("\n[3b] a node that never answers must not be reported as working")
        rc, out = cli("connect", "zur", env={"STUB_NO_HANDSHAKE": "1"})
        check("connect exits non-zero when no handshake arrives", rc != 0, out)
        check("and says the tunnel is not carrying traffic",
              "NOT carrying traffic" in out, out)
        # Leaving the interface up is deliberate: it still holds the default
        # route, so traffic is dropped instead of leaking in the clear.
        check("it explains that traffic is dropped, not leaked",
              "dropped rather than leaking" in out, out)
        check("and tells the user how to get back online",
              "0trust disconnect" in out, out)
        check("and suggests what usually causes it",
              "UDP is blocked" in out, out)

        print("\n[3c] the kill switch is off unless asked for, and sticky once asked")
        rc, out = cli("connect", "zur")
        cfg_path = os.path.join(TMP, "0trust0.conf")
        check("the client wrote its config where we told it to",
              os.path.exists(cfg_path), sorted(os.listdir(TMP)))
        conf = open(cfg_path).read()
        check("no kill-switch rules by default", "PostUp" not in conf, conf[:300])
        rc, out = cli("connect", "zur", "--kill-switch")
        check("--kill-switch succeeds", rc == 0, out)
        conf = open(cfg_path).read()
        check("kill-switch rules are written", "PostUp = iptables" in conf, conf[:400])
        check("PreDown cannot fail and strand the user",
              all(l.endswith("|| true")
                  for l in conf.splitlines() if l.startswith("PreDown")), conf[:400])
        check("the client says the local network is blocked too",
              "including your local network" in out, out)
        # A safety setting that turns itself off because you did not repeat
        # the flag is not a safety setting.
        rc, out = cli("connect", "zur")
        conf = open(cfg_path).read()
        check("the setting sticks across a plain reconnect",
              "PostUp = iptables" in conf, conf[:400])
        rc, out = cli("connect", "zur", "--no-kill-switch")
        conf = open(cfg_path).read()
        check("--no-kill-switch turns it back off", "PostUp" not in conf, conf[:400])

        print("\n[4] SECOND connect — the bug that used to 500")
        rc2, out2 = cli("connect", "zur")
        check("second connect succeeds", rc2 == 0, out2)
        check("second connect is not an api 500", "api 500" not in out2, out2)

        print("\n[5] multi-hop connect + rotate")
        rc, out = cli("connect", "zur", "--exit", "buc")
        check("multi-hop connect succeeds", rc == 0, out)
        check("reports entry and exit nodes",
              "entry=zur" in out and "exit=buc" in out, out)
        rc, out = cli("rotate")
        check("rotate succeeds", rc == 0, out)

        print("\n[6] devices / remove (new commands)")
        rc, out = cli("devices")
        check("devices lists this device", rc == 0 and "* " in out, out)
        check("device slot count shown", "of 8 device slots" in out, out)
        rc, out = cli("remove", "this")
        check("remove this device succeeds", rc == 0 and "removed" in out, out)
        rc, out = cli("devices")
        check("device list now empty", rc == 0 and "no devices" in out, out)
        rc, out = cli("connect", "zur")
        check("can reconnect after removal (fresh key)", rc == 0, out)

    print("\n[7] export for mobile")
    rc, out = cli("export", "--exit", "buc", "--name", "phone", "--out", TMP)
    check("export succeeds", rc == 0, out)
    check("wrote a .conf", os.path.exists(os.path.join(TMP, "phone.conf")), os.listdir(TMP))
    if os.path.exists(os.path.join(TMP, "phone.conf")):
        conf = open(os.path.join(TMP, "phone.conf")).read()
        check("conf has Interface + Peer", "[Interface]" in conf and "[Peer]" in conf, conf[:300])
        check("conf carries a private key", "PrivateKey" in conf, conf[:300])

    print("\n[8] disconnect / logout")
    if ROOT:
        rc, out = cli("disconnect")
        check("disconnect succeeds", rc == 0, out)
    rc, out = cli("logout")
    check("logout succeeds", rc == 0, out)
    rc, out = cli("status")
    check("status after logout tells you to log in",
          "not logged in" in out.lower(), out)

    print("\n[9] error paths")
    rc, out = cli("login", stdin="AAAA-BBBB-CCCC-DDDD\n")
    check("bogus token rejected at login", rc != 0 or "401" in out or "Invalid" in out, out)
    print("\n[10] topup — the command the service tells every customer to run")
    # The bogus-token login above left this client logged out; log the real
    # account back in before asking it to pay for anything.
    rc, out = cli("login", stdin=token + "\n")
    check("logged back in for the payment checks", rc == 0, out[-200:])
    # api/sweep.py's renewal warning and expiry notice both say
    # `0trust topup`, and web/trial.html advertises it. The command did not
    # exist. Every customer approaching expiry was given one instruction, at
    # the moment they were trying to hand over money, and it was wrong.
    rc, out = cli("topup")
    check("topup with no months explains rather than erroring blankly",
          "how many months" in out, out[-300:])

    rc, out = cli("topup", "1")
    check("topup opens an invoice", rc == 0 and "invoice" in out.lower(),
          out[-500:])
    check("and prints an amount that matches PRICING",
          "$5.00" in out, out[-400:] + "\n  the CLI must not quote a price the "
          "API does not charge")
    check("it shows the current expiry so a customer can see months STACK",
          "stack on top" in out, out[-400:])
    m = re.search(r"invoice (\S+) —", out)
    check("the invoice id is printed so it can be checked later", bool(m), out[-300:])
    check("and an address to pay is shown, not just a URL",
          "address" in out.lower(), out[-500:])

    if m:
        inv = m.group(1)
        rc, out2 = cli("topup", "--status", inv)
        check("--status reports that invoice", rc == 0 and inv in out2, out2[-300:])
        # The sharp one: a customer checking on a payment must not open a
        # SECOND invoice by doing so.
        before = int(sqlite3.connect(DB).execute(
            "SELECT COUNT(*) FROM invoices").fetchone()[0])
        cli("topup", "--status", inv)
        after = int(sqlite3.connect(DB).execute(
            "SELECT COUNT(*) FROM invoices").fetchone()[0])
        check("checking status does NOT open another invoice", before == after,
              f"{before} -> {after}")

    # An unpaid top-up must not extend anything.
    exp_before = sqlite3.connect(DB).execute(
        "SELECT expires_at FROM accounts ORDER BY id DESC LIMIT 1").fetchone()[0]
    cli("topup", "12")
    exp_after = sqlite3.connect(DB).execute(
        "SELECT expires_at FROM accounts ORDER BY id DESC LIMIT 1").fetchone()[0]
    check("opening an invoice does not extend the account before payment",
          exp_before == exp_after, f"{exp_before} -> {exp_after}")

    # THE ONE THAT DECIDES WHETHER A LAPSED CUSTOMER COMES BACK. An expired
    # account must still be able to pay. The endpoint takes require_account,
    # not require_active_account, and if that ever changes the customer is
    # locked out of the only action that would fix their account — with the
    # expiry notice still telling them to take it.
    conn = sqlite3.connect(DB)
    conn.execute("UPDATE accounts SET expires_at = ?, status = 'expired' "
                 "WHERE token_hash = ?",
                 (int(__import__("time").time()) - 86400,
                  __import__("hashlib").sha256(
                      token.replace("-", "").upper().encode()).hexdigest()))
    conn.commit(); conn.close()

    rc, out = cli("status")
    check("the account now reads as expired", "expired" in out.lower(), out[-300:])
    rc, out = cli("topup", "1")
    check("an EXPIRED customer can still open an invoice to come back",
          rc == 0 and "invoice" in out.lower(),
          out[-500:] + "\n  if this fails the customer is locked out of the "
          "one action that would fix their account, while the expiry notice "
          "goes on telling them to take it")

    # And an invoice is not a payment: routing must still be refused. Listing
    # devices is NOT the thing to assert on — that stays available on purpose,
    # so a lapsed customer can still see and free up their device slots. What
    # must be refused is being given a tunnel, which is require_active_account
    # rather than require_account.
    st, body = H.call("POST", "/api/v1/wg/register",
                      {"pubkey": H.genkey(), "device_name": "after-expiry",
                       "region": "zur"},
                      headers={"X-Account-Token": token})
    check("an unpaid invoice does not restore routing", st == 402, (st, body))
    rc, out = cli("devices")
    check("but a lapsed customer can still manage their devices", rc == 0,
          out[-300:] + "\n  they may need to free a slot before paying")

    # The help has to name it, or nobody finds it from the terminal.
    rc, out = cli("help")
    check("help documents topup", "topup" in out, out[-400:])

finally:
    H.shutdown()
    tail = f", {len(SKIP)} skipped" if SKIP else ""
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed{tail}")
    if SKIP: print("  skipped (no root): " + ", ".join(SKIP))
    if FAIL: print("  failures: " + ", ".join(FAIL))
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if FAIL else 0)
