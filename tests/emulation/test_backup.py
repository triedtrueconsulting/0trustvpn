#!/usr/bin/env python3
"""
Back the control plane up, then restore it and serve customers from it.

docs/DR.md says, in its own words, that a backup you cannot restore from is a
non-backup, and schedules quarterly restore practice. Nothing in this repo had
ever run that practice once. The failure mode is quiet and total: the operator
finds out the loop is broken on the day the host is gone, and every account is
unrecoverable because tokens are stored hashed and cannot be reissued.

So this does the whole loop for real — a live API with real state, an online
snapshot taken while it is serving, age encryption to a throwaway recipient,
the decrypt from DR.md §Scenario 1, and then the same API booted on the
restored file and asked whether a customer's token still works.

Skips (77) without sqlite3 or age.
"""
import os, shutil, subprocess, sqlite3, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

for tool in ("sqlite3", "age", "age-keygen"):
    if not shutil.which(tool):
        print(f"  SKIP  {tool} not installed")
        sys.exit(77)

TMP = H.tempdir("0trust-backup-")
DB = os.path.join(TMP, "0trust.db")
BACKUP_DIR = os.path.join(TMP, "backups")
KEY = os.path.join(TMP, "backup.key")
RECIPIENTS = os.path.join(TMP, "recipients.txt")

os.environ["ZTV_DB_PATH"] = DB
os.environ["ZTV_TRIAL_SECRET"] = "backup-secret"
os.environ["ZTV_TRIAL_POW_BITS"] = "10"
sys.path.insert(0, os.path.join(H.REPO, "api"))
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=2)

# A stand-in for /etc/0trust/api.env. Pointed at a fixture rather than the
# real file: this box may have one from an install run, and a test that reads
# a live credentials file is a test that can leak one.
ENV_FILE = os.path.join(TMP, "api.env")
ENV_BODY = ("NODE_API_PSK=psk-that-must-survive\n"
            "BTCPAY_WEBHOOK_SECRET=webhook-that-must-survive\n"
            "ZTV_TRIAL_SECRET=trial-that-must-survive\n")
open(ENV_FILE, "w").write(ENV_BODY)

BACKUP_ENV = {**os.environ,
              "ZTV_DB_PATH": DB,
              "ZTV_BACKUP_DIR": BACKUP_DIR,
              "ZTV_ENV_PATH": ENV_FILE,
              "ZTV_AGE_RECIPIENTS": RECIPIENTS}


def run(cmd, env=None, **kw):
    return subprocess.run(cmd, cwd=H.REPO, env=env or BACKUP_ENV,
                          capture_output=True, text=True, timeout=300, **kw)


try:
    print("[1] a control plane with state worth losing")
    token, _ = H.paid_account(months=3)
    hdr = {"X-Account-Token": token}
    pub = H.genkey()
    st, reg = H.call("POST", "/api/v1/wg/register", headers=hdr, body={
        "pubkey": pub, "device_name": "laptop", "region": "zur",
        "exit_region": "rey"})
    check("a paying customer with a multi-hop device", st == 200, reg)
    mesh_ip = reg.get("interface_ip")
    st, before = H.call("GET", "/api/v1/account/status", headers=hdr)
    check("account is active", st == 200 and before["status"] == "active", before)
    expiry_before = before["expires_at"]

    print("\n[2] age recipient, as the runbook has the operator create one")
    r = run(["age-keygen", "-o", KEY])
    check("keypair generated", r.returncode == 0, r.stderr[-300:])
    # age-keygen writes "# public key: age1..." into the key file and prints a
    # similar line on stderr; the file is the reliable one.
    pubkey = next((l.split(":", 1)[1].strip() for l in open(KEY)
                   if "public key" in l.lower()), "")
    check("public key parsed", pubkey.startswith("age1"), pubkey)
    open(RECIPIENTS, "w").write(pubkey + "\n")

    print("\n[3] backup.sh, against a database that is being served")
    # The whole reason for sqlite3 .backup over `cp`: the API is live and the
    # WAL is moving underneath it.
    st, _ = H.call("GET", "/api/v1/status/public")
    r = run(["./scripts/backup.sh"])
    check("backup.sh succeeds", r.returncode == 0,
          (r.stdout[-500:] + r.stderr[-500:]))

    dailies = sorted(os.listdir(os.path.join(BACKUP_DIR, "daily")))
    dbs = [f for f in dailies if f.endswith(".db.age")]
    envs = [f for f in dailies if f.endswith(".env.age")]
    check("one encrypted database written", len(dbs) == 1, dailies)
    archive = os.path.join(BACKUP_DIR, "daily", dbs[0]) if dbs else None

    # The database alone does not bring the service back. docs/DR.md step 6
    # restores api.env, and it used to tell the operator to keep their own
    # copy off-host — a manual step, forever, on the one path where manual
    # steps fail. Without it the restored control plane cannot authenticate
    # a node (NODE_API_PSK) or verify a payment webhook
    # (BTCPAY_WEBHOOK_SECRET): the database comes back and the service does
    # not.
    check("and the environment file beside it", len(envs) == 1, dailies)
    if envs:
        env_arc = os.path.join(BACKUP_DIR, "daily", envs[0])
        head = open(env_arc, "rb").read(32)
        check("the env backup is encrypted too",
              head.startswith(b"age-encryption.org"),
              "these are the service's secrets; a cleartext copy of them in "
              "the backup directory is worse than not having one")
        out = os.path.join(TMP, "env-restored")
        r2 = run(["age", "-d", "-i", KEY, "-o", out, env_arc])
        check("it decrypts with the backup key", r2.returncode == 0, r2.stderr)
        if os.path.exists(out):
            body = open(out).read()
            check("and every secret came back",
                  all(k in body for k in ("psk-that-must-survive",
                                          "webhook-that-must-survive",
                                          "trial-that-must-survive")),
                  body[:200])

    if archive:
        head = open(archive, "rb").read(32)
        check("the backup is encrypted, not a bare SQLite file",
              not head.startswith(b"SQLite format"),
              "an unencrypted database copy is the finding audit-verify.sh "
              "exists to catch")
        check("it is an age file", head.startswith(b"age-encryption.org"),
              head[:24])

    leftovers = [f for f in os.listdir(BACKUP_DIR) if f.startswith(".snap-")]
    check("the cleartext snapshot was shredded, not left behind",
          not leftovers, leftovers)

    print("\n[3a] a failed backup leaves no cleartext behind")
    # `set -e` used to walk out of the script between the snapshot and the
    # shred, so any failure — bad recipients file, full disk, age missing —
    # left a full unencrypted copy of every account on disk, produced by the
    # backup job itself. That is the finding audit-verify.sh exists to catch.
    bad = os.path.join(TMP, "empty-recipients.txt")
    open(bad, "w").write("")
    r = run(["./scripts/backup.sh"], env={**BACKUP_ENV, "ZTV_AGE_RECIPIENTS": bad})
    check("backup.sh fails on an unusable recipients file", r.returncode != 0,
          r.stdout[-300:])
    leftovers = [f for f in os.listdir(BACKUP_DIR) if f.startswith(".snap-")]
    check("and still leaves no cleartext snapshot", not leftovers,
          f"{leftovers} — an unencrypted copy of the customer database")

    print("\n[3b] a backup with no environment file says so")
    # Silently backing up half of what a restore needs is the failure this
    # whole change is about. If the file is not where we looked, the run has
    # to say which secrets are missing from the set.
    r = run(["./scripts/backup.sh"],
            env={**BACKUP_ENV, "ZTV_ENV_PATH": os.path.join(TMP, "nope.env")})
    check("the run still succeeds", r.returncode == 0, r.stderr[-300:])
    out = (r.stdout + r.stderr).lower()
    check("and warns that the backup is incomplete",
          "warning" in out and "not take payments" in out,
          r.stdout[-400:])

    print("\n[4] rotation keeps what it says it keeps")
    # Nine more runs; the script promises 7 dailies. Timestamps are
    # second-resolution, so space them out enough to get distinct names.
    for _ in range(9):
        time.sleep(1.05)
        run(["./scripts/backup.sh"])
    dailies = os.listdir(os.path.join(BACKUP_DIR, "daily"))
    dbs = sorted(f for f in dailies if f.endswith(".db.age"))
    envs = sorted(f for f in dailies if f.endswith(".env.age"))
    # Per ARTIFACT, not per file. Rotation counted files, and once a second
    # artifact appeared per run that would silently have halved every window:
    # seven files is three and a half days, not seven — a regression that
    # shows up as "the backup I wanted is gone" and never as an error.
    check("daily rotation keeps 7 databases", len(dbs) == 7,
          f"{len(dbs)} of {len(dailies)} files")
    check("and 7 environment files", len(envs) == 7,
          f"{len(envs)} of {len(dailies)} files")
    newest = dbs[-1]
    archive = os.path.join(BACKUP_DIR, "daily", newest)

    print("\n[5] the restore from DR.md, step for step")
    H.shutdown()                       # "systemctl stop 0trust-api"
    restored = os.path.join(TMP, "restored.db")
    r = run(["age", "-d", "-i", KEY, "-o", restored, archive])
    check("age decrypts the backup", r.returncode == 0, r.stderr[-400:])
    check("and the result is a SQLite database",
          open(restored, "rb").read(16).startswith(b"SQLite format"))

    # Integrity, before trusting anything in it.
    r = subprocess.run(["sqlite3", restored, "PRAGMA integrity_check;"],
                       capture_output=True, text=True, timeout=120)
    check("integrity_check passes", r.stdout.strip() == "ok", r.stdout[:200])

    print("\n[6] the restored database serves the same customers")
    shutil.copy(restored, DB)          # "> /var/lib/0trust/0trust.db"
    H.boot(DB, workers=2)              # "systemctl start 0trust-api"

    st, after = H.call("GET", "/api/v1/account/status", headers=hdr)
    check("the customer's token still authenticates", st == 200, after)
    if st == 200:
        check("still active", after["status"] == "active", after)
        # The point CLAUDE.md makes about the audit pack: a token on its own
        # cannot rebuild an expiry date. If the backup does not carry it, the
        # customer's remaining months are gone even though they can log in.
        check("the subscription expiry survived",
              after["expires_at"] == expiry_before,
              f"{expiry_before} -> {after.get('expires_at')}")
        check("the device count survived",
              after["device_count"] == before["device_count"],
              f"{before['device_count']} -> {after.get('device_count')}")

    st, devs = H.call("GET", "/api/v1/devices", headers=hdr)
    check("the device list survived", st == 200 and len(devs) == 1, devs)
    if st == 200 and devs:
        # register returns the interface address with its /32; the device list
        # returns the bare address. Same allocation, two representations.
        check("with the same mesh IP",
              devs[0]["mesh_ip"] == mesh_ip.split("/")[0],
              f"{mesh_ip} -> {devs[0]['mesh_ip']}")
        check("and its multi-hop pair", devs[0]["multihop"] is True, devs[0])

    # Re-presenting the same key must still be idempotent after a restore —
    # otherwise every customer's first reconnect burns a device slot.
    st, again = H.call("POST", "/api/v1/wg/register", headers=hdr, body={
        "pubkey": pub, "device_name": "laptop", "region": "zur",
        "exit_region": "rey"})
    check("reconnecting after a restore reuses the device",
          st == 200 and again["interface_ip"] == mesh_ip,
          f"{mesh_ip} -> {again.get('interface_ip')}")

    print("\n[7] the runbook names what it takes to do this")
    dr = open(os.path.join(H.REPO, "docs", "DR.md")).read()
    for needed in ("age -d", "0trust-api", "integrity_check"):
        check(f"DR.md mentions {needed!r}", needed in dr,
              "the restore this module just performed is not written down")

finally:
    H.shutdown()

print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
