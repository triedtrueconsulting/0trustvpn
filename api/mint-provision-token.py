#!/usr/bin/env python3
"""
mint-provision-token.py — Issue a one-shot token for ephemeral node bootstrap.

Run on the control plane host. The token is printed to stdout; copy it into
the cloud-init user-data of the node you're about to launch.

Tokens:
  - Are restricted to (region, role) so a leaked token can't be used to inject
    a node anywhere else in the mesh
  - Are single-use by default: burned on the first /api/v1/node/provision call,
    and expiring an hour after issue

  --uses N mints an ENROLMENT token instead. A node's disk is tmpfs, so a
  reboot loses its WireGuard key and its node id, and a single-use token
  cannot bring it back — the box comes up and never rejoins the mesh. An
  enrolment token pins itself to the first node's public IP on first use and
  re-registers that same node afterwards, so a reboot is a rejoin rather than
  an outage. A copy stolen off the box is inert anywhere else, and the
  dashboard can revoke it.

Usage:
  sudo -u 0trust python3 mint-provision-token.py --region zur --role entry
  sudo -u 0trust python3 mint-provision-token.py --region buc --role exit --ttl 7200

  # a permanent VPS node that must survive reboots
  sudo -u 0trust python3 mint-provision-token.py --region zur --uses 20 --ttl 31536000
"""

import argparse
import hashlib
import os
import secrets
import sqlite3
import sys
import time

DB_PATH = os.environ.get("ZTV_DB_PATH", "/var/lib/0trust/0trust.db")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--region", required=True)
    p.add_argument("--role", required=True, choices=["entry", "exit", "both"])
    p.add_argument("--ttl", type=int, default=3600,
                   help="seconds until token expires (default: 1h)")
    p.add_argument("--uses", type=int, default=1,
                   help="how many nodes it may register (default: 1). "
                        ">1 mints an IP-bound enrolment token that can "
                        "re-register its node after a reboot")
    args = p.parse_args()
    if args.uses < 1:
        print("--uses must be at least 1", file=sys.stderr)
        sys.exit(2)

    if not os.path.exists(DB_PATH):
        print(f"DB missing at {DB_PATH}", file=sys.stderr)
        sys.exit(1)

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time())

    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.execute(
        """INSERT INTO provision_tokens
             (token_hash, region, role, created_at, expires_at, max_uses)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (token_hash, args.region, args.role, now, now + args.ttl, args.uses),
    )
    conn.close()

    kind = "single-use" if args.uses == 1 else f"enrolment, {args.uses} uses"
    print(f"Token ({kind}, valid {args.ttl}s):")
    print()
    print(f"  {token}")
    print()
    print("On the node:")
    print(f"  sudo ./scripts/install.sh --mode node \\")
    print(f"       --control-url https://<control-plane> \\")
    print(f"       --region {args.region} --role {args.role} \\")
    print(f"       --provision-token {token}")
    print()
    if args.uses == 1:
        print("Single-use: after the node registers, this cannot be replayed —")
        print("and the node cannot rejoin after a reboot. Use --uses for that.")
    else:
        print("It binds to the first node's public IP on first use, and is")
        print("stored on that node so a reboot rejoins by itself. Revoke it")
        print("from the dashboard if the box is ever out of your hands.")


if __name__ == "__main__":
    main()
