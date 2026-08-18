#!/usr/bin/env python3
"""
mint-provision-token.py — Issue a one-shot token for ephemeral node bootstrap.

Run on the control plane host. The token is printed to stdout; copy it into
the cloud-init user-data of the node you're about to launch.

Tokens:
  - Are single-use (burned on first /api/v1/node/provision call)
  - Expire 1 hour after issue by default
  - Are restricted to (region, role) so a leaked token can't be used to inject
    a node anywhere else in the mesh

Usage:
  sudo -u 0trust python3 mint-provision-token.py --region zur --role entry
  sudo -u 0trust python3 mint-provision-token.py --region buc --role exit --ttl 7200
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
    args = p.parse_args()

    if not os.path.exists(DB_PATH):
        print(f"DB missing at {DB_PATH}", file=sys.stderr)
        sys.exit(1)

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time())

    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.execute(
        """INSERT INTO provision_tokens
             (token_hash, region, role, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?)""",
        (token_hash, args.region, args.role, now, now + args.ttl),
    )
    conn.close()

    print(f"Token (single-use, valid {args.ttl}s):")
    print()
    print(f"  {token}")
    print()
    print(f"Place this in cloud-init user-data as ZTV_PROVISION_TOKEN.")
    print(f"After first use it cannot be replayed.")


if __name__ == "__main__":
    main()
