#!/usr/bin/env python3
"""
Monero payments, without running a Monero node and without custody.

Read this before changing anything here, because Monero does not work the way
Bitcoin does and the difference is the whole design.

For Bitcoin and for Zcash's transparent addresses, `api/chainwatch.py` derives
a receive address from the operator's extended PUBLIC key and a public
explorer answers "was this address paid". Both halves are possible because
those chains publish who was paid.

Monero publishes neither the recipient nor the amount. There is no explorer
query that can answer "did this address receive money" — that is not a gap in
the explorers, it is the point of the coin. Detecting a payment requires the
wallet's private VIEW key and a scan of every block's outputs. That is a
wallet, not a derivation, and writing one here would mean hand-rolling ed25519
and Keccak in the path that decides whether a customer has paid. A subtle bug
would silently miss payments or credit the wrong ones.

So this does the honest thing: it talks JSON-RPC to `monero-wallet-rpc`, the
reference wallet daemon, running as a VIEW-ONLY wallet against a PUBLIC remote
node. That gives:

  - no blockchain on disk. wallet-rpc keeps a small wallet cache; the chain
    stays on whoever's node you point it at.
  - no custody and no spending authority. A view-only wallet cannot sign. If
    the control plane is seized, the attacker can see incoming payments and
    move nothing.
  - a fresh subaddress per invoice, which is what makes two payments of the
    same amount distinguishable.

What it costs, stated plainly:

  - a second process to run. It is a wallet, not a node, but it is still
    something that has to be up, and if it is down invoices do not settle.
  - the remote node sees which blocks you ask for. It cannot see your keys or
    your balance, but it learns that somebody is scanning. Point it at your
    own node if that matters, or rotate between public ones.
  - the wallet must be created view-only, from the operator's own keys, on
    the operator's own machine. scripts/setup-monero-watch.sh walks it.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request

# 1 XMR = 10^12 piconero. Every amount across this file is atomic units;
# floats never touch a balance comparison.
ATOMIC = 10 ** 12

log = logging.getLogger("0trust.monerowatch")


# The wallet is ours, but the transfers in it are not: anyone can send to a
# subaddress we published on a checkout page, and get_transfers grows with
# them. Same cap, same reason, as payments.MAX_RESPONSE_BYTES.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class MoneroError(Exception):
    """wallet-rpc returned an error, or could not be reached."""


class MoneroWatcher:
    """
    A view-only Monero wallet, addressed over JSON-RPC.

    Everything is scoped to one account (index 0 by default): each invoice
    gets a subaddress under it, and payment detection is per subaddress.
    """

    def __init__(self, rpc_url: str | None = None, account_index: int | None = None,
                 confirmations: int | None = None, timeout: float = 20.0,
                 username: str | None = None, password: str | None = None):
        self.url = (rpc_url or os.environ.get("MONERO_WALLET_RPC")
                    or "http://127.0.0.1:18083/json_rpc").rstrip("/")
        self.account = int(account_index if account_index is not None
                           else os.environ.get("MONERO_ACCOUNT_INDEX", "0"))
        # Ten is the Monero convention for irreversibility, and the number
        # web/help.html quotes. Lower it knowingly or not at all.
        self.confirmations = int(confirmations if confirmations is not None
                                 else os.environ.get("XMR_CONFIRMATIONS", "10"))
        self.timeout = timeout
        self.username = username or os.environ.get("MONERO_RPC_USER") or ""
        self.password = password or os.environ.get("MONERO_RPC_PASSWORD") or ""

    # -- transport ---------------------------------------------------------
    def _rpc(self, method: str, params: dict | None = None):
        body = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method,
                           "params": params or {}}).encode()
        req = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={"Content-Type": "application/json"})
        opener = urllib.request.build_opener()
        if self.username:
            # wallet-rpc uses HTTP digest auth when --rpc-login is set.
            mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            mgr.add_password(None, self.url, self.username, self.password)
            opener = urllib.request.build_opener(
                urllib.request.HTTPDigestAuthHandler(mgr))
        try:
            with opener.open(req, timeout=self.timeout) as r:
                # Capped for the same reason payments._http is: an incoming
                # transfer list grows with whatever anyone chooses to send to
                # the wallet, and this runs on the control plane once a
                # minute. Truncation raises and the invoice stays pending.
                raw = r.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise MoneroError(
                        f"wallet-rpc returned more than {MAX_RESPONSE_BYTES} "
                        f"bytes for {method}; refusing to buffer it")
                payload = json.loads(raw or b"{}")
        except urllib.error.HTTPError as e:
            raise MoneroError(
                f"wallet-rpc HTTP {e.code} for {method}: "
                f"{e.read(4096)[:200].decode('utf-8', 'replace')}") from None
        except Exception as e:
            raise MoneroError(
                f"wallet-rpc unreachable at {self.url}: {e}") from None
        if "error" in payload:
            err = payload["error"]
            raise MoneroError(
                f"wallet-rpc {method}: {err.get('message')} "
                f"(code {err.get('code')})")
        return payload.get("result", {})

    # -- addresses ---------------------------------------------------------
    def new_subaddress(self, label: str = "") -> tuple[str, int]:
        """
        A fresh subaddress for one invoice. Returns (address, minor index).

        The index is what payment detection keys on afterwards, so it is
        stored with the invoice — the address alone is not enough to ask
        wallet-rpc about, and re-deriving it later would mean trusting that
        the wallet hands out indices in the same order twice.
        """
        res = self._rpc("create_address",
                        {"account_index": self.account, "label": label[:60]})
        addr = res.get("address")
        idx = res.get("address_index")
        if not addr or idx is None:
            raise MoneroError(f"create_address returned no address: {res}")
        return addr, int(idx)

    # -- payment detection -------------------------------------------------
    def received(self, minor_index: int) -> tuple[int, int]:
        """
        (confirmed atomic units, pending atomic units) into one subaddress.

        Confirmed means at least self.confirmations deep. Anything shallower
        counts as pending: reporting it lets the checkout stop looking broken
        while the customer waits, without crediting them for a payment that
        could still be reorganised away.
        """
        res = self._rpc("get_transfers", {
            "in": True, "pending": True, "pool": True,
            "account_index": self.account,
            "subaddr_indices": [int(minor_index)],
        })
        confirmed = pending = 0
        for bucket in ("in", "pending", "pool"):
            for t in res.get(bucket) or []:
                # get_transfers ignores subaddr_indices on some versions for
                # the pool bucket, so filter again rather than trusting it.
                sub = (t.get("subaddr_index") or {}).get("minor")
                if sub is None:
                    # Unattributable, so it counts for nobody. This used to
                    # fall through and be added: a transfer the wallet did not
                    # label would be counted by EVERY invoice that asked,
                    # because each one asks with its own minor index and none
                    # of them could tell it was not theirs — one payment
                    # settling any number of invoices. Skipping under-credits
                    # instead, which leaves the invoice open for a human to
                    # look at rather than handing out subscriptions.
                    log.warning(
                        "monero: %s transfer with no subaddr_index, skipped "
                        "(txid %s) — a wallet-rpc that does not label "
                        "transfers cannot be used to attribute payments",
                        bucket, str(t.get("txid"))[:16])
                    continue
                if int(sub) != int(minor_index):
                    continue
                amount = int(t.get("amount") or 0)
                if bucket == "in" and int(t.get("confirmations") or 0) >= self.confirmations:
                    confirmed += amount
                else:
                    pending += amount
        return confirmed, pending

    # -- health ------------------------------------------------------------
    def health(self) -> tuple[bool, str]:
        try:
            ver = self._rpc("get_version").get("version")
            # A wallet that cannot see the chain will happily answer
            # get_version and then never notice a payment, so ask how far it
            # has scanned as well.
            height = self._rpc("get_height").get("height", 0)
        except MoneroError as e:
            return False, str(e)[:200]
        if not height:
            return False, ("wallet-rpc is up but has scanned no blocks — check "
                           "--daemon-address points at a reachable node")
        try:
            # Named for what it means. It was `watch_only` and set True when
            # the mnemonic query SUCCEEDED — that is, when the wallet is not
            # watch-only. The logic below was right and the name said the
            # opposite of the value, in the one check standing between the
            # control plane and a spend key.
            has_spend_key = bool(self._rpc("query_key", {"key_type": "mnemonic"}))
        except MoneroError:
            # A view-only wallet has no mnemonic, and asking for one errors.
            # That error is the answer we want.
            has_spend_key = False
        note = "" if not has_spend_key else \
            " — WARNING: this wallet holds a spend key. Use a view-only wallet."
        return True, (f"monero-wallet-rpc v{ver}, scanned to height {height}, "
                      f"{self.confirmations} confirmations required{note}")
