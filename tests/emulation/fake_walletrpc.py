#!/usr/bin/env python3
"""
Fake monero-wallet-rpc. Speaks the JSON-RPC methods api/monerowatch.py uses:

    create_address   -> a fresh subaddress + its minor index
    get_transfers    -> in / pending / pool buckets for a subaddress
    get_version      -> a version number
    get_height       -> how far the wallet has scanned
    query_key        -> errors for a view-only wallet, which is how the
                        health check tells a view-only wallet from a hot one

Monero cannot be faked with a balance table the way an explorer can, because
there is no address lookup to fake — the whole reason monerowatch talks to a
wallet instead of an explorer. So this fakes the wallet.

PAY credits a subaddress index so a test can say "this invoice was paid"
without a chain, a wallet or ed25519.
"""
import json, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()
SUBADDRS = {}            # minor index -> address
TRANSFERS = {}           # minor index -> list of {amount, confirmations, pool}
# Index 0 is the wallet's primary address, not a subaddress, so a real
# create_address starts at 1. A test that assumed 0 would encode a
# behaviour no wallet has.
NEXT_INDEX = [1]
HEIGHT = [3_100_000]
DOWN = [False]
HOT_WALLET = [False]     # True = pretend to hold a spend key
ERROR = [None]           # force a JSON-RPC error, e.g. (-13, "no wallet file")


def _addr_for(idx):
    # Shaped like a real subaddress: base58, 95 chars, leading '8'. Nothing
    # here parses it, but a test that asserts on shape should see the shape.
    body = f"{idx:d}".rjust(8, "0")
    filler = "9ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz123456789"
    s = "8" + (filler * 3)[:86] + body
    return s[:95]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def do_POST(self):
        if DOWN[0]:
            return self._json(503, {"error": "wallet-rpc down"})
        n = int(self.headers.get("Content-Length") or 0)
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._json(400, {"error": "bad json"})
        method = req.get("method")
        params = req.get("params") or {}

        if ERROR[0] is not None:
            code, msg = ERROR[0]
            return self._json(200, {"jsonrpc": "2.0", "id": "0",
                                    "error": {"code": code, "message": msg}})

        if method == "create_address":
            with LOCK:
                idx = NEXT_INDEX[0]; NEXT_INDEX[0] += 1
                addr = _addr_for(idx)
                SUBADDRS[idx] = addr
            return self._result({"address": addr, "address_index": idx})

        if method == "get_transfers":
            want = [int(i) for i in (params.get("subaddr_indices") or [])]
            out = {"in": [], "pending": [], "pool": []}
            with LOCK:
                for idx, items in TRANSFERS.items():
                    if want and idx not in want:
                        continue
                    for t in items:
                        entry = {"amount": t["amount"],
                                 "confirmations": t["confirmations"],
                                 "subaddr_index": {"major": 0, "minor": idx}}
                        bucket = "pool" if t.get("pool") else "in"
                        out[bucket].append(entry)
            return self._result(out)

        if method == "get_version":
            return self._result({"version": 65539})
        if method == "get_height":
            return self._result({"height": HEIGHT[0]})
        if method == "query_key":
            if HOT_WALLET[0]:
                return self._result({"key": "a b c d e f"})
            return self._json(200, {"jsonrpc": "2.0", "id": "0", "error": {
                "code": -29, "message": "The wallet is watch-only"}})

        return self._json(200, {"jsonrpc": "2.0", "id": "0", "error": {
            "code": -32601, "message": f"Method not found: {method}"}})

    def _result(self, res):
        self._json(200, {"jsonrpc": "2.0", "id": "0", "result": res})


def pay(minor_index, atomic, confirmations=10, pool=False):
    """Credit a subaddress. atomic is piconero; 1 XMR = 10**12."""
    with LOCK:
        TRANSFERS.setdefault(int(minor_index), []).append(
            {"amount": int(atomic), "confirmations": int(confirmations),
             "pool": bool(pool)})


def reset():
    with LOCK:
        SUBADDRS.clear(); TRANSFERS.clear()
        NEXT_INDEX[0] = 1; DOWN[0] = False; HOT_WALLET[0] = False
        ERROR[0] = None


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18083
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
