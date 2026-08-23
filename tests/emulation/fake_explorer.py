#!/usr/bin/env python3
"""
Fake Esplora. Speaks the two endpoints the watch-only provider uses:

    GET /v1/prices          -> {"USD": ...}
    GET /address/{addr}     -> {"chain_stats": {...}, "mempool_stats": {...}}

mempool.space, blockstream.info and any self-hosted Esplora all serve these
identically, which is why the provider needs no per-explorer code.

PAY writes a balance for an address so a test can say "this invoice was paid"
without a blockchain.
"""
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BALANCES, LOCK = {}, threading.Lock()   # address -> (confirmed, mempool) sats
PRICE = [50_000.0]
DOWN = [False]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        if DOWN[0]:
            return self._json(503, {"error": "explorer down"})
        path = self.path.split("?")[0].rstrip("/")
        if path.endswith("/v1/prices"):
            return self._json(200, {"USD": PRICE[0], "EUR": PRICE[0] * 0.9})
        if "/address/" in path:
            addr = path.rsplit("/address/", 1)[1]
            with LOCK:
                conf, mem = BALANCES.get(addr, (0, 0))
            return self._json(200, {
                "address": addr,
                "chain_stats": {"funded_txo_sum": conf, "spent_txo_sum": 0,
                                "tx_count": 1 if conf else 0},
                "mempool_stats": {"funded_txo_sum": mem, "spent_txo_sum": 0,
                                  "tx_count": 1 if mem else 0},
            })
        self._json(404, {"error": "no route"})


def pay(address, sats, confirmed=True):
    with LOCK:
        c, m = BALANCES.get(address, (0, 0))
        BALANCES[address] = (c + sats, m) if confirmed else (c, m + sats)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8097
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
