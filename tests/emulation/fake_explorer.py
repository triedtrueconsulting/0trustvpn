#!/usr/bin/env python3
"""
Fake chain backends for the watch-only provider. Three shapes, one server:

    GET /address/{addr}                  Esplora  (Bitcoin, and any
                                         Esplora-compatible Zcash instance)
    GET /dashboards/address/{addr}       Blockchair (the Zcash default)
    GET /0/public/Ticker?pair=XXXUSD     Kraken   (the USD price feed)

mempool.space, blockstream.info and any self-hosted Esplora serve the first
identically, which is why the provider needs no per-explorer code. Blockchair
answers a different shape, so the provider has a second reader and this has to
exercise it — an untested branch in the code that decides whether a customer
has paid is not a branch worth having.

    GET /v1/prices                       Esplora's own ticker, kept because
                                         mempool.space serves it and an
                                         operator may still point at it.

PAY writes a balance for an address so a test can say "this invoice was paid"
without a blockchain.
"""
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# address -> list of {sats, height}. height None means still in the mempool.
# A flat (confirmed, mempool) pair was enough while the provider treated "in a
# block" and "confirmed" as the same thing. They are not, and modelling them as
# one is what let ZTV_ZEC_CONFIRMATIONS=5 credit a payment one block deep with
# every test green: the fake encoded the same wrong assumption as the code.
PAYMENTS, LOCK = {}, threading.Lock()
TIP = [800_000]                          # current chain tip height
PRICE = [50_000.0]
# Per-coin USD prices for the Kraken-shaped ticker. Kraken renames pairs in
# its response (XBTUSD comes back as XXBTZUSD), and the provider must not
# depend on getting the name it asked for — so the fake renames too.
PRICES = {"XXBTZUSD": 50_000.0, "XZECZUSD": 30.0, "XXMRZUSD": 150.0}
PAIR_ALIAS = {"XBTUSD": "XXBTZUSD", "ZECUSD": "XZECZUSD", "XMRUSD": "XXMRZUSD"}
DOWN = [False]
PRICE_DOWN = [False]


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
        if "/0/public/Ticker" in self.path:
            if PRICE_DOWN[0]:
                return self._json(200, {"error": ["EGeneral:Temporary lockout"],
                                        "result": {}})
            q = self.path.split("?", 1)[1] if "?" in self.path else ""
            pair = dict(p.split("=", 1) for p in q.split("&") if "=" in p).get(
                "pair", "")
            name = PAIR_ALIAS.get(pair, pair)
            if name not in PRICES:
                return self._json(200, {"error": ["EQuery:Unknown asset pair"],
                                        "result": {}})
            px = f"{PRICES[name]:.4f}"
            return self._json(200, {"error": [], "result": {
                name: {"c": [px, "1.0"], "a": [px, "1", "1.0"],
                       "b": [px, "1", "1.0"]}}})
        if path.endswith("/blocks/tip/height"):
            # Esplora answers this one with a bare integer, not an object.
            return self._json(200, TIP[0])
        if "/dashboards/address/" in path:
            addr = path.rsplit("/dashboards/address/", 1)[1]
            conf, mem = _totals(addr)
            with LOCK:
                paid = list(PAYMENTS.get(addr, []))
            return self._json(200, {"data": {addr: {
                "address": {"received": conf, "spent": 0,
                            "unconfirmed_received": mem,
                            "balance": conf + mem},
                # Blockchair reports a height per unspent output; that is what
                # the provider turns into a depth.
                "utxo": [{"block_id": p["height"] if p["height"] else -1,
                          "value": p["sats"], "index": i}
                         for i, p in enumerate(paid)],
            }}, "context": {"code": 200, "state": TIP[0]}})
        if "/address/" in path and path.endswith("/txs"):
            addr = path[:-len("/txs")].rsplit("/address/", 1)[1]
            with LOCK:
                paid = list(PAYMENTS.get(addr, []))
            return self._json(200, [{
                "txid": f"{i:064x}",
                "status": ({"confirmed": True, "block_height": p["height"]}
                           if p["height"] else {"confirmed": False}),
                "vout": [{"scriptpubkey_address": addr, "value": p["sats"]}],
            } for i, p in enumerate(paid)])
        if "/address/" in path:
            addr = path.rsplit("/address/", 1)[1]
            conf, mem = _totals(addr)
            return self._json(200, {
                "address": addr,
                "chain_stats": {"funded_txo_sum": conf, "spent_txo_sum": 0,
                                "tx_count": 1 if conf else 0},
                "mempool_stats": {"funded_txo_sum": mem, "spent_txo_sum": 0,
                                  "tx_count": 1 if mem else 0},
            })
        self._json(404, {"error": "no route"})


def _totals(address):
    """(mined, mempool) sats — mined counts anything in a block, any depth."""
    with LOCK:
        paid = list(PAYMENTS.get(address, []))
    return (sum(p["sats"] for p in paid if p["height"]),
            sum(p["sats"] for p in paid if not p["height"]))


def pay(address, sats, confirmed=True, depth=None):
    """
    Credit an address.

    depth is how many blocks deep the payment is, counting the block it is in,
    and defaults to the tip (1 confirmation) — which is what an explorer's
    chain_stats has always reported it as. Pass a larger number to bury it.
    """
    with LOCK:
        height = None
        if confirmed:
            d = 1 if depth is None else max(1, int(depth))
            height = TIP[0] - d + 1
        PAYMENTS.setdefault(address, []).append({"sats": sats, "height": height})


def mine(blocks=1):
    """Advance the tip, which deepens every payment already in a block."""
    with LOCK:
        TIP[0] += int(blocks)


def reset():
    with LOCK:
        PAYMENTS.clear()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8097
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
