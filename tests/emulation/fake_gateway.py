#!/usr/bin/env python3
"""
Fake hosted crypto gateway — the NOWPayments-shaped API HostedProvider talks to.

Exists so the node-free payment path is exercised for real: invoice creation,
per-currency addresses for BTC/XMR/ZEC, and HMAC-SHA512 IPN callbacks over the
sorted JSON body.
"""
import hashlib, hmac, json, os, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INVOICES, LOCK, SEQ = {}, threading.Lock(), [0]
SECRET = os.environ.get("ZTV_PAYMENT_IPN_SECRET", "ipn-secret")
CONTROL = os.environ.get("CONTROL_URL", "http://127.0.0.1:8099")
ADDRESSES = {"BTC": "bc1qgatewaytest0", "XMR": "4Agatewaytest0", "ZEC": "zs1gatewaytest0"}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if self.path.rstrip("/").endswith("/v1/invoice"):
            with LOCK:
                SEQ[0] += 1
                iid = f"gw{SEQ[0]:06d}"
                INVOICES[iid] = {"id": iid, "payment_status": "waiting",
                                 "price_amount": body.get("price_amount"),
                                 "order_id": body.get("order_id"),
                                 "invoice_url": f"https://gateway.test/i/{iid}"}
            return self._json(200, INVOICES[iid])
        self._json(404, {"error": "no route"})

    def do_GET(self):
        p = self.path.split("?")[0].rstrip("/")
        if p.endswith("/payments"):
            iid = p.split("/v1/invoice/")[1].split("/")[0]
            if iid not in INVOICES: return self._json(404, {})
            return self._json(200, {"data": [
                {"pay_currency": c.lower(), "pay_address": a,
                 "pay_amount": "0.001", "rate": "1", "payment_url": f"{c.lower()}:{a}"}
                for c, a in ADDRESSES.items()]})
        if "/v1/invoice/" in p:
            iid = p.rsplit("/", 1)[1]
            if iid in INVOICES: return self._json(200, INVOICES[iid])
            return self._json(404, {})
        self._json(404, {"error": "no route"})


def ipn(invoice_id, status="finished"):
    """Fire a signed IPN exactly as the gateway spec describes."""
    with LOCK:
        if invoice_id in INVOICES:
            INVOICES[invoice_id]["payment_status"] = status
    payload = {"invoice_id": invoice_id, "payment_status": status,
               "order_id": f"order-{invoice_id}", "actually_paid": 0.001,
               "pay_currency": "xmr", "updated_at": int(time.time())}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = hmac.new(SECRET.encode(), body, hashlib.sha512).hexdigest()
    req = urllib.request.Request(f"{CONTROL}/api/v1/payment/webhook", data=body,
                                 method="POST",
                                 headers={"Content-Type": "application/json",
                                          "x-nowpayments-sig": sig})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status, json.loads(r.read() or b"{}")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8095
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
