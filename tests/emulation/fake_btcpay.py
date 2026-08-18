#!/usr/bin/env python3
"""Fake BTCPay Server — enough Greenfield API surface to drive the control plane."""
import hashlib, hmac, json, os, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INVOICES = {}
LOCK = threading.Lock()
SECRET = os.environ.get("BTCPAY_WEBHOOK_SECRET", "test-webhook-secret")
CONTROL = os.environ.get("CONTROL_URL", "http://127.0.0.1:8099")
_seq = [0]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        if "/invoices" in self.path:
            with LOCK:
                _seq[0] += 1
                iid = f"inv{_seq[0]:06d}"
                INVOICES[iid] = {
                    "id": iid, "status": "New",
                    "amount": body.get("amount"),
                    "metadata": body.get("metadata", {}),
                    "checkoutLink": f"https://btcpay.test/i/{iid}",
                }
            return self._json(200, INVOICES[iid])
        self._json(404, {"error": "no route"})

    def do_GET(self):
        p = self.path.split("?")[0]
        if p.endswith("/payment-methods"):
            iid = p.split("/invoices/")[1].split("/")[0]
            if iid not in INVOICES:
                return self._json(404, {})
            return self._json(200, [
                {"paymentMethod": "BTC", "destination": "bc1qtest000",
                 "amount": "0.00012", "rate": "41000", "paymentLink": f"bitcoin:bc1qtest000?amount=0.00012"},
                {"paymentMethod": "XMR", "destination": "4Atest000",
                 "amount": "0.031", "rate": "160", "paymentLink": "monero:4Atest000"},
                {"paymentMethod": "BTC-LightningNetwork", "destination": "lnbc1test",
                 "amount": "0.00012", "rate": "41000", "paymentLink": "lightning:lnbc1test"},
            ])
        if "/invoices/" in p:
            iid = p.rsplit("/", 1)[1]
            if iid in INVOICES:
                return self._json(200, INVOICES[iid])
            return self._json(404, {})
        self._json(404, {"error": "no route"})


def settle(invoice_id, event_type="InvoiceSettled"):
    """Mark paid and fire the signed webhook, exactly as BTCPay would."""
    with LOCK:
        if invoice_id in INVOICES:
            INVOICES[invoice_id]["status"] = "Settled" if event_type == "InvoiceSettled" else "Expired"
    payload = json.dumps({
        "deliveryId": f"d{int(time.time()*1000)}",
        "webhookId": "wh1", "originalDeliveryId": "d0", "isRedelivery": False,
        "type": event_type, "timestamp": int(time.time()),
        "storeId": "store1", "invoiceId": invoice_id,
    }).encode()
    sig = "sha256=" + hmac.new(SECRET.encode(), payload, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        f"{CONTROL}/api/v1/payment/webhook", data=payload, method="POST",
        headers={"Content-Type": "application/json", "BTCPay-Sig": sig})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, json.loads(r.read() or b"{}")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8098
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
