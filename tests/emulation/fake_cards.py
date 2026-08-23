#!/usr/bin/env python3
"""
Fake Stripe and Square, enough to exercise both card adapters for real:
checkout creation, and webhooks signed exactly the way each vendor specifies.
"""
import base64, hashlib, hmac, json, os, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

SESSIONS, LOCK, SEQ = {}, threading.Lock(), [0]
STRIPE_WH = os.environ.get("STRIPE_WEBHOOK_SECRET", "whsec_test")
SQUARE_WH = os.environ.get("SQUARE_WEBHOOK_KEY", "sq_wh_test")
CONTROL = os.environ.get("CONTROL_URL", "http://127.0.0.1:8099")
NOTIFY = os.environ.get("SQUARE_NOTIFICATION_URL",
                        CONTROL + "/api/v1/payment/webhook")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b""
        # --- Stripe: form-encoded ---
        if self.path.startswith("/v1/checkout/sessions"):
            form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
            with LOCK:
                SEQ[0] += 1
                sid = f"cs_test_{SEQ[0]:06d}"
                SESSIONS[sid] = {"id": sid, "object": "checkout.session",
                                 "payment_status": "unpaid", "status": "open",
                                 "url": f"https://checkout.stripe.test/{sid}",
                                 "metadata": {
                                     "account_id": form.get("metadata[account_id]"),
                                     "months": form.get("metadata[months]")}}
            return self._json(200, SESSIONS[sid])
        # --- Square: JSON ---
        if self.path.startswith("/v2/online-checkout/payment-links"):
            with LOCK:
                SEQ[0] += 1
                lid = f"sqpl_{SEQ[0]:06d}"
                SESSIONS[lid] = {"id": lid, "url": f"https://square.test/{lid}",
                                 "payment_status": "PENDING"}
            return self._json(200, {"payment_link": SESSIONS[lid]})
        self._json(404, {"error": "no route"})

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/v1/balance":
            return self._json(200, {"object": "balance", "livemode": False})
        if p == "/v2/locations":
            return self._json(200, {"locations": [{"id": "L1", "name": "test"}]})
        if p.startswith("/v1/checkout/sessions/"):
            sid = p.rsplit("/", 1)[1]
            return self._json(200, SESSIONS[sid]) if sid in SESSIONS else self._json(404, {})
        if p.startswith("/v2/online-checkout/payment-links/"):
            lid = p.rsplit("/", 1)[1]
            return self._json(200, {"payment_link": SESSIONS.get(lid, {})}) \
                if lid in SESSIONS else self._json(404, {})
        self._json(404, {"error": "no route"})


def stripe_webhook(session_id, etype="checkout.session.completed", paid=True,
                   skew=0, secret=None):
    """Signed the way Stripe does: t=<ts>,v1=HMAC(ts + '.' + body)."""
    with LOCK:
        if session_id in SESSIONS and paid:
            SESSIONS[session_id]["payment_status"] = "paid"
    body = json.dumps({
        "id": f"evt_{int(time.time()*1000)}", "type": etype,
        "data": {"object": {"id": session_id, "object": "checkout.session",
                            "payment_status": "paid" if paid else "unpaid"}},
    }).encode()
    ts = str(int(time.time()) + skew)
    sig = hmac.new((secret or STRIPE_WH).encode(),
                   ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        CONTROL + "/api/v1/payment/webhook", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Stripe-Signature": f"t={ts},v1={sig}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {"raw": e.read().decode("utf-8", "replace")[:200]}


def square_webhook(link_id, status="COMPLETED", secret=None, url=None):
    """Signed the way Square does: base64 HMAC over (notification URL + body)."""
    body = json.dumps({
        "type": "payment.updated",
        "data": {"object": {"payment": {"status": status, "order_id": link_id},
                            "payment_link": {"id": link_id}}},
    }).encode()
    mac = hmac.new((secret or SQUARE_WH).encode(),
                   (url or NOTIFY).encode() + body, hashlib.sha256)
    req = urllib.request.Request(
        CONTROL + "/api/v1/payment/webhook", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "x-square-hmacsha256-signature": base64.b64encode(mac.digest()).decode()})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {"raw": e.read().decode("utf-8", "replace")[:200]}


if __name__ == "__main__":
    import urllib.error
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8091
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
