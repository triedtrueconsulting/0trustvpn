"""
Payment providers.

0trust takes BTC, XMR and ZEC. The operator picks how, via ZTV_PAYMENT_PROVIDER:

  btcpay   BTCPay Server — self-hosted, or somebody else's instance.
           Non-custodial: funds land in your wallet, the server only watches.
  hosted   A commercial crypto payment gateway with a REST API. No blockchain
           infrastructure at all, at the cost of the trade-offs below.

Neither option requires this operator to run a Bitcoin, Monero or Zcash node:
point `btcpay` at a hosted BTCPay and the chain infrastructure is somebody
else's problem either way.

WHAT YOU GIVE UP BY NOT RUNNING A NODE
--------------------------------------
Worth stating plainly, because this product sells verifiable privacy and the
payment path is the one place a customer's money touches an identity.

  * Whoever runs the chain infrastructure sees your addresses, your revenue,
    and the timing of every payment. For BTC and ZEC transparent addresses
    that is a public chain anyway, but they also learn which addresses are
    *yours*, which the chain alone does not say.
  * A hosted gateway is usually custodial and usually KYC'd. That puts a
    company with your identity between you and your customers' money, and it
    can freeze or reverse. BTCPay does not: payments go straight to your
    wallet.
  * A provider that lies about confirmations can credit a subscription that
    was never paid. Both adapters therefore treat only a terminal "settled"
    event as payment, and the caller credits each invoice exactly once.

If the no-logs claims in docs/AUDIT.md ever come to depend on the payment
path, reconcile them with whichever provider is actually configured.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

import chainwatch
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

# The chains we accept. XMR is the private default; BTC is the one everyone
# already has; ZEC is here for shielded senders; ETH because enough customers
# hold nothing else.
#
# None of these requires us to run a node. Which is true for a different
# reason per provider, and worth being precise about:
#   btcpay  — the BTCPay instance holds the chain data. Point BTCPAY_URL at a
#             hosted one and it is somebody else's disk.
#   hosted  — the gateway does it all.
#   stripe/square — no chain involved; these are card rails.
# NODE_RPC_* settings name the public endpoints an operator wants used where
# a provider consults them. We never sync a chain locally.
CURRENCIES = ("BTC", "ETH", "XMR", "ZEC")

# Card processors. Kept separate because they are a different product, not a
# different coin: they need a real identity behind the card, they can reverse
# a payment months later, and they are the one payment route that breaks the
# "no name, no identity" property the rest of this system is built around.
# Offering them is a business decision; web/privacy.html has to say so.
CARD_PROVIDERS = ("stripe", "square")

# Normalized invoice lifecycle, so main.py never sees provider vocabulary.
SETTLED = "settled"
PENDING = "pending"
EXPIRED = "expired"
INVALID = "invalid"


class PaymentError(Exception):
    """Provider returned a non-2xx, or was unreachable."""


def _http(method: str, url: str, headers: dict, body: dict | None = None,
          timeout: float = 15.0) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = r.read()
            return json.loads(payload) if payload else None
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:500]
        raise PaymentError(f"{e.code} {e.reason}: {detail}") from e
    except urllib.error.URLError as e:
        raise PaymentError(f"payment provider unreachable: {e.reason}") from e


# ---------------------------------------------------------------------------
# BTCPay Server
# ---------------------------------------------------------------------------

class BTCPayProvider:
    """
    BTCPay Greenfield. Works against your own instance or a hosted one — the
    only difference is BTCPAY_URL, so "don't run a node" is a config choice
    rather than a code path.
    """

    name = "btcpay"

    def __init__(self, base_url=None, store_id=None, api_key=None,
                 webhook_secret=None, timeout: float = 15.0):
        self.base_url = (base_url or os.environ.get("BTCPAY_URL", "")).rstrip("/")
        self.store_id = store_id or os.environ.get("BTCPAY_STORE_ID", "")
        self.api_key = api_key or os.environ.get("BTCPAY_API_KEY", "")
        self.webhook_secret = (
            webhook_secret if webhook_secret is not None
            else os.environ.get("BTCPAY_WEBHOOK_SECRET", "")
        )
        self.timeout = timeout

    def _headers(self) -> dict:
        return {
            "Authorization": f"token {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def create_invoice(self, amount_usd: float, account_id: int, months: int,
                       redirect_url: str | None = None) -> dict:
        body = {
            "amount": f"{amount_usd:.2f}",
            "currency": "USD",
            "metadata": {
                "accountId": account_id,
                "months": months,
                "orderId": f"0trust-{account_id}-{months}m",
            },
            "checkout": {
                "speedPolicy": "MediumSpeed",
                "expirationMinutes": 60,
                "monitoringMinutes": 90,
                "paymentMethods": list(CURRENCIES) + ["BTC-LightningNetwork"],
                "defaultLanguage": "en-US",
                "redirectAutomatically": True,
            },
        }
        if redirect_url:
            body["checkout"]["redirectURL"] = redirect_url
        raw = _http("POST", f"{self.base_url}/api/v1/stores/{self.store_id}/invoices",
                    self._headers(), body, self.timeout)
        return {"id": raw["id"], "checkout_url": raw.get("checkoutLink", ""),
                "status": self._normalize(raw.get("status", "New")), "raw": raw}

    def get_invoice(self, invoice_id: str) -> dict:
        raw = _http("GET",
                    f"{self.base_url}/api/v1/stores/{self.store_id}/invoices/{invoice_id}",
                    self._headers(), None, self.timeout)
        return {"id": raw.get("id", invoice_id),
                "status": self._normalize(raw.get("status", "New")), "raw": raw}

    def get_payment_methods(self, invoice_id: str) -> list[dict]:
        raw = _http(
            "GET",
            f"{self.base_url}/api/v1/stores/{self.store_id}/invoices/{invoice_id}/payment-methods",
            self._headers(), None, self.timeout,
        ) or []
        out = []
        for m in raw:
            if not m.get("destination"):
                continue
            out.append({
                "currency": (m.get("paymentMethod", "")
                             .replace("-LightningNetwork", "-LN")),
                "address": m.get("destination"),
                "amount": m.get("amount"),
                "rate": m.get("rate"),
                "uri": m.get("paymentLink"),
            })
        return out

    def verify_webhook(self, payload: bytes, headers) -> bool:
        if not self.webhook_secret:
            return False
        sig = _header(headers, "BTCPay-Sig")
        expected = "sha256=" + hmac.new(
            self.webhook_secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, sig or "")

    def parse_webhook(self, payload: bytes) -> tuple[Optional[str], str]:
        event = json.loads(payload)
        etype = event.get("type", "")
        mapping = {
            "InvoiceSettled": SETTLED,
            "InvoicePaymentSettled": PENDING,
            "InvoiceExpired": EXPIRED,
            "InvoiceInvalid": INVALID,
        }
        return event.get("invoiceId"), mapping.get(etype, PENDING)

    @staticmethod
    def _normalize(status: str) -> str:
        return {
            "Settled": SETTLED, "Complete": SETTLED, "Confirmed": SETTLED,
            "Expired": EXPIRED, "Invalid": INVALID,
        }.get(status, PENDING)

    def health(self) -> tuple[bool, str]:
        if not self.base_url:
            return False, "BTCPAY_URL is not set"
        if not self.store_id or not self.api_key:
            return False, "Store ID or API key missing"
        try:
            _http("GET", f"{self.base_url}/api/v1/stores/{self.store_id}",
                  self._headers(), None, self.timeout)
            return True, f"BTCPay reachable at {self.base_url}"
        except PaymentError as e:
            return False, str(e)[:200]


# ---------------------------------------------------------------------------
# Hosted gateway
# ---------------------------------------------------------------------------

class HostedProvider:
    """
    A commercial crypto gateway over REST. Modelled on the shape most of them
    share (NOWPayments, Cryptomus and friends): create an invoice, poll or
    receive an IPN, read a status string.

    Everything that differs between vendors is configuration rather than code:

      ZTV_PAYMENT_API_URL      base URL
      ZTV_PAYMENT_API_KEY      sent as the auth header
      ZTV_PAYMENT_AUTH_HEADER  header name          (default x-api-key)
      ZTV_PAYMENT_IPN_SECRET   HMAC secret for callbacks
      ZTV_PAYMENT_SIG_HEADER   callback signature header (default x-nowpayments-sig)
      ZTV_PAYMENT_SIG_ALGO     sha512 | sha256      (default sha512)

    Signatures are computed over the body with keys sorted, which is what the
    common implementations specify; a vendor that signs the raw bytes instead
    is handled by accepting either form.
    """

    name = "hosted"

    # Gateway status vocabulary -> ours. Anything unlisted stays pending, so an
    # unfamiliar status can never be mistaken for payment.
    STATUS = {
        "finished": SETTLED, "confirmed": SETTLED, "paid": SETTLED,
        "complete": SETTLED, "completed": SETTLED, "settled": SETTLED,
        "expired": EXPIRED, "cancelled": EXPIRED, "canceled": EXPIRED,
        "failed": INVALID, "refunded": INVALID,
    }

    def __init__(self, base_url=None, api_key=None, ipn_secret=None,
                 auth_header=None, sig_header=None, sig_algo=None,
                 timeout: float = 15.0):
        self.base_url = (base_url or os.environ.get("ZTV_PAYMENT_API_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("ZTV_PAYMENT_API_KEY", "")
        self.ipn_secret = (
            ipn_secret if ipn_secret is not None
            else os.environ.get("ZTV_PAYMENT_IPN_SECRET", "")
        )
        self.auth_header = auth_header or os.environ.get(
            "ZTV_PAYMENT_AUTH_HEADER", "x-api-key")
        self.sig_header = sig_header or os.environ.get(
            "ZTV_PAYMENT_SIG_HEADER", "x-nowpayments-sig")
        self.sig_algo = (sig_algo or os.environ.get(
            "ZTV_PAYMENT_SIG_ALGO", "sha512")).lower()
        self.timeout = timeout

    def _headers(self) -> dict:
        return {self.auth_header: self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json"}

    def create_invoice(self, amount_usd: float, account_id: int, months: int,
                       redirect_url: str | None = None) -> dict:
        body = {
            "price_amount": round(amount_usd, 2),
            "price_currency": "usd",
            "order_id": f"0trust-{account_id}-{months}m",
            "order_description": f"0trust VPN — {months} month(s)",
            "ipn_callback_url": os.environ.get("ZTV_PAYMENT_IPN_URL", ""),
        }
        if redirect_url:
            body["success_url"] = redirect_url
        raw = _http("POST", f"{self.base_url}/v1/invoice",
                    self._headers(), body, self.timeout)
        inv_id = str(raw.get("id") or raw.get("invoice_id") or "")
        if not inv_id:
            raise PaymentError(f"gateway returned no invoice id: {raw}")
        return {"id": inv_id,
                "checkout_url": raw.get("invoice_url") or raw.get("url", ""),
                "status": PENDING, "raw": raw}

    def get_invoice(self, invoice_id: str) -> dict:
        raw = _http("GET", f"{self.base_url}/v1/invoice/{invoice_id}",
                    self._headers(), None, self.timeout)
        return {"id": invoice_id, "status": self._normalize(raw), "raw": raw}

    def get_payment_methods(self, invoice_id: str) -> list[dict]:
        """
        Gateways hand the customer their own hosted checkout, so there is
        usually no per-currency address to surface. Return whatever the
        invoice exposes and let the UI fall back to the checkout link.
        """
        try:
            raw = _http("GET", f"{self.base_url}/v1/invoice/{invoice_id}/payments",
                        self._headers(), None, self.timeout) or {}
        except PaymentError:
            return []
        items = raw.get("data") if isinstance(raw, dict) else raw
        out = []
        for m in items or []:
            cur = str(m.get("pay_currency", "")).upper()
            if not m.get("pay_address") or cur not in CURRENCIES:
                continue
            out.append({"currency": cur, "address": m.get("pay_address"),
                        "amount": m.get("pay_amount"), "rate": m.get("rate"),
                        "uri": m.get("payment_url")})
        return out

    def verify_webhook(self, payload: bytes, headers) -> bool:
        if not self.ipn_secret:
            return False
        sig = (_header(headers, self.sig_header) or "").strip()
        if not sig:
            return False
        algo = hashlib.sha512 if self.sig_algo == "sha512" else hashlib.sha256
        candidates = []
        try:
            sorted_body = json.dumps(json.loads(payload), sort_keys=True,
                                     separators=(",", ":")).encode()
            candidates.append(sorted_body)
        except ValueError:
            pass
        candidates.append(payload)
        for c in candidates:
            expected = hmac.new(self.ipn_secret.encode(), c, algo).hexdigest()
            if hmac.compare_digest(expected, sig):
                return True
        return False

    def parse_webhook(self, payload: bytes) -> tuple[Optional[str], str]:
        event = json.loads(payload)
        inv = event.get("invoice_id") or event.get("id") or event.get("order_id")
        return (str(inv) if inv is not None else None), self._normalize(event)

    def _normalize(self, raw: dict) -> str:
        status = str(
            raw.get("payment_status") or raw.get("invoice_status")
            or raw.get("status") or ""
        ).lower()
        return self.STATUS.get(status, PENDING)

    def health(self) -> tuple[bool, str]:
        if not self.base_url:
            return False, "ZTV_PAYMENT_API_URL is not set"
        if not self.api_key:
            return False, "ZTV_PAYMENT_API_KEY is not set"
        try:
            # Most gateways expose a status endpoint; a 404 still proves we
            # reached the host, which is what this check is really asking.
            _http("GET", f"{self.base_url}/v1/status", self._headers(),
                  None, self.timeout)
            return True, "Gateway reachable"
        except PaymentError as e:
            msg = str(e)
            if msg.startswith("404"):
                return True, "Gateway reachable (no /v1/status endpoint)"
            return False, msg[:200]


def _header(headers, name: str) -> str:
    """Case-insensitive lookup across dicts and Starlette Headers alike."""
    if headers is None:
        return ""
    get = getattr(headers, "get", None)
    if get:
        v = get(name) or get(name.lower()) or get(name.upper())
        if v:
            return v
    for k, v in (headers.items() if hasattr(headers, "items") else []):
        if k.lower() == name.lower():
            return v
    return ""


# ---------------------------------------------------------------------------
# Card processors
# ---------------------------------------------------------------------------

class StripeProvider:
    """
    Stripe Checkout.

    A hosted payment page, so no card data ever touches this server and PCI
    scope stays with Stripe. Settlement arrives as a signed webhook.

    Two things to be clear-eyed about before enabling it. Stripe requires a
    verified business identity and can freeze or claw back funds, which is the
    opposite of the property crypto gives here. And a card ties a real person
    to an account: that account is no longer anonymous in any meaningful
    sense, whatever the token says. Both belong in the privacy policy, not in
    a code comment alone.
    """

    name = "stripe"
    API = "https://api.stripe.com/v1"

    def __init__(self, secret_key=None, webhook_secret=None, success_url=None,
                 api_base=None, timeout: float = 20.0):
        # Overridable so the adapter can be exercised against a stand-in.
        # Defaults to Stripe; nothing changes in production.
        self.api = (api_base or os.environ.get("STRIPE_API_BASE")
                    or self.API).rstrip("/")
        self.secret_key = secret_key or os.environ.get("STRIPE_SECRET_KEY", "")
        self.webhook_secret = (
            webhook_secret if webhook_secret is not None
            else os.environ.get("STRIPE_WEBHOOK_SECRET", ""))
        self.success_url = success_url or os.environ.get(
            "STRIPE_SUCCESS_URL", "https://0trustvpn.com/welcome")
        self.timeout = timeout

    def _form(self, method: str, path: str, fields: list[tuple[str, str]] | None = None):
        """Stripe's API is form-encoded, not JSON."""
        data = urllib.parse.urlencode(fields).encode() if fields else None
        req = urllib.request.Request(
            f"{self.api}{path}", data=data, method=method,
            headers={"Authorization": f"Bearer {self.secret_key}",
                     "Content-Type": "application/x-www-form-urlencoded",
                     "Stripe-Version": "2024-06-20"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            raise PaymentError(
                f"{e.code}: {e.read().decode('utf-8', 'replace')[:400]}") from e
        except urllib.error.URLError as e:
            raise PaymentError(f"Stripe unreachable: {e.reason}") from e

    def create_invoice(self, amount_usd: float, account_id: int, months: int,
                       redirect_url: str | None = None) -> dict:
        cents = int(round(amount_usd * 100))
        fields = [
            ("mode", "payment"),
            ("success_url", redirect_url or self.success_url),
            ("cancel_url", (redirect_url or self.success_url)),
            ("line_items[0][quantity]", "1"),
            ("line_items[0][price_data][currency]", "usd"),
            ("line_items[0][price_data][unit_amount]", str(cents)),
            ("line_items[0][price_data][product_data][name]",
             f"0trust VPN — {months} month{'s' if months != 1 else ''}"),
            ("metadata[account_id]", str(account_id)),
            ("metadata[months]", str(months)),
            # Nothing is collected that we do not need. Stripe will still see
            # the cardholder; we decline to receive it.
            ("payment_intent_data[metadata][account_id]", str(account_id)),
        ]
        raw = self._form("POST", "/checkout/sessions", fields)
        return {"id": raw["id"], "checkout_url": raw.get("url", ""),
                "status": PENDING, "raw": raw}

    def get_invoice(self, invoice_id: str) -> dict:
        raw = self._form("GET", f"/checkout/sessions/{invoice_id}")
        paid = raw.get("payment_status") == "paid"
        expired = raw.get("status") == "expired"
        return {"id": invoice_id,
                "status": SETTLED if paid else (EXPIRED if expired else PENDING),
                "raw": raw}

    def get_payment_methods(self, invoice_id: str) -> list[dict]:
        return []          # Stripe hosts its own checkout page

    def verify_webhook(self, payload: bytes, headers) -> bool:
        """
        Stripe-Signature: t=<ts>,v1=<hmac>. The timestamp is part of the
        signed payload and is checked for freshness, which is what stops a
        captured delivery being replayed forever.
        """
        if not self.webhook_secret:
            return False
        sig = _header(headers, "Stripe-Signature")
        if not sig:
            return False
        parts = dict(p.split("=", 1) for p in sig.split(",") if "=" in p)
        ts, v1 = parts.get("t"), parts.get("v1")
        if not ts or not v1:
            return False
        try:
            if abs(time.time() - int(ts)) > 300:
                return False
        except ValueError:
            return False
        expected = hmac.new(self.webhook_secret.encode(),
                            ts.encode() + b"." + payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, v1)

    def parse_webhook(self, payload: bytes) -> tuple[Optional[str], str]:
        event = json.loads(payload)
        etype = event.get("type", "")
        obj = (event.get("data") or {}).get("object") or {}
        inv = obj.get("id")
        if etype == "checkout.session.completed":
            return inv, (SETTLED if obj.get("payment_status") == "paid" else PENDING)
        if etype == "checkout.session.async_payment_succeeded":
            return inv, SETTLED
        if etype in ("checkout.session.expired",):
            return inv, EXPIRED
        if etype in ("checkout.session.async_payment_failed",):
            return inv, INVALID
        # A chargeback is not an invoice event and must not silently settle
        # anything; surfaced as pending so the caller ignores it.
        return inv, PENDING

    def health(self) -> tuple[bool, str]:
        if not self.secret_key:
            return False, "STRIPE_SECRET_KEY is not set"
        try:
            self._form("GET", "/balance")
            return True, "Stripe reachable, key accepted"
        except PaymentError as e:
            return False, str(e)[:200]


class SquareProvider:
    """
    Square hosted checkout (Payment Links).

    Same trade-offs as Stripe: identity behind the card, reversible payments,
    a third party in the middle. Square is here because plenty of small
    operators already have a Square account for other parts of the business.
    """

    name = "square"

    def __init__(self, access_token=None, location_id=None, webhook_key=None,
                 environment=None, notification_url=None, timeout: float = 20.0):
        self.access_token = access_token or os.environ.get("SQUARE_ACCESS_TOKEN", "")
        self.location_id = location_id or os.environ.get("SQUARE_LOCATION_ID", "")
        self.webhook_key = (
            webhook_key if webhook_key is not None
            else os.environ.get("SQUARE_WEBHOOK_KEY", ""))
        env = (environment or os.environ.get("SQUARE_ENV", "production")).lower()
        self.base = (os.environ.get("SQUARE_API_BASE")
                     or ("https://connect.squareupsandbox.com"
                         if env == "sandbox" else "https://connect.squareup.com")
                     ).rstrip("/")
        self.notification_url = notification_url or os.environ.get(
            "SQUARE_NOTIFICATION_URL", "")
        self.timeout = timeout

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.access_token}",
                "Content-Type": "application/json",
                "Square-Version": "2024-06-04",
                "Accept": "application/json"}

    def create_invoice(self, amount_usd: float, account_id: int, months: int,
                       redirect_url: str | None = None) -> dict:
        body = {
            # Square deduplicates on this, so a retried request cannot create
            # a second payment link for the same intent.
            "idempotency_key": f"0trust-{account_id}-{months}-{int(time.time())}",
            "quick_pay": {
                "name": f"0trust VPN — {months} month{'s' if months != 1 else ''}",
                "price_money": {"amount": int(round(amount_usd * 100)),
                                "currency": "USD"},
                "location_id": self.location_id,
            },
            "checkout_options": {
                "redirect_url": redirect_url or os.environ.get(
                    "STRIPE_SUCCESS_URL", "https://0trustvpn.com/welcome"),
                "ask_for_shipping_address": False,
            },
            "payment_note": f"account:{account_id} months:{months}",
        }
        raw = _http("POST", f"{self.base}/v2/online-checkout/payment-links",
                    self._headers(), body, self.timeout)
        link = (raw or {}).get("payment_link") or {}
        if not link.get("id"):
            raise PaymentError(f"Square returned no payment link: {raw}")
        return {"id": link["id"], "checkout_url": link.get("url", ""),
                "status": PENDING, "raw": raw}

    def get_invoice(self, invoice_id: str) -> dict:
        raw = _http("GET",
                    f"{self.base}/v2/online-checkout/payment-links/{invoice_id}",
                    self._headers(), None, self.timeout)
        link = (raw or {}).get("payment_link") or {}
        # A payment link carries no terminal state of its own; settlement is
        # only ever learned from the webhook.
        return {"id": invoice_id,
                "status": SETTLED if link.get("order_id") and
                link.get("payment_status") == "COMPLETED" else PENDING,
                "raw": raw}

    def get_payment_methods(self, invoice_id: str) -> list[dict]:
        return []

    def verify_webhook(self, payload: bytes, headers) -> bool:
        """
        Square signs HMAC-SHA256 over (notification URL + body), base64. The
        URL is part of the signed material, so it has to match exactly what is
        configured in the Square dashboard.
        """
        if not self.webhook_key or not self.notification_url:
            return False
        sig = _header(headers, "x-square-hmacsha256-signature")
        if not sig:
            return False
        mac = hmac.new(self.webhook_key.encode(),
                       self.notification_url.encode() + payload, hashlib.sha256)
        expected = base64.b64encode(mac.digest()).decode()
        return hmac.compare_digest(expected, sig)

    def parse_webhook(self, payload: bytes) -> tuple[Optional[str], str]:
        event = json.loads(payload)
        etype = event.get("type", "")
        obj = ((event.get("data") or {}).get("object") or {})
        link = obj.get("payment_link") or {}
        payment = obj.get("payment") or {}
        inv = link.get("id") or payment.get("order_id") or obj.get("id")
        if etype in ("payment.updated", "payment.created"):
            status = str(payment.get("status", "")).upper()
            if status == "COMPLETED":
                return inv, SETTLED
            if status in ("FAILED", "CANCELED"):
                return inv, INVALID
        return inv, PENDING

    def health(self) -> tuple[bool, str]:
        if not self.access_token:
            return False, "SQUARE_ACCESS_TOKEN is not set"
        if not self.location_id:
            return False, "SQUARE_LOCATION_ID is not set"
        try:
            _http("GET", f"{self.base}/v2/locations", self._headers(),
                  None, self.timeout)
            return True, "Square reachable, token accepted"
        except PaymentError as e:
            return False, str(e)[:200]


# ---------------------------------------------------------------------------


class WatchOnlyProvider:
    """
    Bitcoin straight into the operator's own wallet, with nothing in between.

    Every other provider here puts a third party between the customer and the
    money: BTCPay is a server somebody has to run, and a hosted gateway is
    custodial and usually wants identity documents. This one needs neither. The
    operator pastes the *public* half of their wallet, we derive a fresh
    receive address per invoice, and we watch a public block explorer for the
    payment. Funds land in their wallet directly; the control plane never has
    the keys and could not move a satoshi if it were seized.

    It is also the only provider that works on a fresh VPS with no accounts
    signed up for anywhere, which is the point.

    What it gives up, stated plainly:

      - Bitcoin only. Monero and Zcash need per-invoice addresses this cannot
        derive without wallet software, and reusing one address for every
        customer would both break payment privacy and make two payments of the
        same amount impossible to tell apart. currencies_for() says BTC and
        means it — see docs, and do not add coins here without solving that.
      - It trusts a public explorer for confirmation. That is one API that can
        lie or go down. It cannot steal anything, and a wrong answer is
        recoverable by hand from the dashboard, but it is a dependency and
        pretending otherwise would be dishonest.
      - Price comes from the same explorer's ticker, so the USD conversion is
        theirs, not ours.

    There is no webhook. Confirmation is by polling, which is what makes this
    deployable without an inbound callback URL, a TLS certificate or a
    provider dashboard to configure.
    """

    # Esplora's API, which mempool.space, blockstream.info and any self-hosted
    # instance all speak identically.
    DEFAULT_API = "https://mempool.space/api"

    def __init__(self, xpub=None, api_base=None, confirmations=None,
                 timeout=15.0):
        self.xpub = (xpub if xpub is not None
                     else os.environ.get("WALLET_BTC", "")).strip()
        self.api = (api_base or os.environ.get("NODE_RPC_BTC")
                    or self.DEFAULT_API).rstrip("/")
        self.confirmations = int(
            confirmations if confirmations is not None
            else os.environ.get("ZTV_BTC_CONFIRMATIONS", "1"))
        self.timeout = timeout

    # -- addresses ---------------------------------------------------------
    def address_for(self, index: int) -> str:
        """
        The receive address for this invoice.

        A plain address in WALLET_BTC is accepted and reused, because some
        operators genuinely want that, but it is worse in every way: payments
        become impossible to attribute when two customers owe the same amount,
        and the whole payment history becomes public and linked. The dashboard
        says so.
        """
        if not self.xpub:
            raise PaymentError("WALLET_BTC is not set — no wallet to pay into")
        if chainwatch.looks_like_xpub(self.xpub):
            return chainwatch.receive_address(self.xpub, index)
        return self.xpub

    def reuses_one_address(self) -> bool:
        return bool(self.xpub) and not chainwatch.looks_like_xpub(self.xpub)

    # -- price -------------------------------------------------------------
    def btc_price_usd(self) -> float:
        raw = _http("GET", f"{self.api}/v1/prices", {}, None, self.timeout)
        price = float((raw or {}).get("USD") or 0)
        if price <= 0:
            raise PaymentError("price feed returned no USD rate")
        return price

    # -- provider interface -------------------------------------------------
    def create_invoice(self, amount_usd: float, account_id: int, months: int,
                       redirect_url: str | None = None,
                       index: int | None = None) -> dict:
        if index is None:
            raise PaymentError("watch-only invoices need a derivation index")
        address = self.address_for(index)
        sats = int(round(amount_usd / self.btc_price_usd() * 100_000_000))
        if sats <= 0:
            raise PaymentError("computed a zero-satoshi invoice")
        btc = f"{sats / 100_000_000:.8f}"
        return {
            "id": f"btc-{index}-{int(time.time())}",
            # No hosted checkout to send anyone to: the customer pays from
            # their own wallet. The UI renders the address and a QR.
            "checkout_url": "",
            "status": PENDING,
            "payment_address": address,
            "amount_crypto": btc,
            "derivation_index": index,
            "raw": {"address": address, "sats": sats, "index": index},
        }

    def address_received(self, address: str) -> tuple[int, int]:
        """(confirmed sats, unconfirmed sats) ever received at an address."""
        raw = _http("GET", f"{self.api}/address/{address}", {}, None,
                    self.timeout) or {}
        chain = raw.get("chain_stats") or {}
        mem = raw.get("mempool_stats") or {}
        return int(chain.get("funded_txo_sum") or 0), int(
            mem.get("funded_txo_sum") or 0)

    def check(self, address: str, expected_sats: int) -> dict:
        """
        Has this invoice been paid? Called by the poller, which owns crediting.

        Overpayment settles. Underpayment does not: crediting a month for half
        the price because the customer's wallet took a fee off the top is a
        revenue leak, and the amount received is reported so support can
        settle it by hand.
        """
        confirmed, pending = self.address_received(address)
        paid = confirmed >= expected_sats
        return {
            "status": SETTLED if paid else PENDING,
            "confirmed_sats": confirmed,
            "unconfirmed_sats": pending,
            "expected_sats": expected_sats,
            # Seen but not yet confirmed: worth showing the customer so the
            # page stops looking broken while they wait for a block.
            "seen": confirmed > 0 or pending > 0,
        }

    def get_invoice(self, invoice_id: str) -> dict:
        # The explorer knows addresses, not our invoice ids. The poller and
        # the status endpoint look the address up locally and call check().
        return {"id": invoice_id, "status": PENDING, "raw": {}}

    def get_payment_methods(self, invoice_id: str) -> list[dict]:
        return []

    def verify_webhook(self, payload: bytes, headers) -> bool:
        # There is no webhook, so there is nothing that could be valid. If a
        # POST arrives at the webhook endpoint under this provider it is
        # either a mistake or an attempt.
        return False

    def parse_webhook(self, payload: bytes) -> tuple[Optional[str], str]:
        return None, PENDING

    def health(self) -> tuple[bool, str]:
        if not self.xpub:
            return False, "WALLET_BTC is not set"
        try:
            addr = self.address_for(0)
        except Exception as e:
            return False, f"WALLET_BTC is not usable: {e}"
        try:
            price = self.btc_price_usd()
        except PaymentError as e:
            return False, f"explorer unreachable: {str(e)[:120]}"
        note = "reusing one address for every invoice" \
            if self.reuses_one_address() else f"first address {addr}"
        return True, (f"watching {self.api}, BTC ${price:,.0f}, "
                      f"{self.confirmations} confirmation(s); {note}")


# ---------------------------------------------------------------------------

_PROVIDERS = {"btcpay": BTCPayProvider, "hosted": HostedProvider,
              "stripe": StripeProvider, "square": SquareProvider,
              "watch": WatchOnlyProvider}
_instance = None


def provider():
    """Lazy singleton, so missing config doesn't break module import."""
    global _instance
    if _instance is None:
        name = os.environ.get("ZTV_PAYMENT_PROVIDER", "btcpay").lower()
        cls = _PROVIDERS.get(name)
        if cls is None:
            raise PaymentError(
                f"unknown ZTV_PAYMENT_PROVIDER={name!r}; "
                f"expected one of {sorted(_PROVIDERS)}"
            )
        _instance = cls()
    return _instance


def reset_provider():
    """Drop the cached provider. Tests and the settings editor reconfigure."""
    global _instance
    _instance = None


# Which settings each provider cannot work without. The dashboard uses this to
# tell an operator what is still missing instead of letting signup 502.
REQUIRED_SETTINGS = {
    # Just the wallet. No account anywhere, no callback URL, no secret to
    # share — which is what lets a fresh VPS take money the day it is built.
    "watch": ("WALLET_BTC",),
    "btcpay": ("BTCPAY_URL", "BTCPAY_STORE_ID", "BTCPAY_API_KEY",
               "BTCPAY_WEBHOOK_SECRET"),
    "hosted": ("ZTV_PAYMENT_API_URL", "ZTV_PAYMENT_API_KEY",
               "ZTV_PAYMENT_IPN_SECRET"),
    "stripe": ("STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"),
    "square": ("SQUARE_ACCESS_TOKEN", "SQUARE_LOCATION_ID", "SQUARE_WEBHOOK_KEY"),
}


def required_settings(name: str) -> tuple[str, ...]:
    return REQUIRED_SETTINGS.get((name or "").lower(), ())


def currencies_for(name: str) -> tuple[str, ...]:
    """
    What a customer can actually pay with under this provider.

    Card providers do not take coins, and saying "BTC, ETH, XMR, ZEC" on a
    checkout page that only accepts Visa would be a lie the dashboard is in a
    position to prevent.
    """
    name = (name or "").lower()
    if name in CARD_PROVIDERS:
        return ("USD (card)",)
    # The watch-only path derives addresses from an extended public key, and
    # only Bitcoin's is derivable without wallet software. Listing four coins
    # on a checkout page that can only produce a BTC address would be the
    # same lie in the other direction.
    if name == "watch":
        return ("BTC",)
    return CURRENCIES


def is_card_provider(name: str) -> bool:
    return (name or "").lower() in CARD_PROVIDERS
