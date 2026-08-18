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

import hashlib
import hmac
import json
import os
import urllib.error
import urllib.request
from typing import Any, Optional

# The three chains we accept. XMR is the private default; BTC is the one
# everyone already has; ZEC is here for shielded senders.
CURRENCIES = ("BTC", "XMR", "ZEC")

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

_PROVIDERS = {"btcpay": BTCPayProvider, "hosted": HostedProvider}
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
    """Drop the cached provider. Tests reconfigure between cases."""
    global _instance
    _instance = None
