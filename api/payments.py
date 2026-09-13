"""
Payment providers.

0trust takes BTC, XMR and ZEC. The operator picks how, via ZTV_PAYMENT_PROVIDER:

  watch    THE DEFAULT. Derive a fresh receive address per invoice from the
           operator's extended PUBLIC key and ask a PUBLIC block explorer
           whether it was paid; for Monero, a view-only wallet against a
           public remote node. Non-custodial, no account signed up for
           anywhere, and no chain data on the control plane. The only
           provider that works on a VPS built this morning.
  btcpay   BTCPay Server — self-hosted, or somebody else's instance.
           Non-custodial: funds land in your wallet, the server only watches.
  hosted   A commercial crypto payment gateway with a REST API. No blockchain
           infrastructure at all, at the cost of the trade-offs below.
  stripe   Cards. A different product, not a different coin — see
  square   CARD_PROVIDERS below for why they are kept apart.

NONE of these requires this operator to run a Bitcoin, Monero or Zcash node,
and that is a hard constraint rather than a preference: `watch` reads public
explorers and a public Monero node, and pointing `btcpay` at a hosted BTCPay
puts the chain on somebody else's disk. Nothing in this file ever syncs,
stores or serves a blockchain. If you are about to add something that does,
it does not belong here.

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
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

import chainwatch
import monerowatch

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

# The provider assumed when nothing says otherwise.
#
# This was the literal "btcpay", written out at six call sites, and it was
# wrong in all of them: scripts/install.sh writes watch, watch is the only
# provider that works on a VPS with nothing signed up for anywhere, and
# btcpay means running a BTCPay Server with a chain behind it. An operator
# who copied systemd/api.env.example, or whose env file lost a line, silently
# got a provider they had not configured — and poll_invoices.py returns
# immediately unless the provider is watch, so that deployment would take
# payments to real addresses and credit none of them.
DEFAULT_PROVIDER = "watch"


def provider_name() -> str:
    """The configured provider's name, lowercased, with the default applied."""
    return (os.environ.get("ZTV_PAYMENT_PROVIDER")
            or DEFAULT_PROVIDER).strip().lower()

# Normalized invoice lifecycle, so main.py never sees provider vocabulary.
SETTLED = "settled"
PENDING = "pending"
EXPIRED = "expired"
# A settled invoice the operator has sent the money back for. terms.html §4
# promises a 30-day refund window, and until this existed there was nothing to
# record one: the operator sent the coins from their own wallet and the system
# knew nothing about it, so the account kept every day the payment had bought.
# Pay, use it for twenty-nine days, ask for the money back, keep the service.
REFUNDED = "refunded"
INVALID = "invalid"


# Atomic units per whole coin. Every balance comparison in this file is in
# atomic units: a float comparison against a payment is how you credit an
# account for 0.9999999 of what it owed.
COIN_UNITS = {"BTC": 10 ** 8, "ZEC": 10 ** 8, "XMR": 10 ** 12}

# Where a USD price comes from for a coin we take.
#
# The watch provider used to read BTC's price from the Esplora ticker at
# /v1/prices. That works on mempool.space and is not part of the Esplora API
# — an operator who points NODE_RPC_BTC at a different Esplora instance can
# lose the price feed while address lookups keep working, which fails in the
# confusing direction: invoices stop being created, and nothing about the
# explorer looks broken.
#
# So price is its own dependency now, named as one. Kraken's public ticker
# needs no account and quotes all three coins; ZTV_PRICE_API repoints it.
PRICE_API = "https://api.kraken.com/0/public/Ticker"
# Kraken's pair names. XBT is Bitcoin.
PRICE_PAIRS = {"BTC": "XBTUSD", "ZEC": "ZECUSD", "XMR": "XMRUSD"}


class PaymentError(Exception):
    """Provider returned a non-2xx, or was unreachable."""


# Nothing this module asks for is big. The largest legitimate answer is an
# Esplora address history — 25 transactions, tens of kilobytes — and the
# smallest is a Kraken ticker. 8 MB is two orders of magnitude of headroom.
#
# It is bounded at all because the other end is a third party by design: the
# whole point of the watch provider is that we run no chain of our own, so
# every settlement check is a request to a public explorer whose response
# size we do not control. Worse, an attacker has a cheap lever on it —
# invoice addresses are published to whoever is paying, and dust-spamming one
# inflates that address's history without limit. An unbounded r.read() on the
# once-a-minute poller turns that into memory exhaustion on the control
# plane. Truncation raises, the poller logs "chain check failed" and tries
# again next minute, and the invoice stays pending rather than being
# wrongly settled.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def _read_capped(r, what: str) -> bytes:
    """Read a response body, refusing anything over the cap."""
    payload = r.read(MAX_RESPONSE_BYTES + 1)
    if len(payload) > MAX_RESPONSE_BYTES:
        raise PaymentError(
            f"{what} returned more than {MAX_RESPONSE_BYTES} bytes; refusing to buffer it")
    return payload


def _http(method: str, url: str, headers: dict, body: dict | None = None,
          timeout: float = 15.0) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            # The HOST, not the URL. An explorer URL carries the customer's
            # payment address in its path, and this string ends up in a
            # PaymentError that poll_invoices logs — journald keeps that for
            # seven days, outliving the invoice row the sweeper garbage
            # collects. Which explorer misbehaved is the whole diagnostic;
            # whose address it was asking about is not.
            payload = _read_capped(r, urllib.parse.urlsplit(url).netloc or "the provider")
            return json.loads(payload) if payload else None
    except urllib.error.HTTPError as e:
        detail = e.read(4096).decode("utf-8", errors="replace")[:500]
        raise PaymentError(f"{e.code} {e.reason}: {detail}") from e
    except urllib.error.URLError as e:
        raise PaymentError(f"payment provider unreachable: {e.reason}") from e


# ---------------------------------------------------------------------------
# BTCPay Server
# ---------------------------------------------------------------------------

def usd_price(coin: str, api_base: str | None = None,
              timeout: float = 15.0) -> float:
    """
    One coin's USD price, from a public ticker.

    Raises rather than guessing. An invoice priced from a stale or absent
    feed is either a customer overpaying or a month sold for nothing, and
    both are worse than telling them to come back in a minute.
    """
    coin = coin.upper()
    pair = PRICE_PAIRS.get(coin)
    if pair is None:
        raise PaymentError(f"no price feed configured for {coin}")
    base = (api_base or os.environ.get("ZTV_PRICE_API") or PRICE_API).rstrip("/")
    raw = _http("GET", f"{base}?pair={pair}", {}, None, timeout) or {}
    if raw.get("error"):
        raise PaymentError(f"price feed error for {coin}: {raw['error'][:1]}")
    result = raw.get("result") or {}
    if not result:
        raise PaymentError(f"price feed returned nothing for {coin}")
    # Kraken keys the result by its own canonical pair name, which is not
    # always the one asked for (XBTUSD comes back as XXBTZUSD). There is
    # exactly one entry, so take it rather than guessing the name.
    entry = next(iter(result.values()))
    try:
        price = float((entry.get("c") or [0])[0])
    except (TypeError, ValueError, AttributeError):
        raise PaymentError(f"price feed gave no last-trade price for {coin}")
    if price <= 0:
        raise PaymentError(f"price feed returned {price} for {coin}")
    return price


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
                return json.loads(_read_capped(r, "Stripe") or b"{}")
        except urllib.error.HTTPError as e:
            raise PaymentError(
                f"{e.code}: {e.read(4096).decode('utf-8', 'replace')[:400]}") from e
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
    Crypto straight into the operator's own wallet, with nothing in between.

    Every other provider here puts a third party between the customer and the
    money: BTCPay is a server somebody has to run, and a hosted gateway is
    custodial and usually wants identity documents. This one needs neither,
    and it is the only provider that works on a fresh VPS with no accounts
    signed up for anywhere.

    Three coins, and they do NOT work the same way. The difference is not an
    implementation detail — it decides what a deployment can offer:

      BTC, ZEC   The operator pastes the PUBLIC half of their wallet. We
                 derive a fresh receive address per invoice from it and ask a
                 public explorer whether that address was paid. Zcash here
                 means TRANSPARENT addresses (t1…): shielded ones are private
                 by design and no explorer can answer for them.

      XMR        No address derivation and no explorer, because Monero
                 publishes neither recipient nor amount. Detection needs the
                 private view key and a block scan, which is a wallet. So we
                 talk to a view-only monero-wallet-rpc pointed at a PUBLIC
                 remote node — no chain on disk, no spending authority.
                 api/monerowatch.py explains the trade in full.

    What all three give up, stated plainly:

      - Confirmation comes from something we do not control: an explorer, or
        the remote node the wallet is scanning against. It can lie or go
        down. It cannot steal anything, and a wrong answer is recoverable by
        hand from the dashboard, but it is a dependency.
      - USD conversion comes from a public ticker, so the rate is theirs.

    There is no webhook. Confirmation is by polling, which is what makes this
    deployable without an inbound callback URL, a TLS certificate or a
    provider dashboard to configure.
    """

    # Esplora's API, which mempool.space, blockstream.info and any self-hosted
    # instance all speak identically.
    DEFAULT_API = {
        "BTC": "https://mempool.space/api",
        # Blockchair speaks a different shape; see _explorer_received. Any
        # Esplora-compatible Zcash endpoint can be set instead.
        "ZEC": "https://api.blockchair.com/zcash",
    }
    ENV_WALLET = {"BTC": "WALLET_BTC", "ZEC": "WALLET_ZEC"}
    ENV_API = {"BTC": "NODE_RPC_BTC", "ZEC": "NODE_RPC_ZEC"}

    def __init__(self, xpub=None, api_base=None, confirmations=None,
                 timeout=15.0):
        # `xpub` and `api_base` stay as the Bitcoin ones for compatibility
        # with every existing caller and test.
        self.wallets = {}
        for coin, env in self.ENV_WALLET.items():
            if coin == "BTC" and xpub is not None:
                value = xpub
            else:
                value = os.environ.get(env, "")
            self.wallets[coin] = (value or "").strip()
        self.xpub = self.wallets["BTC"]

        self.apis = {}
        for coin, env in self.ENV_API.items():
            if coin == "BTC" and api_base:
                self.apis[coin] = api_base.rstrip("/")
            else:
                self.apis[coin] = (os.environ.get(env)
                                   or self.DEFAULT_API[coin]).rstrip("/")
        self.api = self.apis["BTC"]

        self.confirmations = {
            "BTC": int(confirmations if confirmations is not None
                       else os.environ.get("ZTV_BTC_CONFIRMATIONS", "1")),
            # Zcash blocks are ~75s; the network convention is more than one.
            "ZEC": int(os.environ.get("ZTV_ZEC_CONFIRMATIONS", "5")),
        }
        self.timeout = timeout
        self._xmr = None

    # -- what this deployment can actually take -----------------------------
    def monero(self):
        """The view-only wallet, or None when one is not configured."""
        if not os.environ.get("MONERO_WALLET_RPC"):
            return None
        if self._xmr is None:
            self._xmr = monerowatch.MoneroWatcher(timeout=self.timeout)
        return self._xmr

    def supported(self) -> tuple[str, ...]:
        """
        The coins this deployment can issue an address for, right now.

        Not a constant: a coin with no wallet configured cannot be paid in,
        and offering it on the checkout would send a customer to an address
        that does not exist. currencies_for() asks this.
        """
        out = [c for c in ("BTC", "ZEC") if self.wallets.get(c)]
        if self.monero() is not None:
            out.append("XMR")
        return tuple(out)

    # -- addresses ---------------------------------------------------------
    def address_for(self, index: int, coin: str = "BTC") -> str:
        """
        The receive address for this invoice.

        A plain address in a wallet slot is accepted and reused, because some
        operators genuinely want that, but it is worse in every way: payments
        become impossible to attribute when two customers owe the same amount,
        and the whole payment history becomes public and linked. The dashboard
        says so.
        """
        coin = coin.upper()
        wallet = self.wallets.get(coin, "")
        if not wallet:
            raise PaymentError(
                f"{self.ENV_WALLET.get(coin, coin)} is not set — no wallet to pay into")
        if chainwatch.looks_like_xpub(wallet):
            return chainwatch.receive_address(wallet, index, coin=coin)
        return wallet

    def reuses_one_address(self, coin: str = "BTC") -> bool:
        w = self.wallets.get(coin.upper(), "")
        return bool(w) and not chainwatch.looks_like_xpub(w)

    # -- price -------------------------------------------------------------
    def price_usd(self, coin: str = "BTC") -> float:
        return usd_price(coin, timeout=self.timeout)

    def btc_price_usd(self) -> float:
        """Kept because callers and tests use it by name."""
        return self.price_usd("BTC")

    # -- provider interface -------------------------------------------------
    def create_invoice(self, amount_usd: float, account_id: int, months: int,
                       redirect_url: str | None = None,
                       index: int | None = None, coin: str = "BTC") -> dict:
        coin = (coin or "BTC").upper()
        if coin not in self.supported():
            raise PaymentError(
                f"{coin} is not configured on this deployment "
                f"(offering {', '.join(self.supported()) or 'nothing'})")
        units = COIN_UNITS[coin]
        atomic = int(round(amount_usd / self.price_usd(coin) * units))
        if atomic <= 0:
            raise PaymentError(f"computed a zero-value {coin} invoice")

        if coin == "XMR":
            # The wallet allocates the subaddress and tells us its index; we
            # do not choose it. That index, not the address, is what payment
            # detection keys on later.
            #
            # MoneroError is not a PaymentError — monerowatch has no reason to
            # know this module exists — so it has to be translated here. It
            # was not, and a wallet that was merely down turned signup into a
            # 500 with a stack trace instead of "processor unavailable".
            try:
                address, ref = self.monero().new_subaddress(
                    f"acct{account_id}-{months}m")
            except monerowatch.MoneroError as e:
                raise PaymentError(str(e)) from None
        else:
            if index is None:
                raise PaymentError("watch-only invoices need a derivation index")
            address, ref = self.address_for(index, coin), index

        return {
            # The invoice id is a CAPABILITY: /api/v1/payment/{id}/methods and
            # /status are deliberately unauthenticated, because the checkout
            # page polls them before the customer has any credential. So the
            # id has to be unguessable, and this one was not — it was the coin,
            # the derivation index (0, 1, 2, … sequential) and the unix second.
            # An attacker who opened one invoice of their own learned the
            # current index and the clock, and every other customer's id was a
            # handful of guesses away: their receive address, the amount owed,
            # and how much had arrived. On a product whose pitch is that
            # payments cannot be linked to each other, that is the link.
            #
            # The readable prefix stays for support and log-grepping; the
            # entropy is what makes it a capability. Nothing parses this id —
            # derivation_index is its own column — so the shape is free.
            "id": f"{coin.lower()}-{ref}-{secrets.token_urlsafe(18)}",
            # No hosted checkout to send anyone to: the customer pays from
            # their own wallet. The UI renders the address and a QR.
            "checkout_url": "",
            "status": PENDING,
            "payment_address": address,
            "amount_crypto": f"{atomic / units:.{8 if units == 10**8 else 12}f}",
            "derivation_index": ref,
            "pay_currency": coin,
            "raw": {"address": address, "atomic": atomic, "index": ref,
                    "coin": coin},
        }

    # -- chain lookups ------------------------------------------------------
    #
    # "Confirmed" below means AT LEAST self.confirmations blocks deep, not
    # "in a block". Those are the same thing only when the requirement is one.
    #
    # They were treated as the same thing for BTC and ZEC. ZTV_BTC_CONFIRMATIONS
    # and ZTV_ZEC_CONFIRMATIONS were read into self.confirmations, printed by
    # health(), and labelled in the dashboard as "confirmations before
    # crediting" — and then never consulted. An explorer's chain_stats counts
    # a transaction from the moment it is mined, so a Zcash invoice settled
    # one block deep while the operator had asked for five, and a reorg at
    # that depth is a month sold for nothing. Monero enforced its depth all
    # along (monerowatch.received), which is what made the gap easy to miss:
    # two of the three coins quietly ignored the setting.
    #
    # The one-confirmation case keeps the single cheap call it always used.
    # Depth costs an extra request, and only an operator who asked for depth
    # pays for it.

    def _esplora_received(self, api: str, address: str,
                          min_conf: int = 1) -> tuple[int, int]:
        if min_conf <= 1:
            raw = _http("GET", f"{api}/address/{address}", {}, None,
                        self.timeout) or {}
            chain = raw.get("chain_stats") or {}
            mem = raw.get("mempool_stats") or {}
            return int(chain.get("funded_txo_sum") or 0), int(
                mem.get("funded_txo_sum") or 0)

        # Depth needs per-transaction block heights and the current tip.
        # /blocks/tip/height answers with a bare integer.
        tip = int(_http("GET", f"{api}/blocks/tip/height", {}, None,
                        self.timeout) or 0)
        if tip <= 0:
            raise PaymentError(
                f"{api} did not report a chain tip — cannot tell how deep a "
                f"payment is, so it will not be credited")
        # Mempool transactions plus the most recent 25 confirmed ones.
        # Normally the payment is the only thing this address has ever seen.
        # It is not guaranteed to be: the address is published to whoever is
        # paying, and BIP84 derivation is sequential, so somebody who has
        # bought once can predict the next addresses and dust-spam them. Past
        # 25 confirmed transactions the real payment falls off this page and
        # is counted as nothing — the customer has paid and the invoice never
        # settles, with no error anywhere. The total below is what makes that
        # visible; without it the failure is silent, which is the part that
        # cannot be supported.
        summary = _http("GET", f"{api}/address/{address}", {}, None,
                        self.timeout) or {}
        funded_total = int((summary.get("chain_stats") or {}).get(
            "funded_txo_sum") or 0)
        txs = _http("GET", f"{api}/address/{address}/txs", {}, None,
                    self.timeout) or []
        deep = shallow = 0
        for tx in txs:
            paid = sum(int(v.get("value") or 0)
                       for v in (tx.get("vout") or [])
                       if v.get("scriptpubkey_address") == address)
            if not paid:
                continue
            status = tx.get("status") or {}
            height = status.get("block_height")
            if status.get("confirmed") and height is not None:
                depth = tip - int(height) + 1
            else:
                depth = 0
            if depth >= min_conf:
                deep += paid
            else:
                shallow += paid
        if deep + shallow < funded_total:
            # Some of what this address received is not on the page, so its
            # depth is unknown. Refuse rather than report the smaller figure:
            # the poller treats a raise as "ask again next minute", and the
            # log line names an address a human can look at. Counting the
            # rest as deep would be the opposite error — crediting money we
            # cannot see the depth of — and this is the direction that costs
            # a support ticket instead of a reorg.
            raise PaymentError(
                f"{api} paged out part of {address}'s history "
                f"({deep + shallow} of {funded_total} accounted for) — cannot "
                f"tell how deep the rest is, so it will not be credited")
        return deep, shallow

    # How many unspent outputs Blockchair returns for one address. At the cap
    # the list is truncated and nothing in the response says so.
    BLOCKCHAIR_UTXO_PAGE = 100

    def _blockchair_received(self, api: str, address: str,
                             min_conf: int = 1) -> tuple[int, int]:
        raw = _http("GET", f"{api}/dashboards/address/{address}", {}, None,
                    self.timeout) or {}
        data = (raw.get("data") or {}).get(address) or {}
        addr = data.get("address") or {}
        received = int(addr.get("received") or 0)
        unconfirmed = int(addr.get("unconfirmed_received") or 0)
        if min_conf <= 1:
            return received, unconfirmed

        tip = int((raw.get("context") or {}).get("state") or 0)
        utxo = data.get("utxo")
        if tip <= 0 or utxo is None:
            # Refuse rather than fall back to the shallow figure. Falling back
            # would silently reinstate exactly the bug this exists to close,
            # and the poller treats a raise as "ask again next minute" — a
            # late credit, not a wrong one.
            raise PaymentError(
                f"{api} did not report block heights for {address} — cannot "
                f"confirm {min_conf} blocks of depth, so it will not be credited")
        if len(utxo) >= self.BLOCKCHAIR_UTXO_PAGE:
            # Blockchair caps the UTXO list it returns. Past that cap this
            # reader fails in the DANGEROUS direction, not the safe one: the
            # `received - unspent` term below exists to count already-swept
            # outputs as confirmed, and a truncated list inflates exactly that
            # difference — so outputs whose depth was never seen get credited
            # as deep. That is the reorg risk the confirmations setting exists
            # to remove, arriving through the back door.
            #
            # A single-use invoice address does not accumulate a hundred
            # outputs on its own. One that has is being dusted, and the honest
            # answer is that we cannot account for it.
            raise PaymentError(
                f"{api} returned {len(utxo)} unspent outputs for {address}, "
                f"its page limit — the rest of the address's outputs are not "
                f"visible, so their depth cannot be confirmed and it will not "
                f"be credited")
        deep = unspent = 0
        for u in utxo:
            value = int(u.get("value") or 0)
            block = int(u.get("block_id") or -1)
            unspent += value
            if block > 0 and (tip - block + 1) >= min_conf:
                deep += value
        # Anything already spent out of this address was necessarily mined,
        # and the operator could only have swept it from a confirmed output.
        # Without this an address swept while its invoice was still open would
        # read as never paid — the utxo set is what Blockchair reports heights
        # for, and a swept output has left it. Safe only because the page-limit
        # check above rules out the other reason the two figures can differ.
        deep += max(0, received - unspent)
        return deep, max(unconfirmed, received - deep)

    def address_received(self, address: str, coin: str = "BTC",
                         min_conf: int | None = None) -> tuple[int, int]:
        """
        (confirmed, unconfirmed) atomic units received at an address, where
        confirmed means at least `min_conf` blocks deep.
        """
        coin = coin.upper()
        api = self.apis.get(coin, self.api)
        if min_conf is None:
            min_conf = self.confirmations.get(coin, 1)
        min_conf = max(1, int(min_conf))
        # Two explorer shapes, chosen by what the URL is rather than by coin,
        # so an operator who runs their own Esplora for Zcash gets the
        # Esplora path without a second setting to remember.
        if "blockchair" in api:
            return self._blockchair_received(api, address, min_conf)
        return self._esplora_received(api, address, min_conf)

    def check(self, address: str, expected_atomic: int, coin: str = "BTC",
              ref: int | None = None) -> dict:
        """
        Has this invoice been paid? Called by the poller, which owns crediting.

        Overpayment settles. Underpayment does not: crediting a month for half
        the price because the customer's wallet took a fee off the top is a
        revenue leak, and the amount received is reported so support can
        settle it by hand.
        """
        coin = (coin or "BTC").upper()
        if coin == "XMR":
            xmr = self.monero()
            if xmr is None:
                raise PaymentError("an XMR invoice exists but MONERO_WALLET_RPC "
                                   "is not configured")
            if ref is None:
                raise PaymentError("an XMR invoice has no subaddress index")
            try:
                confirmed, pending = xmr.received(int(ref))
            except monerowatch.MoneroError as e:
                raise PaymentError(str(e)) from None
            required = xmr.confirmations
        else:
            confirmed, pending = self.address_received(address, coin)
            required = max(1, int(self.confirmations.get(coin, 1)))

        paid = confirmed >= expected_atomic
        return {
            "status": SETTLED if paid else PENDING,
            "coin": coin,
            "confirmed_sats": confirmed,
            "unconfirmed_sats": pending,
            "expected_sats": expected_atomic,
            # How deep this deployment wants a payment before it counts. The
            # customer's money can be on the chain and this still be PENDING,
            # which looks like nothing happening unless somebody says why.
            "confirmations_required": required,
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
        coins = self.supported()
        if not coins:
            return False, ("no wallet configured — set WALLET_BTC, WALLET_ZEC, "
                           "or MONERO_WALLET_RPC")
        notes, failed = [], []
        for coin in coins:
            if coin == "XMR":
                ok, detail = self.monero().health()
                (notes if ok else failed).append(f"XMR: {detail}")
                continue
            try:
                addr = self.address_for(0, coin)
            except Exception as e:
                failed.append(f"{coin}: wallet unusable: {e}")
                continue
            try:
                price = self.price_usd(coin)
            except PaymentError as e:
                failed.append(f"{coin}: price feed: {str(e)[:80]}")
                continue
            where = "one reused address" if self.reuses_one_address(coin) \
                else f"first address {addr}"
            notes.append(f"{coin}: ${price:,.2f}, "
                         f"{self.confirmations.get(coin, 1)} conf, {where}")
        if failed:
            return False, "; ".join(failed + notes)[:400]
        return True, "; ".join(notes)[:400]


# ---------------------------------------------------------------------------

_PROVIDERS = {"btcpay": BTCPayProvider, "hosted": HostedProvider,
              "stripe": StripeProvider, "square": SquareProvider,
              "watch": WatchOnlyProvider}
_instance = None


def provider():
    """Lazy singleton, so missing config doesn't break module import."""
    global _instance
    if _instance is None:
        name = provider_name()
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
    # Just a wallet. No account anywhere, no callback URL, no secret to
    # share — which is what lets a fresh VPS take money the day it is built.
    # Any ONE of these is enough; required_settings() resolves that, because a
    # Zcash-only deployment is a real configuration and telling its operator
    # that WALLET_BTC is "missing" would be wrong.
    "watch": ("WALLET_BTC",),
    "btcpay": ("BTCPAY_URL", "BTCPAY_STORE_ID", "BTCPAY_API_KEY",
               "BTCPAY_WEBHOOK_SECRET"),
    "hosted": ("ZTV_PAYMENT_API_URL", "ZTV_PAYMENT_API_KEY",
               "ZTV_PAYMENT_IPN_SECRET"),
    "stripe": ("STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"),
    "square": ("SQUARE_ACCESS_TOKEN", "SQUARE_LOCATION_ID", "SQUARE_WEBHOOK_KEY"),
}


def required_settings(name: str) -> tuple[str, ...]:
    name = (name or "").lower()
    if name == "watch":
        # Satisfied by any configured wallet. Naming BTC when the operator has
        # deliberately set up Zcash only would send them to fix a non-problem.
        try:
            if provider().supported():
                return ()
        except Exception:
            pass
        return ("WALLET_BTC (or WALLET_ZEC, or MONERO_WALLET_RPC)",)
    return REQUIRED_SETTINGS.get(name, ())


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
    # The watch-only path can take whatever it has a wallet for, which is a
    # property of this deployment's configuration rather than of the code.
    # Asking the provider is the only answer that cannot drift: listing a coin
    # here that no wallet backs would send a customer to an address that does
    # not exist.
    if name == "watch":
        try:
            return provider().supported() or ()
        except Exception:
            return ()
    return CURRENCIES


def confirmations_for(name: str) -> dict:
    """
    Blocks of depth each offered coin needs before an invoice is credited.

    Published by /api/v1/config so no page has to hardcode it. The site said
    "activates on the first confirmation", which is true for Bitcoin at the
    default and false for Zcash (five) and Monero (ten) — a specific,
    checkable claim about a customer's money that two of the three coins did
    not honour. The numbers are settings, so the only way copy stays true is
    to read them rather than restate them.
    """
    name = (name or "").lower()
    if name != "watch":
        return {}
    try:
        prov = provider()
    except Exception:
        return {}
    out = {}
    for coin in prov.supported():
        if coin == "XMR":
            xmr = prov.monero()
            if xmr is not None:
                out[coin] = int(xmr.confirmations)
        else:
            out[coin] = max(1, int(prov.confirmations.get(coin, 1)))
    return out


def is_card_provider(name: str) -> bool:
    return (name or "").lower() in CARD_PROVIDERS
