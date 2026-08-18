"""
BTCPay Server client.

Docs: https://docs.btcpayserver.org/API/Greenfield/v1/

Auth: API key passed as `Authorization: token <key>` header. Create one at:
  Account → Manage Account → API Keys
  Permissions needed: btcpay.store.canviewinvoices, btcpay.store.cancreateinvoice
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


class BTCPayError(Exception):
    """Raised when BTCPay returns a non-2xx response."""


class BTCPayClient:
    def __init__(
        self,
        base_url: str | None = None,
        store_id: str | None = None,
        api_key: str | None = None,
        timeout: float = 10.0,
    ):
        self.base_url = (base_url or os.environ["BTCPAY_URL"]).rstrip("/")
        self.store_id = store_id or os.environ["BTCPAY_STORE_ID"]
        self.api_key = api_key or os.environ["BTCPAY_API_KEY"]
        self.timeout = timeout

    # ---------------------------------------------------------------- internal

    def _request(self, method: str, path: str, body: dict | None = None) -> Any:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"token {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                payload = r.read()
                return json.loads(payload) if payload else None
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            raise BTCPayError(f"{e.code} {e.reason}: {err_body}") from e
        except urllib.error.URLError as e:
            raise BTCPayError(f"BTCPay unreachable: {e.reason}") from e

    # ------------------------------------------------------------------ public

    def create_invoice(
        self,
        amount_usd: float,
        account_id: int,
        months: int,
        redirect_url: str | None = None,
    ) -> dict:
        """
        Create a new invoice. Returns the full BTCPay invoice object.

        Important fields in the response:
          id            : invoice ID (store this)
          checkoutLink  : hosted checkout URL we redirect the user to
          status        : New | Processing | Settled | Invalid | Expired
        """
        body = {
            "amount": f"{amount_usd:.2f}",
            "currency": "USD",
            "metadata": {
                "accountId": account_id,
                "months": months,
                "orderId": f"0trust-{account_id}-{months}m",
            },
            "checkout": {
                "speedPolicy": "MediumSpeed",      # 1 confirmation for BTC
                "expirationMinutes": 60,
                "monitoringMinutes": 90,
                "paymentMethods": ["BTC", "BTC-LightningNetwork", "XMR", "ETH", "LTC"],
                "defaultLanguage": "en-US",
                "redirectAutomatically": True,
            },
        }
        if redirect_url:
            body["checkout"]["redirectURL"] = redirect_url

        return self._request(
            "POST",
            f"/api/v1/stores/{self.store_id}/invoices",
            body=body,
        )

    def get_invoice(self, invoice_id: str) -> dict:
        return self._request(
            "GET",
            f"/api/v1/stores/{self.store_id}/invoices/{invoice_id}",
        )

    def get_payment_methods(self, invoice_id: str) -> list[dict]:
        """
        Returns one entry per supported payment method, each with:
          paymentMethod   : "BTC" | "XMR" | "ETH" | "LTC" | "BTC-LightningNetwork"
          destination     : address to pay to
          amount          : amount in the crypto's units (string)
          rate            : exchange rate to USD
          paymentLink     : BIP21-style URI for the QR code
        """
        return self._request(
            "GET",
            f"/api/v1/stores/{self.store_id}/invoices/{invoice_id}/payment-methods",
        )

    def archive_invoice(self, invoice_id: str) -> None:
        self._request(
            "DELETE",
            f"/api/v1/stores/{self.store_id}/invoices/{invoice_id}",
        )
