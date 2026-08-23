#!/usr/bin/env python3
"""
0trust visitor proxy.

A quick way to read a public page through our egress, and the top of the
funnel: after a few pages the banner offers a free trial of the real VPN.

It is deliberately NOT a general-purpose proxy — see guards.py for the rails
and why each one is there. Runs as its own service on its own port so that
abuse, blocklisting or a crash here cannot take the control plane with it.

  ZTV_PROXY_PORT        listen port                      (default 8081)
  ZTV_PROXY_PREFIX      public path clients see          (default /surf)
  ZTV_PROXY_BLOCKLIST   comma-separated host suffixes
  ZTV_PROXY_UA          User-Agent sent upstream
  ZTV_PROXY_TRIAL_AFTER pages before the trial offer     (default 3)
  ZTV_API_BASE          control plane, for the trial link and its length
  ZTV_TRIAL_DAYS        fallback trial length if the control plane is down
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import parse_qs, quote, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

from guards import (
    ALLOWED_METHODS, FETCH_TIMEOUT, MAX_BODY_BYTES, MAX_REDIRECTS,
    Blocked, check_url, content_type_allowed,
)
from rewrite import rewrite_css, rewrite_html

PORT = int(os.environ.get("ZTV_PROXY_PORT", "8081"))
PREFIX = os.environ.get("ZTV_PROXY_PREFIX", "/surf")
UA = os.environ.get(
    "ZTV_PROXY_UA",
    "Mozilla/5.0 (compatible; 0trust-surf/1.0; +https://0trustvpn.com/surf)")
TRIAL_AFTER = int(os.environ.get("ZTV_PROXY_TRIAL_AFTER", "3"))
BLOCKLIST = tuple(
    h.strip().lower().lstrip(".")
    for h in os.environ.get("ZTV_PROXY_BLOCKLIST", "").split(",")
    if h.strip()
)
API_BASE = os.environ.get("ZTV_API_BASE", "http://127.0.0.1:8080").rstrip("/")

# --- How long the trial is -------------------------------------------------
# An operator changes this in the admin dashboard, which writes it into the
# control plane's environment — not ours. A number typed into this banner would
# keep advertising last month's offer, so we ask the control plane and cache the
# answer. The env var is the fallback for a cold start or an API that is down;
# it is deliberately the same variable the API reads.
TRIAL_DAYS_FALLBACK = int(os.environ.get("ZTV_TRIAL_DAYS", "7"))
_TRIAL_TTL = 300
_trial_cache = {"ts": 0.0, "label": "", "days": TRIAL_DAYS_FALLBACK}


def _plain_label(days: int) -> str:
    """
    Local copy of the API's phrasing, for when the API cannot be reached.

    Kept word-for-word in step with duration_label() in api/main.py so a
    control plane blip changes nothing a visitor can see.
    """
    words = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six"}
    if days <= 0:
        return "no time at all"
    for size, unit in ((365, "year"), (30, "month"), (7, "week")):
        if days % size == 0:
            n = days // size
            if n in words:
                return f"{words[n]} {unit}" + ("" if n == 1 else "s")
            return f"{n} {unit}s"
    if days in words:
        return f"{words[days]} day" + ("" if days == 1 else "s")
    return f"{days} days"


def trial_label() -> str:
    """The offer, phrased. Cached for five minutes; never raises."""
    now = time.time()
    if _trial_cache["label"] and now - _trial_cache["ts"] < _TRIAL_TTL:
        return _trial_cache["label"]
    label, days = "", TRIAL_DAYS_FALLBACK
    try:
        req = urllib.request.Request(f"{API_BASE}/api/v1/config",
                                     headers={"User-Agent": "0trust-surf"})
        with urllib.request.urlopen(req, timeout=2) as r:
            trial = json.loads(r.read(65536) or b"{}").get("trial") or {}
        if int(trial.get("days") or 0) > 0:
            days = int(trial["days"])
            label = str(trial.get("label") or "")
    except Exception:
        pass                      # the fallback below is always sound
    _trial_cache.update(ts=now, days=days, label=label or _plain_label(days))
    return _trial_cache["label"]

app = FastAPI(title="0trust surf", docs_url=None, redoc_url=None, openapi_url=None)


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """
    Stop urllib following redirects on its own.

    Every hop has to go back through check_url, or a public hostname can
    redirect to 127.0.0.1 and walk straight past the guard that vetted the
    first URL.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise _Redirect(newurl)


class _Redirect(Exception):
    def __init__(self, location: str):
        self.location = location


def fetch(url: str, method: str = "GET") -> tuple[str, bytes, str, int]:
    """
    Fetch a vetted URL, following redirects manually with a guard check on
    each hop. Returns (final_url, body, content_type, status).
    """
    opener = urllib.request.build_opener(_NoRedirect)
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        current = check_url(current, BLOCKLIST)
        req = urllib.request.Request(
            current, method=method,
            headers={
                "User-Agent": UA,
                "Accept": "text/html,application/xhtml+xml,image/*;q=0.8,*/*;q=0.5",
                "Accept-Language": "en",
                # No Referer, no Cookie, no Authorization: the origin learns
                # nothing about the visitor beyond our egress IP.
            },
        )
        try:
            with opener.open(req, timeout=FETCH_TIMEOUT) as r:
                ct = r.headers.get("Content-Type", "")
                if not content_type_allowed(ct):
                    raise Blocked(f"The proxy does not serve {ct.split(';')[0]} content")
                # Read one byte past the cap so truncation is detectable.
                body = r.read(MAX_BODY_BYTES + 1)
                if len(body) > MAX_BODY_BYTES:
                    raise Blocked("That page is larger than the 5 MB proxy limit")
                return current, body, ct, r.status
        except _Redirect as e:
            current = urllib.parse.urljoin(current, e.location)
            continue
        except urllib.error.HTTPError as e:
            body = e.read(MAX_BODY_BYTES)
            return current, body, e.headers.get("Content-Type", "text/html"), e.code
        except urllib.error.URLError as e:
            raise Blocked(f"Could not reach that site ({e.reason})")
        except TimeoutError:
            raise Blocked("That site took too long to respond")
    raise Blocked("Too many redirects")


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------

def banner(target: str, views: int) -> str:
    """The upsell. Shown on every proxied page; sharpens after a few views."""
    host = urlsplit(target).hostname or target
    offer = trial_label()
    if views >= TRIAL_AFTER:
        pitch = (
            '<strong>You are reading through a shared proxy.</strong> '
            'It hides your IP from this site and nothing else — the page still '
            'sees a datacentre, your ISP still sees you connecting to us, and '
            'this only covers the browser tab. '
            f'<a class="ztv-cta" href="/trial?from=surf">Get {offer} of the real VPN, free</a>'
        )
    else:
        pitch = (
            f'Browsing <code>{host}</code> through 0trust. '
            'This proxy covers this tab only. '
            f'<a class="ztv-cta" href="/trial?from=surf">{offer} of the full VPN, free</a>'
        )
    return f"""
<div id="ztv-banner" style="all:initial;display:block;position:sticky;top:0;z-index:2147483647;
 background:#0c0c0a;color:#f4ede0;font:14px/1.5 ui-sans-serif,system-ui,sans-serif;
 padding:10px 14px;border-bottom:1px solid #2a2820">
  <span style="color:#d4a574;font-weight:600">0trust</span>
  <span style="opacity:.85;margin-left:8px">{pitch}</span>
  <form action="{PREFIX}" method="get" style="display:inline-block;margin-left:12px">
    <input name="url" placeholder="https://…" style="background:#161511;border:1px solid #2a2820;
      color:#f4ede0;padding:4px 8px;border-radius:4px;width:220px;font:13px ui-monospace,monospace">
  </form>
  <style>#ztv-banner .ztv-cta{{color:#0c0c0a;background:#d4a574;padding:3px 10px;
    border-radius:4px;text-decoration:none;font-weight:600;margin-left:6px}}</style>
</div>"""


def page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(status_code=status, content=f"""<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — 0trust</title>
<style>
 body{{background:#0c0c0a;color:#f4ede0;font:16px/1.6 ui-sans-serif,system-ui,sans-serif;
   max-width:44rem;margin:0 auto;padding:3rem 1.25rem}}
 a{{color:#d4a574}} code{{font-family:ui-monospace,monospace;color:#d4a574}}
 h1{{font-size:1.5rem;margin:0 0 1rem}}
 input,button{{font:inherit;padding:.6rem .8rem;border-radius:6px;border:1px solid #2a2820}}
 input{{background:#161511;color:#f4ede0;width:min(28rem,100%)}}
 button{{background:#d4a574;color:#0c0c0a;font-weight:600;border:0;cursor:pointer}}
 .note{{color:#8a8172;font-size:.9rem}}
</style>
{body}""")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _views(request: Request) -> int:
    try:
        return int(request.cookies.get("ztv_views", "0"))
    except ValueError:
        return 0


@app.get("/healthz")
def healthz():
    return {"status": "ok", "ts": int(time.time())}


@app.get(PREFIX, response_class=HTMLResponse)
async def surf(request: Request):
    raw = request.query_params.get("url", "").strip()
    if not raw:
        return page("Surf", f"""
<h1>Read a page through 0trust</h1>
<form action="{PREFIX}" method="get">
  <input name="url" placeholder="https://example.com" autofocus>
  <button type="submit">Go</button>
</form>
<p class="note">Public pages only, 5 MB max, no downloads or form submissions.
The site you visit sees our egress, not your address.</p>
<p class="note"><strong>This is not the VPN.</strong> It covers one browser tab.
Your ISP still sees you connecting to us, and nothing outside this tab is
affected. <a href="/trial?from=surf">Get {trial_label()} of the real thing, free.</a></p>""")

    if request.method not in ALLOWED_METHODS:
        return page("Not allowed", "<h1>Only GET is proxied</h1>", 405)

    try:
        final, body, ctype, status = fetch(raw)
    except Blocked as e:
        return page("Blocked", f"<h1>Can't fetch that</h1><p>{e}</p>"
                               f'<p><a href="{PREFIX}">Try another URL</a></p>', 400)

    views = _views(request) + 1
    base_ct = (ctype or "").split(";")[0].strip().lower()

    if base_ct in ("text/html", "application/xhtml+xml") or (not base_ct and b"<html" in body[:1024].lower()):
        text = body.decode("utf-8", errors="replace")
        out = rewrite_html(text, final, PREFIX, banner(final, views))
        resp: Response = HTMLResponse(out)
    elif base_ct == "text/css":
        resp = Response(rewrite_css(body.decode("utf-8", "replace"), final, PREFIX),
                        media_type="text/css")
    else:
        resp = Response(body, media_type=base_ct or "application/octet-stream")

    resp.set_cookie("ztv_views", str(views), max_age=86400,
                    httponly=True, samesite="lax", path="/")
    # The fetched page is hostile by default. It renders with scripts already
    # stripped, and this CSP is the backstop: no scripts, no framing us, no
    # form posts, and every subresource has to come back through the proxy.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'none'; object-src 'none'; frame-ancestors 'none'; "
        "form-action 'self'; base-uri 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    return resp


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots():
    # Keep proxied copies of other people's pages out of search indexes.
    return "User-agent: *\nDisallow: /\n"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
