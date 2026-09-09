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

import html
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




# Every response, not just the proxied one.
#
# These were set only on the success path, so the error page — the one that
# reflects whatever you put in ?url= — went out with no CSP at all. The
# reflected value is escaped now, but a page that renders somebody else's
# string should not be relying on the escaping alone, and `script-src 'none'`
# costs nothing here because none of these pages run any script.
#
# `default-src 'self'` also forces every subresource of a proxied page back
# through us, which is what keeps the site from seeing the visitor directly.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; script-src 'none'; object-src 'none'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Robots-Tag": "noindex, nofollow",
    "X-Frame-Options": "DENY",
}


@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp
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
            # An error response is still a response, and it gets the same
            # rails. This branch used to return the origin's Content-Type
            # unchecked, so any site could hand us a payload of any type by
            # serving it with a 404: application/pdf, application/zip,
            # video/mp4, application/octet-stream — none of which the success
            # path will carry — and we would serve it from our own origin.
            # The CSP's `script-src 'none'` is what kept that from being an
            # XSS on 0trustvpn.com rather than anything on this path, and a
            # security rail that only holds on 2xx is not a rail.
            ct = e.headers.get("Content-Type", "text/html")
            if not content_type_allowed(ct):
                raise Blocked(
                    f"The proxy does not serve {ct.split(';')[0]} content")
            # One byte past the cap, as above, so an oversized body is
            # refused rather than silently truncated and rendered as though
            # it were the whole page.
            body = e.read(MAX_BODY_BYTES + 1)
            if len(body) > MAX_BODY_BYTES:
                raise Blocked("That page is larger than the 5 MB proxy limit")
            return current, body, ct, e.code
        except urllib.error.URLError as e:
            raise Blocked(f"Could not reach that site ({e.reason})")
        except TimeoutError:
            raise Blocked("That site took too long to respond")
    raise Blocked("Too many redirects")


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------

def esc(value) -> str:
    """
    HTML-escape anything that came from outside this file.

    /surf?url=<attacker string> reached the error page unescaped, so
    `?url=http://<img src=x onerror=…>.test/` reflected the payload straight
    into the response — and the error path set no CSP at all, while nginx's
    site-wide policy allows 'unsafe-inline', so it would have executed either
    way. Reflected XSS on the funnel's front door, which is the single page
    whose whole job is being trustworthy.

    Everything interpolated into HTML below goes through this: the hostname,
    the exception text, and the trial label the control plane hands us.
    """
    return html.escape(str(value), quote=True)


def banner(target: str, views: int) -> str:
    """
    The upsell. Shown on every proxied page; sharpens after a few views.

    Everything here is inline or inside a `#ztv-banner`-scoped <style>, and the
    container carries `all:initial`, because this bar rides on top of somebody
    else's stylesheet and that stylesheet is hostile by assumption.

    System fonts on purpose: the proxied response sets `default-src 'self'`, so
    a webfont from anywhere else is blocked outright. The landing page has no
    such restriction and does use the brand faces.
    """
    host = urlsplit(target).hostname or target
    offer = trial_label()
    if views >= TRIAL_AFTER:
        pitch = (
            '<strong>You are reading through a shared proxy.</strong> '
            'It hides your IP from this site and nothing else — the page still '
            'sees a datacentre, your ISP still sees you connecting to us, and '
            'this only covers the browser tab.'
        )
        cta = f'Get {esc(offer)} of the real VPN, free'
    else:
        pitch = (f'Browsing <code>{esc(host)}</code> through 0trust. '
                 'This proxy covers this tab only.')
        cta = f'{esc(offer)} of the full VPN, free'
    return f"""
<div id="ztv-banner" style="all:initial;display:block;position:sticky;top:0;
 z-index:2147483647;background:#0c0c0a;color:#f4ede0;
 font:14px/1.5 ui-sans-serif,system-ui,-apple-system,sans-serif;
 border-bottom:1px solid #2a2820;box-shadow:0 1px 0 rgba(212,165,116,.18),
 0 6px 24px -12px rgba(0,0,0,.9)">
  <div class="ztv-row">
    <span class="ztv-mark">0trust</span>
    <span class="ztv-pitch">{pitch}</span>
    <form action="{PREFIX}" method="get" class="ztv-form">
      <input name="url" placeholder="Read another page…" aria-label="URL to read">
    </form>
    <a class="ztv-cta" href="/trial?from=surf">{cta}</a>
  </div>
  <style>
    #ztv-banner *{{box-sizing:border-box}}
    #ztv-banner .ztv-row{{display:flex;align-items:center;gap:14px;
      flex-wrap:wrap;max-width:1180px;margin:0 auto;padding:10px 18px}}
    #ztv-banner .ztv-mark{{font:600 14px/1 ui-monospace,SFMono-Regular,
      Menlo,monospace;letter-spacing:.04em;color:#d4a574;flex:none;
      padding-right:14px;border-right:1px solid #2a2820}}
    #ztv-banner .ztv-pitch{{flex:1 1 22rem;min-width:0;color:#cfc7b8}}
    #ztv-banner .ztv-pitch strong{{color:#f4ede0;font-weight:600}}
    #ztv-banner code{{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;
      color:#d4a574;background:#161511;border:1px solid #2a2820;
      border-radius:4px;padding:1px 6px}}
    #ztv-banner .ztv-form{{flex:0 1 15rem;margin:0}}
    #ztv-banner input{{width:100%;background:#161511;color:#f4ede0;
      border:1px solid #2a2820;border-radius:6px;padding:6px 10px;
      font:13px ui-monospace,SFMono-Regular,Menlo,monospace;outline:none;
      transition:border-color .15s,box-shadow .15s}}
    #ztv-banner input::placeholder{{color:#6f6858}}
    #ztv-banner input:focus{{border-color:#d4a574;
      box-shadow:0 0 0 3px rgba(212,165,116,.16)}}
    #ztv-banner .ztv-cta{{flex:none;color:#0c0c0a;background:#d4a574;
      padding:7px 14px;border-radius:6px;text-decoration:none;
      font-weight:600;font-size:13px;white-space:nowrap;
      transition:background .15s,transform .15s}}
    #ztv-banner .ztv-cta:hover{{background:#e0b689;transform:translateY(-1px)}}
    @media (max-width:720px){{
      #ztv-banner .ztv-row{{gap:10px;padding:9px 14px}}
      #ztv-banner .ztv-form{{order:3;flex:1 1 100%}}
      #ztv-banner .ztv-cta{{order:2}}
    }}
  </style>
</div>"""


# The brand faces, served from our own box.
#
# This linked fonts.googleapis.com, like the rest of the site did. On THIS page
# that was a contradiction: /surf exists to stop a site learning who is reading
# it, and the first thing it did was tell Google. Self-hosting also drops a
# render-blocking round trip to a third party on the funnel's front door.
#
# nginx serves /fonts from the webroot, so the same path works for the proxy's
# own pages and for the rest of the site. A proxied response sets
# `default-src 'self'`, which permits these and blocks anything else — the
# banner is still built for system fonts regardless, because it has to render
# before anything loads.
FONTS = '<link rel="stylesheet" href="/fonts/faces.css">'

# Every face has a real fallback stack: the page has to look deliberate before
# the webfont arrives, and stay that way if it never does.
CSS = """
 *{box-sizing:border-box}
 body{background:#0c0c0a;color:#f4ede0;margin:0;
   font:400 16px/1.65 'IBM Plex Sans',ui-sans-serif,system-ui,sans-serif;
   -webkit-font-smoothing:antialiased}
 /* A single soft light source behind the hero, so the page has depth without
    anything moving or loading. */
 body::before{content:'';position:fixed;inset:0;pointer-events:none;
   background:radial-gradient(60rem 32rem at 50% -14rem,
     rgba(212,165,116,.10),transparent 70%)}
 .wrap{position:relative;max-width:46rem;margin:0 auto;padding:5rem 1.25rem 4rem}
 .mark{font:600 13px/1 'JetBrains Mono',ui-monospace,monospace;
   letter-spacing:.12em;text-transform:uppercase;color:#d4a574;
   display:block;margin-bottom:1.75rem}
 h1{font:400 clamp(2.1rem,5.5vw,3rem)/1.12 'Instrument Serif',Georgia,serif;
   margin:0 0 .85rem;letter-spacing:-.01em}
 .lede{color:#a99f8d;font-size:1.05rem;margin:0 0 2.25rem;max-width:34rem}
 /* One control, not two boxes: the button sits inside the field. */
 .field{display:flex;align-items:center;gap:.5rem;background:#141310;
   border:1px solid #2a2820;border-radius:10px;padding:.45rem .45rem .45rem .9rem;
   transition:border-color .15s,box-shadow .15s}
 .field:focus-within{border-color:#d4a574;
   box-shadow:0 0 0 4px rgba(212,165,116,.14)}
 .field input{flex:1;min-width:0;background:none;border:0;outline:none;
   color:#f4ede0;font:15px/1.4 'JetBrains Mono',ui-monospace,monospace;
   padding:.55rem 0}
 .field input::placeholder{color:#6f6858}
 .field button{flex:none;background:#d4a574;color:#0c0c0a;border:0;
   border-radius:7px;cursor:pointer;padding:.6rem 1.35rem;
   font:600 15px/1 'IBM Plex Sans',system-ui,sans-serif;
   transition:background .15s,transform .15s}
 .field button:hover{background:#e0b689;transform:translateY(-1px)}
 .facts{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;
   background:#2a2820;border:1px solid #2a2820;border-radius:10px;
   overflow:hidden;margin:1.5rem 0 2.5rem}
 .facts div{background:#0f0e0c;padding:.95rem 1rem}
 .facts dt{font:500 11px/1 'JetBrains Mono',ui-monospace,monospace;
   letter-spacing:.1em;text-transform:uppercase;color:#7d8f5a;margin-bottom:.4rem}
 .facts dd{margin:0;font-size:.9rem;color:#cfc7b8}
 /* The honest part. Given its own frame in the warning colour, because
    burying it would be the one thing this page must not do. */
 .limits{border:1px solid #2a2820;border-left:2px solid #c44536;
   border-radius:8px;background:#100e0c;padding:1.15rem 1.25rem;margin:0 0 2rem}
 .limits h2{font:600 12px/1 'JetBrains Mono',ui-monospace,monospace;
   letter-spacing:.1em;text-transform:uppercase;color:#c44536;margin:0 0 .6rem}
 .limits p{margin:0;color:#a99f8d;font-size:.94rem}
 .limits strong{color:#f4ede0}
 .cta{display:inline-block;margin-top:1.1rem;background:none;color:#d4a574;
   border:1px solid #d4a574;border-radius:7px;padding:.6rem 1.15rem;
   text-decoration:none;font-weight:600;font-size:.94rem;
   transition:background .15s,color .15s}
 .cta:hover{background:#d4a574;color:#0c0c0a}
 a{color:#d4a574}
 code{font-family:'JetBrains Mono',ui-monospace,monospace;color:#d4a574}
 .note{color:#8a8172;font-size:.9rem}
 h1+.note{margin-top:0}
 @media (max-width:620px){
   .wrap{padding:3.25rem 1.1rem 3rem}
   .facts{grid-template-columns:1fr}
   .field{flex-wrap:wrap}
   .field button{width:100%}
 }
"""


def page(title: str, body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(status_code=status, content=f"""<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — 0trust</title>
{FONTS}
<style>{CSS}</style>
<div class="wrap">{body}</div>""")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def _views(request: Request) -> int:
    try:
        return int(request.cookies.get("ztv_views", "0"))
    except ValueError:
        return 0


# In production nginx serves /fonts from the webroot and never routes it here.
# Mounting it anyway means `uvicorn server:app` on its own renders the page
# correctly — a reviewer or a developer should not need the whole nginx stack
# to see what the funnel's front door looks like.
_FONTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "web", "fonts")
if os.path.isdir(_FONTS_DIR):
    from fastapi.staticfiles import StaticFiles
    app.mount("/fonts", StaticFiles(directory=_FONTS_DIR), name="fonts")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "ts": int(time.time())}


# Deliberately `def`, not `async def`.
#
# The body of this handler blocks: fetch() is urllib, and it will sit on a
# socket for FETCH_TIMEOUT (12s) per hop across up to MAX_REDIRECTS+1 hops,
# then read up to 5 MB from whatever trickle the origin is sending. As an
# `async def` all of that ran ON the event loop, so a single visitor pointing
# ?url= at a slow host froze that worker — every other visitor's request,
# including the front page, waited behind it. Two of them (the unit runs
# --workers 2) took /surf down completely, from an unauthenticated GET that
# anybody can send. This is the most exposed thing we run and the cheapest
# possible denial of service against it.
#
# A plain `def` hands the whole handler to Starlette's threadpool, so a slow
# origin occupies one thread instead of the entire worker. trial_label()'s
# 2s call to the control plane rides along in the same thread.
@app.get(PREFIX, response_class=HTMLResponse)
def surf(request: Request):
    raw = request.query_params.get("url", "").strip()
    if not raw:
        return page("Surf", f"""
<span class="mark">0trust &middot; surf</span>
<h1>Read a page through 0trust</h1>
<p class="lede">Paste a link. We fetch it, strip the scripts, and hand you the
text — so the site sees our egress instead of your address.</p>

<form action="{PREFIX}" method="get">
  <div class="field">
    <input name="url" placeholder="https://example.com/article" autofocus
           aria-label="Address to read">
    <button type="submit">Surf it</button>
  </div>
</form>

<dl class="facts">
  <div><dt>Fetches</dt><dd>Public pages, GET only</dd></div>
  <div><dt>Limit</dt><dd>5&nbsp;MB, no downloads</dd></div>
  <div><dt>Scripts</dt><dd>Removed before render</dd></div>
</dl>

<section class="limits">
  <h2>What this is not</h2>
  <p><strong>This is not the VPN.</strong> It covers one browser tab. Your ISP
  still sees you connecting to us, the page you read still lands on a
  datacentre address shared with everyone else using it, and nothing outside
  this tab is affected.</p>
  <a class="cta" href="/trial?from=surf">Get {trial_label()} of the real thing, free</a>
</section>""")

    if request.method not in ALLOWED_METHODS:
        return page("Not allowed", f"""
<span class="mark">0trust &middot; surf</span>
<h1>Only GET is proxied</h1>
<p class="lede">This is a reader, not a relay: it will not submit forms or
send anything on your behalf.</p>
<p><a class="cta" href="{PREFIX}">Back to surf</a></p>""", 405)

    try:
        final, body, ctype, status = fetch(raw)
    except Blocked as e:
        return page("Blocked", f"""
<span class="mark">0trust &middot; surf</span>
<h1>Can&rsquo;t fetch that</h1>
<p class="lede">{esc(e)}</p>
<form action="{PREFIX}" method="get">
  <div class="field">
    <input name="url" placeholder="https://example.com/article" autofocus
           aria-label="Address to read">
    <button type="submit">Surf it</button>
  </div>
</form>""", 400)

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
    return resp


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots():
    # Keep proxied copies of other people's pages out of search indexes.
    return "User-agent: *\nDisallow: /\n"


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
