"""
HTML rewriting for the visitor proxy.

Every URL in a fetched page has to be pointed back at us, or the visitor's
browser goes straight to the origin and the "you are browsing through 0trust"
claim becomes false — which for this product is worse than the feature being
absent. Rewriting also strips the parts of a page that would leak the visitor
or execute in our origin's context.

Deliberately a tokenizer rather than a full DOM parse: no third-party
dependency, and a page we half-understand degrades into a page with some
un-proxied links rather than a crash. What we do NOT do is pretend to sanitize
hostile HTML — the response is served from a sandboxed origin with a strict
CSP (see server.py), which is what actually contains it.
"""

from __future__ import annotations

import html.parser
import io
import re
from urllib.parse import quote, urljoin, urlsplit

# Attributes carrying a single URL.
URL_ATTRS = {
    "a": ("href",), "img": ("src", "longdesc"), "script": ("src",),
    "link": ("href",), "iframe": ("src",), "form": ("action",),
    "video": ("src", "poster"), "audio": ("src",), "source": ("src",),
    "embed": ("src",), "object": ("data",), "track": ("src",),
    "input": ("src",), "area": ("href",), "base": ("href",),
}

# Dropped outright: trackers, page-controlled navigation, and anything that
# would run before the visitor sees the banner.
DROP_TAGS = {"script", "noscript", "object", "embed", "applet"}
DROP_ATTR_PREFIX = ("on",)          # onclick, onload, ...
DROP_ATTRS = {"integrity", "nonce", "crossorigin", "ping", "srcset"}

# Dropped only on the tags where they mean navigation, NOT everywhere.
#
# The code claimed to "make every link open in the same tab so the banner
# stays put" and only added rel — target="_blank" sailed straight through and
# the link opened a fresh tab with no banner in it. An existing rel was worse:
# it was not removed, so a page carrying rel="opener" emitted TWO rel
# attributes and the browser takes the first, which is the page's, defeating
# the noopener the code thought it had applied.
#
# Per-tag because rel is not only a link relation on <a>: dropping it globally
# takes it off <link rel="stylesheet"> too, and a <link> with no rel is
# ignored — every proxied page renders unstyled. That is what the first
# version of this did, which is a fair reminder that a fix aimed at one tag
# does not belong in a set that applies to all of them.
DROP_ATTRS_BY_TAG = {
    "a": {"target", "rel"},
    "area": {"target", "rel"},
    "form": {"target"},
    "base": {"target"},
}

CSS_URL_RE = re.compile(r"""url\(\s*(['"]?)([^'")]+)\1\s*\)""", re.I)

# @import without url(): `@import "x.css";` or `@import 'x.css' screen;`.
# The url() form is already covered above. Left alone, the browser resolves it
# against the ORIGIN. The CSP (`style-src 'self'`) blocks that fetch, so this
# is a rendering fix rather than a leak — the stylesheet simply never loaded.
CSS_IMPORT_RE = re.compile(r"""(@import\s+)(['"])([^'"]+)\2""", re.I)

# <meta http-equiv="refresh" content="0; url=...">
#
# This walked straight through the rewriter, and it is the one thing in a page
# that can move the visitor's browser off the proxy on its own. No CSP
# directive stops a meta refresh — form-action covers forms and
# frame-ancestors covers framing, but top-level navigation is not restricted
# by anything that ships — so the origin got a direct connection from the
# visitor, with their address, while our banner said they were browsing
# through us. This module's own docstring calls that outcome worse than the
# feature being absent.
#
# Rewritten rather than dropped: a page that redirects is doing something
# legitimate most of the time, and dropping it breaks the page instead of
# fixing the leak.
META_REFRESH_RE = re.compile(r"""^(\s*[\d.]*\s*;\s*url\s*=\s*)(['"]?)(.*?)\2\s*$""",
                             re.I | re.S)


def proxied(url: str, base: str, prefix: str) -> str:
    """Absolutize against the page, then point it back at the proxy."""
    if not url:
        return url
    stripped = url.strip()
    low = stripped.lower()
    # Leave in-page anchors and non-navigational schemes alone. mailto: and
    # tel: are the user's business; data: and javascript: are dropped by the
    # CSP and shouldn't be rewritten into something that looks proxied.
    if low.startswith(("#", "mailto:", "tel:", "data:", "javascript:", "about:")):
        return stripped
    absolute = urljoin(base, stripped)
    if urlsplit(absolute).scheme not in ("http", "https"):
        return stripped
    return f"{prefix}?url={quote(absolute, safe='')}"


def rewrite_css(text: str, base: str, prefix: str) -> str:
    text = CSS_URL_RE.sub(
        lambda m: f"url({m.group(1)}{proxied(m.group(2), base, prefix)}{m.group(1)})",
        text,
    )
    return CSS_IMPORT_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}"
                  f"{proxied(m.group(3), base, prefix)}{m.group(2)}",
        text,
    )


def rewrite_meta_refresh(content: str, base: str, prefix: str) -> str:
    """Point a meta refresh's target back at the proxy, or leave it alone.

    `content` is "<seconds>" or "<seconds>; url=<target>". Only the second
    form navigates anywhere; the first reloads the current page, which is
    already ours.
    """
    m = META_REFRESH_RE.match(content or "")
    if not m:
        return content
    target = m.group(3).strip()
    if not target:
        return content
    return f"{m.group(1)}{m.group(2)}{proxied(target, base, prefix)}{m.group(2)}"


class _Rewriter(html.parser.HTMLParser):
    def __init__(self, base: str, prefix: str, banner: str):
        super().__init__(convert_charrefs=False)
        self.base = base
        self.prefix = prefix
        self.banner = banner
        self.out = io.StringIO()
        self._skip_depth = 0
        self._in_style = False
        self._banner_done = False

    # -- helpers ----------------------------------------------------------
    def _emit(self, s: str):
        if self._skip_depth == 0:
            self.out.write(s)

    def _attrs(self, tag: str, attrs) -> str:
        parts = []
        # A meta refresh is the one attribute whose meaning depends on another
        # attribute of the same tag, so the tag is inspected before the loop.
        is_refresh = tag == "meta" and any(
            k.lower() == "http-equiv" and (v or "").strip().lower() == "refresh"
            for k, v in attrs)
        for k, v in attrs:
            kl = k.lower()
            if (kl.startswith(DROP_ATTR_PREFIX) or kl in DROP_ATTRS
                    or kl in DROP_ATTRS_BY_TAG.get(tag, ())):
                continue
            if v is None:
                parts.append(f" {k}")
                continue
            if kl in URL_ATTRS.get(tag, ()):
                v = proxied(v, self.base, self.prefix)
            elif kl == "style":
                v = rewrite_css(v, self.base, self.prefix)
            elif is_refresh and kl == "content":
                v = rewrite_meta_refresh(v, self.base, self.prefix)
            parts.append(f' {k}="{html_escape(v)}"')
        # target and rel were dropped above, so these are the only ones: the
        # link opens in this tab, where the banner is, and the destination
        # gets no window.opener.
        if tag == "a":
            parts.append(' rel="noopener noreferrer"')
        return "".join(parts)

    # -- parser callbacks -------------------------------------------------
    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t in DROP_TAGS:
            self._skip_depth += 1
            return
        # <base> would re-point every relative URL past the proxy.
        if t == "base":
            return
        if t == "style":
            self._in_style = True
        self._emit(f"<{tag}{self._attrs(t, attrs)}>")
        if t == "body" and not self._banner_done:
            self._banner_done = True
            self._emit(self.banner)

    def handle_startendtag(self, tag, attrs):
        t = tag.lower()
        if t in DROP_TAGS or t == "base":
            return
        self._emit(f"<{tag}{self._attrs(t, attrs)} />")

    def handle_endtag(self, tag):
        t = tag.lower()
        if t in DROP_TAGS:
            if self._skip_depth:
                self._skip_depth -= 1
            return
        if t == "base":
            return
        if t == "style":
            self._in_style = False
        self._emit(f"</{tag}>")

    def handle_data(self, data):
        if self._in_style:
            self._emit(rewrite_css(data, self.base, self.prefix))
        else:
            self._emit(data)

    def handle_comment(self, data):
        # Conditional comments can smuggle markup past the tokenizer.
        pass

    def handle_entityref(self, name):
        self._emit(f"&{name};")

    def handle_charref(self, name):
        self._emit(f"&#{name};")

    def handle_decl(self, decl):
        self._emit(f"<!{decl}>")


def html_escape(v: str) -> str:
    return (v.replace("&", "&amp;").replace('"', "&quot;")
             .replace("<", "&lt;").replace(">", "&gt;"))


def rewrite_html(body: str, base: str, prefix: str, banner: str) -> str:
    r = _Rewriter(base, prefix, banner)
    r.feed(body)
    r.close()
    out = r.out.getvalue()
    if not r._banner_done:
        # No <body> tag (fragment, or malformed) — prepend so the visitor can
        # always find their way back.
        out = banner + out
    return out
