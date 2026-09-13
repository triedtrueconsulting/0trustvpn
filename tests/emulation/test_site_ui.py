#!/usr/bin/env python3
"""
The site's shared chrome, in a real browser.

test_site.py reads the HTML; this one renders it. Everything caught here was
invisible to source-level checks and would have shipped:

  - the nav CTA drew amber text on an amber button, because `.sitenav-links a`
    (0,1,1) out-specified `.sitenav-cta` (0,1,0). Perfectly valid markup,
    perfectly valid CSS, an unreadable button.
  - on a phone the CTA sat past the right edge of a scrolling link list, so
    the one control these pages exist to offer was simply not on screen.
  - between the desktop layout and the 900px breakpoint the link row pushed
    the whole document into a horizontal scroll.

So: render every public page at five widths and assert the bar behaves.

Skips (77) without Playwright or a browser.
"""
import glob, http.server, functools, os, socket, sys, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("  SKIP  playwright not installed")
    sys.exit(77)

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

WEB = os.path.join(H.REPO, "web")
PORT = H.pick_port()

ROUTES = {"/trial": "/trial.html", "/status": "/status.html",
          "/download": "/download.html", "/help": "/help.html",
          "/privacy": "/privacy.html", "/terms": "/terms.html",
          "/audit": "/audit.html", "/security-policy": "/security-policy.html"}

# Pages are served from web/ with the nginx path rewrites, and nothing else:
# no control plane, no fonts. The bar's geometry must not depend on either.
class Site(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        path = self.path.split("?")[0].split("#")[0]
        if path in ROUTES:
            self.path = ROUTES[path]
        elif path == "/surf":
            body = b"<html><body>surf</body></html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body); return
        return super().do_GET()

srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT),
                                      functools.partial(Site, directory=WEB))
threading.Thread(target=srv.serve_forever, daemon=True).start()

PAGES = ["/", "/download", "/help", "/status", "/audit",
         "/privacy", "/terms", "/security-policy", "/trial"]

# 1024 is the gap the old breakpoint left open; 901 is one pixel above it.
WIDTHS = [(1440, "desktop"), (1100, "laptop"), (1024, "small"),
          (901, "just-wide"), (390, "phone")]

GEOMETRY = """() => {
  const nav = document.querySelector('.sitenav');
  if (!nav) return {err: 'no .sitenav on the page'};
  const nb = nav.getBoundingClientRect();
  const links = nav.querySelector('.sitenav-links');
  const cta = nav.querySelector('.sitenav-cta');
  const cb = cta ? cta.getBoundingClientRect() : null;
  const wrap = document.querySelector('.wrap, main, .hero');
  let first = null;
  if (wrap) for (const c of wrap.children) {
    const r = c.getBoundingClientRect();
    if (r.height > 0) { first = r; break; }
  }
  const cs = cta ? getComputedStyle(cta) : null;
  return {
    navBottom: Math.round(nb.bottom),
    ctaRight: cb ? Math.round(cb.right) : null,
    ctaLeft: cb ? Math.round(cb.left) : null,
    ctaColor: cs ? cs.color : null,
    ctaBg: cs ? cs.backgroundColor : null,
    linkCount: links ? links.querySelectorAll('a').length : 0,
    docOverflow: document.documentElement.scrollWidth
                 - document.documentElement.clientWidth,
    firstTop: first ? Math.round(first.top) : null,
  };
}"""


def srgb(c):
    """'rgb(1, 2, 3)' -> relative luminance, for a contrast ratio."""
    n = [int(x) / 255 for x in c[c.index("(") + 1:c.index(")")].split(",")[:3]]
    f = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in n]
    return 0.2126 * f[0] + 0.7152 * f[1] + 0.0722 * f[2]


def contrast(a, b):
    la, lb = srgb(a), srgb(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


browser = None
try:
    with sync_playwright() as pw:
        try:
            browser = H.launch_chromium(pw)
        except H.SkipModule as e:
            print(f"  SKIP  {e}")
            sys.exit(77)

        base = f"http://127.0.0.1:{PORT}"

        def offline(ctx):
            """Render with the fallback font stacks, always.

            The pages ask Google Fonts for three faces. Waiting on that is
            most of this module's runtime, and on a machine that cannot reach
            it the wait is a connect timeout per page. Cutting it also makes
            the geometry deterministic — and it errs the safe way, because the
            generic monospace fallback is wider than JetBrains Mono, so the
            bar is measured with more text in it than it will really carry.
            """
            ctx.route("**://fonts.googleapis.com/**", lambda r: r.abort())
            ctx.route("**://fonts.gstatic.com/**", lambda r: r.abort())

        for width, tag in WIDTHS:
            print(f"\n[{tag}] {width}px")
            ctx = browser.new_context(viewport={"width": width, "height": 900})
            offline(ctx)
            page = ctx.new_page()
            sideways, buried, offscreen, thin, counts = [], [], [], [], set()
            for route in PAGES:
                page.goto(base + route, wait_until="load", timeout=30000)
                page.wait_for_timeout(120)
                g = page.evaluate(GEOMETRY)
                if g.get("err"):
                    sideways.append(f"{route}: {g['err']}")
                    continue
                counts.add(g["linkCount"])
                if g["docOverflow"] > 1:
                    sideways.append(f"{route} scrolls sideways by {g['docOverflow']}px")
                if g["firstTop"] is not None and g["firstTop"] < g["navBottom"]:
                    buried.append(f"{route}: content starts at {g['firstTop']}px, "
                                  f"under a bar ending at {g['navBottom']}px")
                # The CTA has to be on screen and whole, not merely in the DOM.
                if g["ctaRight"] is None or g["ctaRight"] > width or g["ctaLeft"] < 0:
                    offscreen.append(f"{route}: CTA spans {g['ctaLeft']}..{g['ctaRight']} "
                                     f"in a {width}px viewport")
                ratio = contrast(g["ctaColor"], g["ctaBg"])
                if ratio < 4.5:
                    thin.append(f"{route}: CTA text {g['ctaColor']} on {g['ctaBg']} "
                                f"is {ratio:.1f}:1")
            check(f"{tag}: no page scrolls sideways", not sideways,
                  "\n          ".join(sideways))
            check(f"{tag}: content clears the fixed bar", not buried,
                  "\n          ".join(buried))
            check(f"{tag}: the CTA is fully on screen", not offscreen,
                  "\n          ".join(offscreen))
            check(f"{tag}: the CTA label is legible on its own button", not thin,
                  "\n          ".join(thin))
            check(f"{tag}: every page shows the same number of nav links",
                  len(counts) == 1, counts)
            ctx.close()

        print("\n[keyboard] the bar can be got past and tabbed through")
        ctx = browser.new_context(viewport={"width": 1440, "height": 900})
        offline(ctx)
        page = ctx.new_page()
        page.goto(base + "/download", wait_until="load", timeout=30000)
        page.wait_for_timeout(150)
        page.keyboard.press("Tab")
        page.wait_for_timeout(350)   # the skip link slides in
        skip = page.evaluate("""() => {
          const a = document.activeElement, r = a.getBoundingClientRect();
          return {cls: a.className, top: Math.round(r.top),
                  txt: (a.textContent || '').trim()};
        }""")
        check("the first tab stop is the skip link",
              skip["cls"] == "sitenav-skip", skip)
        check("and it is on screen once focused", skip["top"] >= 0,
              f"focused but positioned at {skip['top']}px — invisible to the "
              "sighted keyboard user it exists for")
        page.keyboard.press("Enter")
        page.wait_for_timeout(300)
        after = page.evaluate("() => document.activeElement.id")
        check("and it moves focus to the content", after == "content", after)

        # A focus ring drawn outside a scroll container's padding box is
        # clipped away. .sitenav-links is a scroll container.
        page.goto(base + "/download", wait_until="load", timeout=30000)
        page.wait_for_timeout(150)
        clipped = []
        for _ in range(12):
            page.keyboard.press("Tab")
            r = page.evaluate("""() => {
              const a = document.activeElement;
              if (!a.closest('.sitenav-links')) return null;
              const el = a.getBoundingClientRect();
              const box = document.querySelector('.sitenav-links').getBoundingClientRect();
              return {txt: a.textContent.trim(),
                      shadow: getComputedStyle(a).boxShadow,
                      room: Math.round(Math.min(el.top - box.top, box.bottom - el.bottom))};
            }""")
            if r is None:
                continue
            if r["shadow"] == "none":
                clipped.append(f"{r['txt']}: no focus ring at all")
            elif r["room"] < 3:
                clipped.append(f"{r['txt']}: only {r['room']}px inside the scroll "
                               "container, so the 3px ring is clipped")
        check("nav links show a focus ring that is not clipped away",
              not clipped, "\n          ".join(clipped))

        print("\n[anchors] the nav's in-page links land clear of the bar")
        under = []
        for frag in ("how", "jurisdictions", "pricing"):
            p2 = ctx.new_page()
            p2.goto(base + "/", wait_until="load", timeout=30000)
            p2.wait_for_timeout(200)
            p2.evaluate("(f) => { location.hash = '#' + f; }", frag)
            p2.wait_for_timeout(600)
            r = p2.evaluate("""(f) => {
              const el = document.getElementById(f);
              if (!el) return null;
              const nav = document.querySelector('.sitenav').getBoundingClientRect();
              return {top: Math.round(el.getBoundingClientRect().top),
                      navB: Math.round(nav.bottom)};
            }""", frag)
            p2.close()
            if r is None:
                under.append(f"#{frag}: the nav links to an id no page has")
            elif r["top"] < r["navB"] - 1:
                under.append(f"#{frag}: lands at {r['top']}px, behind a bar "
                             f"ending at {r['navB']}px")
        check("every in-page nav target is visible after the jump", not under,
              "\n          ".join(under))

        print("\n[legend] the status key actually shows its colours")
        # The three swatches were styled as `.region .small-dot` and the legend
        # is not inside a .region, so they had no width, no height and no
        # background: three state words with nothing beside them. A key that
        # renders nothing is worse than no key — the reader is told one exists.
        p3 = ctx.new_page()
        p3.goto(base + "/status", wait_until="load", timeout=30000)
        p3.wait_for_timeout(600)
        dots = p3.evaluate("""() => [...document.querySelectorAll('.legend .small-dot')]
            .map(e => { const r = e.getBoundingClientRect();
                        const c = getComputedStyle(e);
                        return {w: Math.round(r.width), h: Math.round(r.height),
                                bg: c.backgroundColor}; })""")
        check("the legend has one swatch per state", len(dots) == 3, dots)
        check("each swatch is actually painted",
              all(d["w"] >= 6 and d["h"] >= 6 for d in dots), dots)
        check("and no two states share a colour",
              len({d["bg"] for d in dots}) == 3, dots)
        check("none of them is transparent",
              not any("rgba(0, 0, 0, 0)" in d["bg"] for d in dots), dots)
        p3.close()
        ctx.close()
        browser.close()
        browser = None

finally:
    srv.shutdown()

print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
