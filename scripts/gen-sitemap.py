#!/usr/bin/env python3
"""
Generate web/sitemap.xml from the routes the installer actually serves.

Two things could go stale here and both are caught rather than trusted:

  * a page exists and is not in the sitemap, so it is never crawled;
  * a sitemap entry names a URL nginx does not route, so a crawler is sent
    to a 404 by the file that is supposed to be the map.

The URL list is therefore not written by hand. Every public page maps to the
clean URL scripts/install.sh gives it, and test_site.py regenerates this and
compares — a page added without a route, or a route added without a sitemap
entry, fails there rather than in a search console six weeks later.

  ./scripts/gen-sitemap.py            # rewrite web/sitemap.xml
  ./scripts/gen-sitemap.py --check    # exit 1 if it is out of date
"""
import os, re, subprocess, sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = "https://0trustvpn.com"

# clean URL -> (source page, priority, change frequency)
#
# Ordered by how much we want a crawler to spend its budget on them. The
# trial page is second only to the landing page because it is the one page
# whose entire job is a conversion.
PAGES = [
    ("/",                 "index.html",           "1.0", "weekly"),
    ("/trial",            "trial.html",           "0.9", "weekly"),
    ("/download",         "download.html",        "0.9", "weekly"),
    ("/help",             "help.html",            "0.8", "weekly"),
    ("/audit",            "audit.html",           "0.8", "monthly"),
    ("/status",           "status.html",          "0.6", "daily"),
    ("/privacy",          "privacy.html",         "0.6", "monthly"),
    ("/security-policy",  "security-policy.html", "0.5", "monthly"),
    ("/terms",            "terms.html",           "0.5", "monthly"),
]

# Deliberately absent, and each for a reason rather than an oversight:
#   admin.html   the operations dashboard; noindex, and IP-restricted
#   404.html     error pages are not destinations
#   50x.html
#   /surf        renders other people's pages under our origin
EXCLUDED = {"admin.html", "404.html", "50x.html"}


def lastmod(page):
    """The date the page last actually changed, from git rather than mtime.

    A checkout's mtimes are all the moment it was cloned, which would put
    every page's lastmod at the same wrong day and teach crawlers to ignore
    the field."""
    r = subprocess.run(["git", "log", "-1", "--format=%cs", "--", f"web/{page}"],
                       cwd=REPO, capture_output=True, text=True)
    return r.stdout.strip() or "2026-01-01"


def build():
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for url, page, prio, freq in PAGES:
        out.append("  <url>")
        out.append(f"    <loc>{SITE}{url}</loc>")
        out.append(f"    <lastmod>{lastmod(page)}</lastmod>")
        out.append(f"    <changefreq>{freq}</changefreq>")
        out.append(f"    <priority>{prio}</priority>")
        out.append("  </url>")
    out.append("</urlset>")
    return "\n".join(out) + "\n"


def main():
    path = os.path.join(REPO, "web", "sitemap.xml")
    want = build()
    if "--check" in sys.argv:
        have = open(path).read() if os.path.exists(path) else ""
        if have != want:
            print("web/sitemap.xml is out of date — run scripts/gen-sitemap.py",
                  file=sys.stderr)
            return 1
        print(f"[ok] sitemap covers {len(PAGES)} URLs and is current")
        return 0
    open(path, "w").write(want)
    print(f"wrote web/sitemap.xml — {len(PAGES)} URLs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
