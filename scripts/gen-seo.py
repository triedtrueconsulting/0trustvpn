#!/usr/bin/env python3
"""
Generate the JSON-LD structured data blocks in web/*.html.

Written rather than hand-maintained for two reasons, both of which are drift
this repository has been bitten by before.

The first is prices. A Product offer carries $5/$13/$48, and those numbers
live in api/main.py's PRICING. A price written into a page by hand is bug
class #12 with a rich-result attached: Google would show a figure the
checkout does not charge, which is worse than showing none.

The second is the FAQ. help.html answers twenty-one real questions, and a
FAQPage block is how an answer engine gets them — but a hand-copied one
answers whatever the page said on the day it was pasted. The questions and
answers here are extracted from the page itself, so editing the page edits
the schema.

    ./scripts/gen-seo.py            # rewrite the blocks
    ./scripts/gen-seo.py --check    # exit 1 if any is out of date
"""
import html, json, os, re, sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(REPO, "web")
SITE = "https://0trustvpn.com"
EMAIL = "0trustvpn@proton.me"
BEGIN, END = "<!-- SEO:JSONLD -->", "<!-- /SEO:JSONLD -->"


def api_constants():
    """PRICING and TRIAL_DAYS, read from the API rather than restated.

    Parsed rather than imported: this script runs on an operator's machine
    and in the site checks, neither of which should need FastAPI installed
    to find out what a month costs."""
    src = open(os.path.join(REPO, "api", "main.py")).read()
    block = re.search(r"^PRICING\s*=\s*\{(.*?)\}", src, re.S | re.M).group(1)
    pricing = {int(m): float(p) for m, p in
               re.findall(r"(\d+)\s*:\s*([\d.]+)", block)}
    days = int(re.search(r'TRIAL_DAYS\s*=\s*int\(os\.environ\.get\(\s*"[^"]+"\s*,\s*"(\d+)"',
                         src).group(1))
    return pricing, days


def strip_tags(s):
    s = re.sub(r"(?s)<(script|style).*?</\1>", " ", s)
    s = re.sub(r"<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", html.unescape(s)).strip()


def faq_entries():
    """Every .q block in help.html, as question and answer text."""
    src = open(os.path.join(WEB, "help.html"), encoding="utf-8").read()
    out = []
    for block in re.findall(r'(?s)<div class="q">(.*?)</div>', src):
        q = re.search(r"(?s)<h3[^>]*>(.*?)</h3>", block)
        if not q:
            continue
        answer = strip_tags(re.sub(r"(?s)<h3[^>]*>.*?</h3>", "", block))
        if not answer:
            continue
        out.append({
            "@type": "Question",
            "name": strip_tags(q.group(1)),
            "acceptedAnswer": {"@type": "Answer", "text": answer},
        })
    return out


def organization():
    return {
        "@type": "Organization",
        "@id": f"{SITE}/#organization",
        "name": "0trustvpn",
        "legalName": "0trust GmbH",
        "url": SITE + "/",
        "logo": {"@type": "ImageObject", "url": f"{SITE}/favicon.svg"},
        "image": f"{SITE}/og.png",
        "email": EMAIL,
        "description":
            "0trustvpn operates a no-logs WireGuard mesh VPN with multi-hop "
            "routing through Switzerland, Iceland and Romania. Accounts are "
            "anonymous 16-character tokens; there is no email address, "
            "password or identity attached to one, and payment is in "
            "cryptocurrency.",
        "address": {"@type": "PostalAddress", "addressCountry": "CH"},
        "contactPoint": [{
            "@type": "ContactPoint",
            "contactType": "customer support",
            "email": EMAIL,
            "availableLanguage": ["en"],
        }, {
            "@type": "ContactPoint",
            "contactType": "security",
            "email": EMAIL,
            "url": f"{SITE}/security-policy",
        }],
    }


def product(pricing, trial_days):
    """The Product node.

    Note what the copy here does NOT say: which coins beyond Bitcoin. A
    deployment can take BTC, XMR, ZEC and ETH depending on its provider, but
    the installer default derives addresses from an xpub and only Bitcoin's
    are derivable that way. Static copy is written for that floor, because it
    is the state a fresh install launches in — and structured data is the
    worst possible place to overstate it, since an answer engine will quote
    it back as a fact about the product. test_site.py's [pay] section fails
    on any other coin appearing here."""
    offers = [{
        "@type": "Offer",
        "name": f"{m} month" + ("s" if m != 1 else ""),
        "price": f"{usd:.2f}",
        "priceCurrency": "USD",
        "availability": "https://schema.org/InStock",
        "url": f"{SITE}/#pricing",
    } for m, usd in sorted(pricing.items())]
    return {
        "@type": ["SoftwareApplication", "Product"],
        "@id": f"{SITE}/#product",
        "name": "0trustvpn",
        "applicationCategory": "SecurityApplication",
        "applicationSubCategory": "VPN",
        "operatingSystem": "Linux, Windows, macOS, Android",
        "url": SITE + "/",
        "downloadUrl": f"{SITE}/download",
        "publisher": {"@id": f"{SITE}/#organization"},
        "description":
            "A WireGuard mesh VPN that keeps no connection logs. Single-hop "
            "or multi-hop routing between three servers outside the Five, "
            "Nine and Fourteen Eyes alliances — Zurich, Reykjavik and "
            "Bucharest. Sign-up takes no email address, no password and no "
            "personal details: an account is a 16-character token, paid for "
            "in cryptocurrency.",
        "featureList": [
            "No connection, traffic or DNS logs",
            "Anonymous accounts — no email, password or identity",
            "Multi-hop routing: enter one country, exit another",
            "Servers outside the Five, Nine and Fourteen Eyes alliances",
            "RAM-only servers that keep nothing across a reboot",
            "Payment in Bitcoin — no name, address or card",
            "Optional obfuscation against deep packet inspection",
            "Encrypted DNS over TLS with query logging off",
            "Up to 8 devices per account",
            "Published audit pack with a verifier you can run yourself",
        ],
        "offers": {
            "@type": "AggregateOffer",
            "priceCurrency": "USD",
            "lowPrice": f"{min(pricing.values()):.2f}",
            "highPrice": f"{max(pricing.values()):.2f}",
            "offerCount": len(offers),
            "offers": offers,
        },
        "isAccessibleForFree": False,
        "termsOfService": f"{SITE}/terms",
        "privacyPolicy": f"{SITE}/privacy",
        "softwareHelp": f"{SITE}/help",
    }


def webpage(path, name, description, breadcrumb=True):
    node = {
        "@type": "WebPage",
        "@id": f"{SITE}{path}#webpage",
        "url": f"{SITE}{path}",
        "name": name,
        "description": description,
        "isPartOf": {"@id": f"{SITE}/#website"},
        "publisher": {"@id": f"{SITE}/#organization"},
        "inLanguage": "en",
    }
    if breadcrumb:
        node["breadcrumb"] = {
            "@type": "BreadcrumbList",
            "itemListElement": [
                {"@type": "ListItem", "position": 1, "name": "Home",
                 "item": SITE + "/"},
                {"@type": "ListItem", "position": 2, "name": name},
            ],
        }
    return node


def website():
    return {
        "@type": "WebSite",
        "@id": f"{SITE}/#website",
        "url": SITE + "/",
        "name": "0trustvpn",
        "publisher": {"@id": f"{SITE}/#organization"},
        "inLanguage": "en",
    }


def page_meta(fn):
    """Title and description straight out of the page's own head, so the
    schema cannot say something the meta tags do not."""
    s = open(os.path.join(WEB, fn), encoding="utf-8").read()
    title = html.unescape(re.search(r"(?s)<title>(.*?)</title>", s).group(1))
    desc = re.search(r'<meta name="description" content="([^"]*)"', s)
    return title, html.unescape(desc.group(1)) if desc else ""


def graphs():
    pricing, trial_days = api_constants()
    out = {}

    t, d = page_meta("index.html")
    out["index.html"] = [organization(), website(), product(pricing, trial_days),
                         webpage("/", t, d, breadcrumb=False)]

    t, d = page_meta("help.html")
    out["help.html"] = [
        webpage("/help", t, d),
        {"@type": "FAQPage", "@id": f"{SITE}/help#faq",
         "mainEntity": faq_entries()},
    ]

    for fn, path in (("download.html", "/download"),
                     ("audit.html", "/audit"),
                     ("privacy.html", "/privacy"),
                     ("terms.html", "/terms"),
                     ("security-policy.html", "/security-policy"),
                     ("status.html", "/status"),
                     ("trial.html", "/trial")):
        t, d = page_meta(fn)
        out[fn] = [webpage(path, t, d)]

    # The trial is an offer in its own right, and it is the one an answer
    # engine is most likely to be asked about ("is there a free VPN trial
    # without a card"). Its length is TRIAL_DAYS, not a literal.
    out["trial.html"].append({
        "@type": "Offer",
        "@id": f"{SITE}/trial#offer",
        "name": f"{trial_days}-day free trial",
        "price": "0",
        "priceCurrency": "USD",
        "availability": "https://schema.org/InStock",
        "url": f"{SITE}/trial",
        "itemOffered": {"@id": f"{SITE}/#product"},
        "description":
            f"A {trial_days}-day trial of 0trustvpn that takes no email "
            "address, no payment card and no personal details. The browser "
            "solves a proof-of-work and receives an anonymous account token.",
        "eligibleCustomerType": "https://schema.org/Enthusiast",
    })
    return out


def render(nodes):
    doc = {"@context": "https://schema.org", "@graph": nodes}
    body = json.dumps(doc, indent=2, ensure_ascii=False)
    return (BEGIN + '\n<script type="application/ld+json">\n'
            + body + "\n</script>\n" + END)


def apply(check_only):
    stale = []
    for fn, nodes in graphs().items():
        p = os.path.join(WEB, fn)
        s = open(p, encoding="utf-8").read()
        block = render(nodes)
        if BEGIN in s:
            i, j = s.index(BEGIN), s.index(END) + len(END)
            new = s[:i] + block + s[j:]
        else:
            anchor = '<link rel="icon" href="/favicon.svg" type="image/svg+xml">'
            if anchor not in s:
                print(f"{fn}: no anchor to insert at", file=sys.stderr)
                return 1
            new = s.replace(anchor, block + "\n" + anchor, 1)
        if new == s:
            continue
        if check_only:
            stale.append(fn)
        else:
            open(p, "w", encoding="utf-8").write(new)
            print(f"  wrote {len(nodes)} node(s) into {fn}")
    if check_only:
        if stale:
            print("structured data is out of date in: " + ", ".join(stale)
                  + "\nrun scripts/gen-seo.py", file=sys.stderr)
            return 1
        n = sum(len(v) for v in graphs().values())
        print(f"[ok] {n} schema.org nodes across {len(graphs())} pages, current")
    return 0


if __name__ == "__main__":
    sys.exit(apply("--check" in sys.argv))
