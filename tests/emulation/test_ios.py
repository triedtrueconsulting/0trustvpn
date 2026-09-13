#!/usr/bin/env python3
"""
The iOS app, against a live control plane.

There is no Swift compiler in this environment and SwiftUI / NetworkExtension
have no Linux SDK, so nothing here type-checks the app — mobile/ios/syntax-check.sh
says as much about itself. What this module CAN do is the part a compiler
would not do anyway, and it is the part that has actually broken a client of
this API before: compare the wire contract the Swift declares against real
JSON from a running control plane, field by field.

The Android client was once entirely broken by a camelCase/snake_case
mismatch that compiled perfectly.
"""
import glob, json, os, plistlib, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

IOS = os.path.join(H.REPO, "mobile", "ios")
SRCDIR = os.path.join(IOS, "0trust")
SRC = {os.path.relpath(p, SRCDIR): open(p).read()
       for p in glob.glob(os.path.join(SRCDIR, "**", "*.swift"), recursive=True)}
ALL_SWIFT = "\n".join(SRC.values())


def code_only(text: str) -> str:
    """Source with // comments removed — the files explain the rules they
    follow, so a naive grep matches the explanation as well as a violation."""
    return "\n".join(l.split("//")[0] for l in text.splitlines())


CODE = code_only(ALL_SWIFT)


def coding_keys(struct: str) -> dict:
    """
    {swiftProperty: wireName} from a struct's CodingKeys enum.

    Both forms count: `case expiresAt = "expires_at"` renames, and a bare
    `case status` means the property and the wire field share a name.
    """
    i = ALL_SWIFT.find(f"struct {struct}")
    if i < 0:
        return {}

    def block(text: str, start: int) -> tuple:
        """(body, end) of the brace block opening at or after `start`."""
        open_at = text.index("{", start)
        depth, k = 0, open_at
        while k < len(text):
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
                if depth == 0:
                    return text[open_at + 1:k], k
            k += 1
        return text[open_at + 1:], len(text)

    outer, _ = block(ALL_SWIFT, i)
    # PublicConfig nests a Trial struct that has CodingKeys of its own, and a
    # naive search finds the inner one first. Strip nested types so the enum
    # we pick belongs to the struct we were asked about.
    while True:
        m = re.search(r"\bstruct\s+\w+", outer)
        if not m:
            break
        _, end = block(outer, m.start())
        outer = outer[:m.start()] + outer[end + 1:]

    j = outer.find("enum CodingKeys")
    if j < 0:
        return {}
    body, _ = block(outer, j)
    out = {}
    for line in body.splitlines():
        line = line.split("//")[0].strip()
        if not line.startswith("case "):
            continue
        for part in line[len("case "):].split(","):
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                prop, wire = part.split("=", 1)
                out[prop.strip()] = wire.strip().strip('"')
            else:
                out[part] = part
    return out


TMP = H.tempdir("0trust-ios-")
DB = os.path.join(TMP, "0trust.db")
os.environ["ZTV_DB_PATH"] = DB
os.environ["ZTV_TRIAL_SECRET"] = "ios-secret"
os.environ["ZTV_TRIAL_POW_BITS"] = "10"
sys.path.insert(0, os.path.join(H.REPO, "api"))
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=2)

try:
    print("[1] the Swift wire contract, against live API responses")
    check("Swift sources found", len(SRC) >= 5, sorted(SRC))

    token, _ = H.paid_account()
    st, status_json = H.call("GET", "/api/v1/account/status",
                             headers={"X-Account-Token": token})
    check("status 200", st == 200, status_json)

    # Every key the Swift expects must exist in the real payload. The reverse
    # is not required — a client may ignore fields — but a key the app decodes
    # and the server never sends is a silently-nil property.
    for struct, payload, required in (
        ("AccountStatus", status_json,
         {"status", "expires_at", "days_remaining", "plan",
          "max_devices", "device_count"}),
    ):
        keys = coding_keys(struct)
        check(f"{struct} declares CodingKeys", bool(keys), keys)
        wire = set(keys.values())
        check(f"{struct} covers every field the app needs",
              required <= wire, sorted(required - wire))
        missing = [w for w in wire if w not in payload]
        check(f"every {struct} key exists in the live payload",
              not missing, f"absent from server JSON: {missing}")

    # Register a device and check the register/peer shapes the same way.
    pk = H.genkey()
    st, reg = H.call("POST", "/api/v1/wg/register",
                     {"pubkey": pk, "device_name": "iPhone", "region": "zur"},
                     headers={"X-Account-Token": token})
    check("register 200", st == 200, f"{st} {reg}")

    keys = coding_keys("RegisterResponse")
    wire = set(keys.values())
    missing = [w for w in wire if w not in reg]
    check("every RegisterResponse key exists in the live payload",
          not missing, f"absent from server JSON: {missing}")
    for need in ("interface_ip", "interface_ip6", "dns", "peers", "same_host"):
        check(f"RegisterResponse decodes {need}", need in wire, sorted(wire))

    peer_keys = set(coding_keys("WgPeer").values())
    live_peer = (reg.get("peers") or [{}])[0]
    missing = [w for w in peer_keys if w not in live_peer]
    check("every WgPeer key exists in the live peer object",
          not missing, f"absent: {missing}; live keys: {sorted(live_peer)}")

    st, devs = H.call("GET", "/api/v1/devices", headers={"X-Account-Token": token})
    dev_keys = set(coding_keys("DeviceInfo").values())
    live_dev = (devs or [{}])[0]
    missing = [w for w in dev_keys if w not in live_dev]
    check("every DeviceInfo key exists in the live device object",
          not missing, f"absent: {missing}; live keys: {sorted(live_dev)}")

    st, cfg = H.call("GET", "/api/v1/config")
    cfg_keys = set(coding_keys("PublicConfig").values())
    missing = [w for w in cfg_keys if w not in cfg]
    check("every PublicConfig key exists in /config", not missing, missing)
    trial_keys = set(coding_keys("Trial").values())
    missing = [w for w in trial_keys if w not in (cfg.get("trial") or {})]
    check("every Trial key exists in /config.trial", not missing, missing)

    print("\n[2] auth is the token header, never Bearer")
    check("the app sends X-Account-Token", "X-Account-Token" in ALL_SWIFT)
    check("and never an Authorization header",
          "Authorization" not in CODE and "Bearer" not in CODE,
          [l.strip() for l in CODE.splitlines()
           if "Authorization" in l or "Bearer" in l][:3])

    print("\n[3] regions come from the mesh, not from a literal")
    st, live_regions = H.call("GET", "/api/v1/regions")
    check("the app decodes the {\"regions\": [...]} envelope, not a bare array",
          "RegionsResponse" in ALL_SWIFT and "envelope.regions" in ALL_SWIFT,
          "decoding [RegionInfo] directly fails and empties the picker")
    live_codes = {r["code"] for r in live_regions["regions"]}
    check("the live mesh reports zur/rey/buc", live_codes == {"zur", "rey", "buc"},
          sorted(live_codes))
    # Recurring bug class: codes from an earlier design leaking into defaults.
    stale = re.findall(r'"(ams|fra|lon|sto|nyc|sjc|sgp|tyo)"', ALL_SWIFT)
    check("no stale region codes in the app", not stale, sorted(set(stale)))
    # The picker must be populated from /regions, not a hardcoded array.
    check("the region pickers read the fetched list",
          "ForEach(state.regions)" in ALL_SWIFT,
          "region pickers should iterate state.regions")
    hardcoded = re.search(r'ForEach\(\s*\[\s*"(zur|rey|buc)"', ALL_SWIFT)
    check("no hardcoded region array drives a picker",
          hardcoded is None, hardcoded.group(0) if hardcoded else "")

    print("\n[4] the device identity is generated once and kept")
    # Registration is idempotent on the pubkey. A keypair generated per
    # connect registers a new device each time and burns the account's cap —
    # the exact bug the Android app shipped and had to be fixed for.
    st, again = H.call("POST", "/api/v1/wg/register",
                       {"pubkey": pk, "device_name": "iPhone", "region": "zur"},
                       headers={"X-Account-Token": token})
    check("re-registering the same key is not a new device", st == 200, f"{st} {again}")
    st, devs2 = H.call("GET", "/api/v1/devices", headers={"X-Account-Token": token})
    check("and does not consume a second slot", len(devs2) == len(devs),
          f"{len(devs)} -> {len(devs2)}")
    check("the app persists its keypair rather than making one per connect",
          "loadOrCreate" in ALL_SWIFT and "Keychain.privateKeyKey" in ALL_SWIFT)
    check("connect() uses the persisted identity",
          re.search(r"DeviceIdentity\.loadOrCreate\(\)", ALL_SWIFT) is not None)

    print("\n[5] per-plan values are read, never hardcoded")
    # 2 on a trial, 8 paid. Printing a constant told trial customers they had
    # slots they did not have — three surfaces shipped that bug.
    check("the device cap comes from the server",
          "maxDevices" in ALL_SWIFT and "deviceCap" in ALL_SWIFT)
    bad_cap = re.findall(r'"\s*/\s*8\s*"|of\s+8\s+(?:device|slot)', ALL_SWIFT)
    check("no literal device cap in the UI", not bad_cap, bad_cap)
    # The trial length is an operator setting; a number in an App Store build
    # cannot be corrected without another review cycle.
    stale_days = re.findall(
        r'"[^"]*\b(?:\d+[- ]day|one week|a week|7[- ]day|week free)[^"]*"',
        ALL_SWIFT, re.I)
    check("no trial duration is hardcoded in the iOS copy", not stale_days, stale_days)
    check("the trial pitch renders the published label",
          "config?.trial" in ALL_SWIFT and "label" in ALL_SWIFT)

    print("\n[6] the tunnel never claims more than it has")
    ptp = SRC.get("Tunnel/PacketTunnelProvider.swift", "")
    check("the tunnel provider exists", bool(ptp))
    # The skeleton called completionHandler(nil) without starting anything:
    # iOS would show "Connected" while no packet was ever encrypted.
    check("startTunnel actually starts the adapter",
          "adapter.start(tunnelConfiguration:" in ptp)
    check("and reports failure instead of a silent success",
          "TunnelError.adapter" in ptp and "completionHandler(TunnelError" in ptp)
    check("no placeholder left in the tunnel path",
          "fatalError" not in ALL_SWIFT and "TODO" not in ALL_SWIFT,
          [l.strip() for l in ALL_SWIFT.splitlines()
           if "fatalError" in l or "TODO" in l][:3])
    # NEVPNStatus.connected only means the extension started.
    check("the app distinguishes 'up' from 'carrying traffic'",
          "carryingTraffic" in ALL_SWIFT and "last_handshake_time_sec" in ALL_SWIFT)

    print("\n[7] ::/0 is always claimed")
    # Dropping ::/0 to "fix" v6 is how v6 leaks around the tunnel. Without an
    # address it is blackholed, which is the safe failure.
    wgc = SRC.get("Shared/WgConfig.swift", "")
    check("the config builder defaults to both families",
          '"::/0"' in wgc and '"0.0.0.0/0"' in wgc, wgc[:200])
    check("a v6 address is only added when the exit provides one",
          "interfaceIP6" in wgc and "compactMap" in wgc)
    check("exactly one peer per config",
          "primaryPeer" in wgc and "peers.first" in wgc)

    print("\n[8] the project can be generated and signed")
    spec = os.path.join(IOS, "project.yml")
    check("an XcodeGen spec exists", os.path.exists(spec))
    spec_text = open(spec).read()
    for want, why in (
        ("packet-tunnel-provider", "the NE entitlement is declared"),
        ("group.vpn.zerotrust.app", "the App Group is declared"),
        ("wireguard-apple", "WireGuardKit is a real dependency"),
        ("vpn.zerotrust.app.tunnel", "the extension bundle id matches the app"),
    ):
        check(why, want in spec_text, f"{want} missing from project.yml")

    # The provider bundle id the app asks NetworkExtension to load has to be
    # the id the extension is actually built with, or startTunnel finds
    # nothing to start.
    ext_plist = plistlib.load(open(os.path.join(SRCDIR, "Tunnel", "Info.plist"), "rb"))
    ext_id = ext_plist.get("CFBundleIdentifier", "")
    referenced = re.search(r'providerBundleIdentifier\s*=\s*"([^"]+)"', ALL_SWIFT)
    check("the app loads the extension's real bundle id",
          referenced is not None and referenced.group(1) == ext_id,
          f"plist={ext_id} app={referenced.group(1) if referenced else None}")
    check("the extension declares the packet-tunnel point",
          ext_plist.get("NSExtension", {}).get("NSExtensionPointIdentifier")
          == "com.apple.networkextension.packet-tunnel", ext_plist.get("NSExtension"))

    # App Group and keychain group must agree across both targets and the code.
    for name, path in (("app", "App/0trust.entitlements"),
                       ("tunnel", "Tunnel/Tunnel.entitlements")):
        ent = plistlib.load(open(os.path.join(SRCDIR, path), "rb"))
        check(f"the {name} target joins the App Group",
              "group.vpn.zerotrust.app"
              in ent.get("com.apple.security.application-groups", []), ent)
        check(f"the {name} target carries the NE entitlement",
              "packet-tunnel-provider"
              in ent.get("com.apple.developer.networking.networkextension", []), ent)
        check(f"the {name} target shares the keychain group",
              any("group.vpn.zerotrust.app" in g
                  for g in ent.get("keychain-access-groups", [])), ent)

    print("\n[9] the app is branded the way every other surface is")
    app_plist = plistlib.load(open(os.path.join(SRCDIR, "App", "Info.plist"), "rb"))
    check("the launcher name is the brand mark",
          app_plist.get("CFBundleDisplayName") == "0trustvpn",
          app_plist.get("CFBundleDisplayName"))
    check("dark only, like the rest of the product",
          app_plist.get("UIUserInterfaceStyle") == "Dark")
    theme = SRC.get("App/Theme.swift", "")
    for hexv, name in (("0.831", "amber"), ("0.769", "terra"), ("0.490", "moss")):
        check(f"the {name} accent matches the design system", hexv in theme)

    print("\n[9b] messages from the service actually reach the phone")
    # The feature was write-only across the whole product: the operator
    # dashboard could broadcast, and no client anywhere rendered one.
    notice_keys = set(coding_keys("NoticeInfo").values())
    check("NoticeInfo declares CodingKeys", bool(notice_keys), notice_keys)
    st, live_notices = H.call("GET", "/api/v1/notices",
                              headers={"X-Account-Token": token})
    check("notices 200", st == 200, live_notices)
    # Post one through the DB so there is a real payload to compare against.
    import sqlite3 as _sq
    nc = _sq.connect(DB)
    acct = nc.execute("SELECT account_id FROM devices LIMIT 1").fetchone()[0]
    nc.execute("""INSERT INTO notices
                  (account_id, severity, subject, body, created_at,
                   expires_at, created_by)
                  VALUES (?, 'warning', 'subj', 'body', ?, 0, 'test')""",
               (acct, 1))
    nc.commit(); nc.close()
    st, live_notices = H.call("GET", "/api/v1/notices",
                              headers={"X-Account-Token": token})
    live = (live_notices or [{}])[0]
    missing = [w for w in notice_keys if w not in live]
    check("every NoticeInfo key exists in the live payload",
          not missing, f"absent: {missing}; live: {sorted(live)}")
    check("the app fetches them, not just the unread count",
          "func notices(" in ALL_SWIFT and "/api/v1/notices" in ALL_SWIFT)
    check("and renders them", "NoticeBanner" in ALL_SWIFT)
    check("with a way to dismiss", "markNoticeRead" in ALL_SWIFT
          and "dismissNotice" in ALL_SWIFT)

    print("\n[10] the site does not promise an app nobody can install yet")
    # The source is complete, but shipping needs Apple's packet-tunnel
    # entitlement and App Review. Until an artifact exists, the download page
    # offers the QR-export path and does not advertise an App Store listing.
    dl = open(os.path.join(H.REPO, "web", "download.html")).read()
    visible = "\n".join(l for l in dl.splitlines() if not l.strip().startswith("<!--"))
    for claim in ("App Store listing", "Download for iOS",
                  "TestFlight", "apps.apple.com"):
        check(f"no unbacked iOS claim: {claim!r}",
              claim.lower() not in visible.lower(),
              [l.strip() for l in visible.splitlines()
               if claim.lower() in l.lower()][:2])
    check("the QR-export path is still offered for iOS",
          "WireGuard" in visible and "QR" in visible.upper())

    # And the same rule across every public page, not just this one. The
    # drift arrives as an aside rather than a heading — both of these were
    # live, and neither reads as a claim until you look for one:
    #
    #   "Available for Linux, macOS, Windows, iOS and Android."
    #   "The Android app has the same switch. The iPhone app does not ..."
    #
    # The first lists iOS as a platform the client runs on. The second tells
    # the reader there is an iPhone app by describing what it lacks. So the
    # rule is not "iOS is mentioned near WireGuard" — the first sentence
    # mentions WireGuard immediately afterwards and would sail past that.
    # It is: iOS never appears in a list of platforms we ship a client for,
    # and every sentence naming it also names the route that does work.
    OTHERS = ("Linux", "macOS", "Windows", "Android")
    WORKS = ("WireGuard", "0trust export", "QR", "no 0trustvpn app for iOS",
             "config")
    BLOCK = r"</?(?:p|div|li|ul|ol|section|h[1-6]|td|tr|th|br|blockquote)\b[^>]*>"

    def claims(html):
        """Each text unit, one per block element, split into sentences.

        Blocks are separated first and inline tags (code, strong, em, a) are
        not, because both directions matter: collapsing the whole document
        into one string runs the mockup chrome together with the prose and
        invents platform lists that nobody wrote, while splitting at every
        tag chops `<strong>iOS:</strong> use <code>0trust export</code>` into
        a fragment that names iOS and nothing else. Headings are dropped —
        a two-word label is not where a claim lives, and the outright bans
        above already cover the ones that would be.
        """
        # Script and style contents are not copy. The JSON-LD block is one
        # long line naming every platform the client builds for, so scanning
        # it as prose invented a platform list nobody wrote — and its own
        # sentence structure is JSON, which no sentence splitter can read.
        html = re.sub(r"(?is)<(script|style)\b[^>]*>.*?</\1>", " ", html)
        html = re.sub(r"(?is)<h[1-6]\b[^>]*>.*?</h[1-6]>", " ", html)
        for unit in re.split(BLOCK, html):
            unit = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", unit)).strip()
            for sent in re.split(r"(?<=[.!?]) ", unit):
                if sent.strip():
                    yield sent.strip()

    for page in sorted(glob.glob(os.path.join(H.REPO, "web", "*.html"))):
        listed, unexplained = [], []
        for sent in claims(open(page, encoding="utf-8").read()):
            if not re.search(r"(?<![A-Za-z])(iOS|iPhone|iPad)(?![A-Za-z])", sent):
                continue
            if sum(o in sent for o in OTHERS) >= 2:
                listed.append(sent[:200])
            elif not any(k in sent for k in WORKS):
                unexplained.append(sent[:200])
        name = os.path.basename(page)
        check(f"{name} does not list iOS as a platform we ship a client for",
              not listed, listed[:1])
        check(f"{name} names iOS only beside the route that works",
              not unexplained, unexplained[:1])

    print("\n[11] there is a build, not a set of instructions to click through")
    # The Windows MSI has build.ps1 and Android has Gradle. iOS had "open
    # Xcode", which is not a release process — it drifts, and nothing notices.
    build = os.path.join(IOS, "build.sh")
    check("a command-line build exists", os.path.exists(build))
    bt = open(build).read()
    check("and it refuses to pretend it can run off a Mac",
          'uname -s' in bt and "Darwin" in bt,
          "xcodebuild, the iOS SDK and codesign exist nowhere else")
    check("it is honest that nobody has run it",
          "NOTHING HAS EVER RUN THIS" in bt,
          "same standard the app sources and the README hold themselves to: "
          "this is written from documentation, not from a green run")
    # App Store Connect refuses a repeated build number and tells you by
    # email after the upload, so the script has to demand one up front.
    check("it requires an explicit build number", "--build is required" in bt)
    check("and a version that looks like one",
          r"^[0-9]+\.[0-9]+\.[0-9]+$" in bt)

    # The sharp difference from Windows, and the one most likely to be
    # misremembered later: shipping unsigned is a CHOICE there and does not
    # exist here at any price.
    # Flowed prose in a comment block wraps mid-sentence and every
    # continuation line starts with "# ", so match against the text with the
    # comment markers and line breaks taken out — otherwise this passes or
    # fails on where the paragraph happened to wrap.
    prose = re.sub(r"\s+", " ", re.sub(r"(?m)^\s*#\s?", "", bt))
    check("it says why iOS gets no unsigned path",
          "will not install an unsigned application" in prose,
          prose[:600])

    # An .ipa must never join releases/: Apple re-signs what it distributes,
    # so a published hash of these bytes matches nothing a customer can get,
    # and verify-release.sh would be telling people to check the uncheckable.
    check("the .ipa is kept out of the signed release",
          "does NOT go into releases/" in bt)
    rel = open(os.path.join(H.REPO, "scripts", "release.sh")).read()
    check("and release.sh does not collect one", ".ipa" not in rel)

    # Version: four literals in three files had to move together. They resolve
    # from build settings now, which is what makes --version reach the bundle.
    for name, path in (("app", "App/Info.plist"), ("tunnel", "Tunnel/Info.plist")):
        pl = plistlib.load(open(os.path.join(SRCDIR, path), "rb"))
        check(f"the {name} version comes from the build settings",
              pl.get("CFBundleShortVersionString") == "$(MARKETING_VERSION)"
              and pl.get("CFBundleVersion") == "$(CURRENT_PROJECT_VERSION)",
              f"{pl.get('CFBundleShortVersionString')} / {pl.get('CFBundleVersion')} "
              "— a literal here makes build.sh --version decorative")
    spec_text2 = open(os.path.join(IOS, "project.yml")).read()
    # xcodegen WRITES the file at info.path. Without these properties it would
    # write one with no NSExtension block, and an extension that does not
    # declare the packet-tunnel point is never asked to start one.
    check("project.yml keeps the tunnel's extension point too",
          "com.apple.networkextension.packet-tunnel" in spec_text2,
          "xcodegen generate regenerates Tunnel/Info.plist; if the spec does "
          "not carry NSExtension, generating destroys it")

    print("\n[12] the faces the app asks for are the faces it ships")
    # Font.custom takes a PostScript name and substitutes the system font when
    # it does not resolve — no error, no log line, just an app that looks
    # wrong. Nothing else in the battery would see it.
    res = os.path.join(SRCDIR, "Resources")
    ttfs = sorted(glob.glob(os.path.join(res, "*.ttf")))
    check("the faces are committed, not an operator to-do", len(ttfs) >= 5,
          f"found {len(ttfs)} in {res}")
    asked = set(re.findall(r'custom\(\s*"([^"]+)"', SRC.get("App/Theme.swift", "")))
    check("Theme.swift asks for at least one", bool(asked))

    def ps_name(path):
        import struct
        d = open(path, "rb").read()
        num = struct.unpack(">H", d[4:6])[0]
        tabs = {d[12+16*i:16+16*i].decode("latin1"):
                struct.unpack(">II", d[20+16*i:28+16*i]) for i in range(num)}
        o, _ = tabs["name"]
        _, count, so = struct.unpack(">HHH", d[o:o+6])
        for i in range(count):
            pid, _, _, nid, ln, off = struct.unpack(">HHHHHH", d[o+6+12*i:o+18+12*i])
            if nid == 6:
                raw = d[o+so+off:o+so+off+ln]
                return raw.decode("utf-16-be") if pid == 3 else raw.decode("latin1")
        return ""

    have = {ps_name(f): os.path.basename(f) for f in ttfs}
    check("every face the code asks for is present, by PostScript name",
          asked <= set(have), f"missing {sorted(asked - set(have))}; have {sorted(have)}")
    check("and each file is named the same as its internal name",
          all(have[n] == n + ".ttf" for n in have),
          {n: have[n] for n in have if have[n] != n + ".ttf"})
    registered = set(app_plist.get("UIAppFonts", []))
    check("and iOS is told to register each one",
          {have[n] for n in have} <= registered,
          f"not in UIAppFonts: {sorted({have[n] for n in have} - registered)}")
    check("the licences are recorded with them",
          os.path.exists(os.path.join(res, "FONTS.md")),
          "all three families are OFL 1.1 and redistributing them says so")

    print("\n[13] the Apple lead time is on the launch playbook")
    # Enrolment, the D-U-N-S number and the entitlement request are weeks of
    # waiting on other people, and none of it appeared on the playbook at all
    # — so the earliest anyone would have discovered it is the day they
    # wanted to ship.
    launch = open(os.path.join(H.REPO, "docs", "LAUNCH.md")).read()
    low = launch.lower()
    for want, why in (
        ("developer program", "the $99/yr membership"),
        ("d-u-n-s", "organisation enrolment needs one, and it takes days by itself"),
        ("packet-tunnel-provider", "the entitlement is not self-serve"),
        ("5.4", "Guideline 5.4 requires an organisation, not an individual"),
    ):
        check(f"the playbook names {why}", want in low,
              f"{want!r} absent from LAUNCH.md")
    check("and puts it on Day 1 rather than the day you ship",
          "Start the Apple clock" in launch,
          "it is the longest lead item and it ships last, which is exactly "
          "how it gets started last")

    # ----------------------------------------------------------------------
    # The device-delete URL, on both mobile clients.
    #
    # DELETE /api/v1/devices/{pubkey} carries a base64 key: it routinely holds
    # '/' and '+', and every one of them ends in '='. So the segment is
    # percent-encoded, and whatever joins it to the base must not encode it
    # AGAIN. iOS used base.appendingPathComponent(path), which escapes what it
    # is handed — a '%3D' can come back as '%253D', the server matches no
    # device, and the delete 404s. That is the one call an account at its
    # device cap needs to work, and nothing has ever compiled this app, let
    # alone run it, so it would not have surfaced until a customer was stuck.
    #
    # Android concatenates and says why (ApiClient.kt). Same construction on
    # both, asserted here because neither can be executed from this suite.
    # ----------------------------------------------------------------------
    print("\n[url] the delete path is joined the same way on iOS and Android")
    swift_src = open(os.path.join(H.REPO, "mobile", "ios", "0trust", "Shared",
                                  "APIClient.swift")).read()
    # Comments stripped. Without this the check below read the paragraph
    # EXPLAINING why appendingPathComponent is not used and reported the
    # opposite of the truth — CLAUDE.md's bug class #17, hit twice now while
    # writing checks against it, which is a fair measure of how easy it is.
    swift = "\n".join(ln for ln in swift_src.splitlines()
                      if not ln.lstrip().startswith("//"))
    kotlin = open(os.path.join(
        H.REPO, "mobile", "android", "app", "src", "main", "java", "vpn",
        "zerotrust", "app", "ApiClient.kt")).read()

    check("iOS percent-encodes the pubkey before it goes in the path",
          "addingPercentEncoding" in swift,
          "a raw '/' in a key would split the path segment")
    check("Android does too",
          "URLEncoder.encode" in kotlin)
    check("iOS does not re-join with appendingPathComponent",
          "appendingPathComponent" not in swift,
          "it escapes the component it is given, so the already-encoded "
          "pubkey is encoded a second time and the delete matches nothing")
    check("iOS builds the request URL from the base and the path directly",
          "URL(string: joinBase + path)" in swift,
          "one construction with one meaning, the same as Android's")
    check("and a base with a trailing slash cannot produce a double slash",
          "while s.hasSuffix(\"/\") { s.removeLast() }" in swift,
          "https://0trustvpn.com/ is an ordinary thing to type")
    check("Android joins by concatenation, unchanged",
          'baseUrl + "/api/v1/devices/" + encoded' in kotlin)

    # ----------------------------------------------------------------------
    # The renewal link both phone apps put under an expiry notice.
    #
    # A phone shows the sweeper's warning and had nowhere to send the
    # customer: no command line for `0trust topup`, and the site's Begin flow
    # opens a NEW account instead of extending this one. Both apps now read a
    # URL out of the notice body — so the destination lives in sweep.py, not
    # written down twice more here.
    #
    # That makes a notice, which is operator-supplied text, into something
    # that can open a browser. The pattern is what keeps that from being a
    # phishing surface, and neither app can be executed from this suite, so
    # the pattern text is lifted out of both sources and exercised here.
    # ----------------------------------------------------------------------
    print("\n[notice-link] the same narrow pattern on both phones")
    main_kt = open(os.path.join(
        H.REPO, "mobile", "android", "app", "src", "main", "java", "vpn",
        "zerotrust", "app", "MainActivity.kt")).read()
    cv_src = open(os.path.join(H.REPO, "mobile", "ios", "0trust", "App",
                               "ContentView.swift")).read()
    cv = "\n".join(ln for ln in cv_src.splitlines()
                   if not ln.lstrip().startswith("///")
                   and not ln.lstrip().startswith("//"))

    k_pat = re.search(r'NOTICE_LINK = Regex\("""(.+?)"""\)', main_kt)
    s_pat = re.search(r'let pattern = "(.+?)"', cv)
    check("Android declares a notice-link pattern", bool(k_pat), main_kt[:200])
    check("iOS declares one too", bool(s_pat), cv[:200])
    if k_pat and s_pat:
        # Swift's string literal doubles every backslash; Kotlin's raw string
        # does not. Compare what the regex engines each end up with.
        kp = k_pat.group(1)
        sp = s_pat.group(1).replace("\\\\", "\\")
        check("and the two patterns are the same", kp == sp, f"{kp!r} vs {sp!r}")

        rx = re.compile(kp)
        def link(body):
            m = rx.search(body)
            return "https://0trustvpn.com" + m.group(1) if m else None

        # The real notice the sweeper posts has to produce the real page.
        sweep_src = open(os.path.join(H.REPO, "api", "sweep.py")).read()
        body = " ".join(re.findall(
            r'"([^"]*)"', re.search(r'\("Renew at .*?\),\n', sweep_src, re.S).group(0)))
        check("the sweeper's renewal notice yields the renewal page",
              link(body) == "https://0trustvpn.com/renew", link(body))

        # And nothing else can be smuggled through it. Each of these is a
        # notice body an operator could post; none may produce a link off our
        # own host.
        for hostile, why in [
            ("visit 0trustvpn.com@evil.example/x", "userinfo trick"),
            ("visit evil.example/0trustvpn.com", "our name in someone's path"),
            ("visit 0trustvpn.com.evil.example/x", "our name as a subdomain"),
            ("visit not0trustvpn.com/renew", "our name as a suffix"),
            ("visit javascript:alert(1)", "a script URL"),
            ("visit http://0trustvpn.com:8080@evil.example/", "port + userinfo"),
        ]:
            got = link(hostile)
            ok = got is None or got.startswith("https://0trustvpn.com/")
            check(f"a notice cannot link off-site via {why}", ok,
                  f"{hostile!r} -> {got!r}")
        check("and an ordinary notice with no URL gets no button",
              link("buc-01 reboots at 02:00 UTC.") is None)

finally:
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
