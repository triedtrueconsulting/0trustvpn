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

finally:
    H.shutdown()
    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
