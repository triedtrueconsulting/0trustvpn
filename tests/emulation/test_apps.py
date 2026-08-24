#!/usr/bin/env python3
"""
The Android app and the Windows installer, against the real thing.

Neither can be compiled here: the Android SDK and Google's Maven repo are not
reachable from a headless box, and WiX only runs on Windows. That is a fact
about the environment, not a reason to ship them unchecked — the parts that
break in practice are checkable without a compiler, and every assertion below
came from something that was actually wrong in this repo:

  - The Kotlin wire types drifted from the API's snake_case JSON once already
    and broke the whole app. So: boot the control plane, make the real calls,
    and compare the JSON keys against what the @SerialName annotations claim.
  - The app generated a fresh WireGuard keypair on every connect, registering a
    new device each time until the account's cap locked the customer out — with
    no device list and no delete anywhere in the app to escape it.
  - It declared a second VpnService, which makes Android refuse to enable
    Always-on VPN for the app at all.
  - Its boot receiver was not exported, so it never received BOOT_COMPLETED.
  - The MSI named an icon file that was not in the repo, so the documented
    build command could not run.
  - Uninstalling left the tunnel service running and the device's WireGuard
    private key on disk.
"""
import glob, json, os, re, sys, xml.etree.ElementTree as ET
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as H

FAIL, PASS = [], []
def check(n, ok, d=""):
    (PASS if ok else FAIL).append(n)
    print(("  PASS  " if ok else "  FAIL  ") + n + ("" if ok else f"\n          {d}"))

ANDROID = os.path.join(H.REPO, "mobile", "android")
KT = os.path.join(ANDROID, "app", "src", "main", "java", "vpn", "zerotrust", "app")
MANIFEST = os.path.join(ANDROID, "app", "src", "main", "AndroidManifest.xml")
WIN = os.path.join(H.REPO, "installer", "windows")
AND_NS = "http://schemas.android.com/apk/res/android"

SRC = {os.path.basename(p): open(p).read() for p in glob.glob(os.path.join(KT, "*.kt"))}
ALL_KT = "\n".join(SRC.values())


def serial_names(block: str) -> set:
    """The JSON keys a Kotlin @Serializable data class actually reads.

    A property with @SerialName uses that; one without uses its Kotlin name,
    which is the trap — a camelCase property with no annotation silently
    matches nothing in a snake_case payload and takes its default. Splitting on
    top-level commas rather than on newlines, because a one-line data class is
    just as valid and hiding half its fields from this parser would make the
    check quietly pass.
    """
    parts, depth, cur = [], 0, ""
    for ch in block:
        if ch in "(<[":
            depth += 1
        elif ch in ")>]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur); cur = ""
        else:
            cur += ch
    parts.append(cur)

    keys = set()
    for part in parts:
        part = re.sub(r"//.*", "", part).strip()
        if not part:
            continue
        m = re.search(r'@SerialName\("([^"]+)"\)', part)
        if m:
            keys.add(m.group(1))
            continue
        m = re.search(r'\bval\s+([A-Za-z_][A-Za-z0-9_]*)\s*:', part)
        if m:
            keys.add(m.group(1))
    return keys


def _ico_sizes(path: str) -> set:
    """The icon sizes actually present in an .ico, read out of its directory."""
    import struct
    with open(path, "rb") as fh:
        head = fh.read(6)
        if len(head) < 6:
            return set()
        _, kind, count = struct.unpack("<HHH", head)
        if kind != 1:
            return set()
        out = set()
        for _ in range(count):
            entry = fh.read(16)
            if len(entry) < 16:
                break
            w = entry[0] or 256
            out.add(w)
        return out


def kotlin_class(name: str) -> str:
    """The parameter list of a data class, one-line or multi-line."""
    i = ALL_KT.find("data class " + name)
    if i < 0:
        return ""
    i = ALL_KT.index("(", i)
    depth, j = 0, i
    while j < len(ALL_KT):
        if ALL_KT[j] == "(":
            depth += 1
        elif ALL_KT[j] == ")":
            depth -= 1
            if depth == 0:
                return ALL_KT[i + 1:j]
        j += 1
    return ""


# ---------------------------------------------------------------------------
# Live control plane, so the comparison is against real JSON and not a copy of
# the Python models that could drift with them.
# ---------------------------------------------------------------------------
import tempfile
TMP = tempfile.mkdtemp(prefix="0trust-apps-")
DB = os.path.join(TMP, "0trust.db")
os.environ["ZTV_DB_PATH"] = DB
os.environ["ZTV_TRIAL_SECRET"] = "apps-secret"
os.environ["ZTV_TRIAL_POW_BITS"] = "10"
sys.path.insert(0, os.path.join(H.REPO, "api"))
import main as api_main; api_main.init_db()
H.seed_nodes(DB)
H.boot(DB, workers=2)

try:
    print("[1] the Android wire contract, against live API responses")
    token, _ = H.paid_account()
    hdr = {"X-Account-Token": token}

    st, status = H.call("GET", "/api/v1/account/status", headers=hdr)
    check("account status responds", st == 200, status)
    kt = serial_names(kotlin_class("AccountStatusResponse"))
    missing = set(status) - kt
    check("AccountStatusResponse reads every key the API sends",
          not missing,
          f"the app ignores {sorted(missing)} — a @SerialName is missing, and "
          "kotlinx just uses the default instead of telling anyone")

    st, regions = H.call("GET", "/api/v1/regions")
    check("regions responds", st == 200, regions)
    kt = serial_names(kotlin_class("RegionListItem"))
    check("RegionListItem matches", not (set(regions["regions"][0]) - kt),
          sorted(set(regions["regions"][0]) - kt))

    pub = H.genkey()
    st, reg = H.call("POST", "/api/v1/wg/register", headers=hdr, body={
        "pubkey": pub, "device_name": "android-test", "region": "zur"})
    check("wg/register responds", st == 200, reg)
    kt = serial_names(kotlin_class("WgRegisterResponse"))
    missing = set(reg) - kt
    check("WgRegisterResponse reads every key the API sends", not missing,
          sorted(missing))
    kt = serial_names(kotlin_class("WgPeer"))
    missing = set(reg["peers"][0]) - kt
    check("WgPeer reads every key the API sends", not missing, sorted(missing))

    st, devs = H.call("GET", "/api/v1/devices", headers=hdr)
    check("devices responds", st == 200, devs)
    kt = serial_names(kotlin_class("DeviceInfoResponse"))
    missing = set(devs[0]) - kt
    check("DeviceInfoResponse reads every key the API sends", not missing,
          sorted(missing))

    # And the other direction: what the app sends has to be what the API reads.
    req_fields = serial_names(kotlin_class("WgRegisterRequest"))
    st, _ = H.call("POST", "/api/v1/wg/register", headers=hdr,
                   body={k: {"pubkey": H.genkey(), "device_name": "shape-test",
                             "region": "zur", "exit_region": None}[k]
                         for k in req_fields})
    check("a body built from WgRegisterRequest's own field names is accepted",
          st == 200, f"HTTP {st} — the request type names fields the API does not")

    # A one-box deployment answers to all three region codes from one machine.
    # Every client has to notice, because "enters one country, exits another"
    # over the top of that is the exact claim-vs-reality drift this product
    # cannot afford. The CLI prints a warning; the app must too.
    check("the app reads same_host",
          "same_host" in SRC["ApiClient.kt"],
          "the field the control plane sets on a single-host multi-hop route")
    check("and says so instead of the privacy claim",
          "sameHostRoute" in SRC["MainActivity.kt"] and
          "SAME host" in SRC["MainActivity.kt"],
          "the routing card would keep saying traffic crosses a border")

    print("\n[2] the device cap is survivable from the phone")
    check("the app can list devices", "/api/v1/devices" in SRC["ApiClient.kt"])
    check("and delete one", "fun deleteDevice" in SRC["ApiClient.kt"] and
          ".delete()" in SRC["ApiClient.kt"])
    # base64 pubkeys contain '/' and '+'; a raw path segment splits on the first
    check("and escapes the pubkey into the path",
          "URLEncoder.encode" in SRC["ApiClient.kt"],
          "a key containing '/' would hit the wrong route")
    check("the UI exposes removal", "DevicesCard" in SRC["MainActivity.kt"] and
          "onRemoveDevice" in SRC["MainActivity.kt"])
    check("the device cap comes from the API, not a constant",
          "maxDevices" in SRC["MainActivity.kt"] and
          not re.search(r'deviceCount\}\s*/\s*8', SRC["MainActivity.kt"]),
          'the card printed "/ 8" for every account, including trials with a '
          'lower cap')

    print("\n[3] the device keypair survives a reconnect")
    # Registering is idempotent on the pubkey, which is only worth anything if
    # the client presents the same key twice. Prove the API's half here, then
    # assert the app's half is stored rather than regenerated.
    st, again = H.call("POST", "/api/v1/wg/register", headers=hdr, body={
        "pubkey": pub, "device_name": "android-test", "region": "zur"})
    check("re-registering the same key returns the same mesh IP",
          st == 200 and again["interface_ip"] == reg["interface_ip"],
          f"{reg['interface_ip']} -> {again.get('interface_ip')}")
    st, devs2 = H.call("GET", "/api/v1/devices", headers=hdr)
    check("and does not create a second device",
          len([d for d in devs2 if d["pubkey"] == pub]) == 1)

    boot = SRC.get("TunnelBootstrap.kt", "")
    check("the app stores its keypair", "KEY_WG_PRIV" in boot and
          "putString(KEY_WG_PRIV" in boot,
          "no persisted private key — every connect registers a new device")
    check("and reuses it rather than generating on each connect",
          "generateKeypair" not in SRC["AppState.kt"] and
          boot.count("WgConfig.generateKeypair()") == 1,
          "generateKeypair is called outside the one place that persists it")
    check("the private key lives in EncryptedSharedPreferences",
          "EncryptedSharedPreferences" in SRC["AppState.kt"])
    check("and is never sent to the control plane",
          "privateKey" not in SRC["ApiClient.kt"],
          "the API client mentions a private key; it must only ever see public ones")

    print("\n[4] the Android manifest")
    root = ET.parse(MANIFEST).getroot()
    app = root.find("application")
    services = app.findall("service")
    vpn_services = [
        s for s in services
        if any(a.get(f"{{{AND_NS}}}name") == "android.net.VpnService"
               for f in s.findall("intent-filter") for a in f.findall("action"))
    ]
    check("the app declares no VpnService of its own", not vpn_services,
          "the wireguard-android AAR already declares one. Android resolves an "
          "app's always-on VPN service by requiring exactly one match on that "
          "intent filter, so a second declaration makes Always-on VPN "
          "impossible to enable: " +
          str([s.get(f"{{{AND_NS}}}name") for s in vpn_services]))
    check("and does not hold BIND_VPN_SERVICE on a service it does not bind",
          not any(s.get(f"{{{AND_NS}}}permission", "").endswith("BIND_VPN_SERVICE")
                  for s in services))
    check("the tunnel service is not a VpnService in code",
          "class ZeroTrustVpnService : Service()" in SRC["ZeroTrustVpnService.kt"],
          "it still extends VpnService")

    for s in services:
        name = s.get(f"{{{AND_NS}}}name")
        fst = s.get(f"{{{AND_NS}}}foregroundServiceType")
        check(f"{name} declares a foreground service type", bool(fst),
              "Android 14 refuses to start a foreground service without one")
        if fst == "specialUse":
            props = [p.get(f"{{{AND_NS}}}name") for p in s.findall("property")]
            check(f"{name} declares the specialUse subtype property",
                  "android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" in props, props)

    perms = {p.get(f"{{{AND_NS}}}name") for p in root.findall("uses-permission")}
    for s in services:
        fst = s.get(f"{{{AND_NS}}}foregroundServiceType") or ""
        if fst == "specialUse":
            check("FOREGROUND_SERVICE_SPECIAL_USE is requested",
                  "android.permission.FOREGROUND_SERVICE_SPECIAL_USE" in perms,
                  sorted(perms))
    check("no permission is requested that nothing uses",
          "android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED" not in perms,
          "systemExempted was dropped; the permission should go with it")

    for r in app.findall("receiver"):
        name = r.get(f"{{{AND_NS}}}name")
        actions = {a.get(f"{{{AND_NS}}}name")
                   for f in r.findall("intent-filter") for a in f.findall("action")}
        if "android.intent.action.BOOT_COMPLETED" in actions:
            check(f"{name} is exported so BOOT_COMPLETED can reach it",
                  r.get(f"{{{AND_NS}}}exported") == "true",
                  "the system broadcasts from another uid; a non-exported "
                  "receiver never sees it, so the toggle did nothing")
    check("the boot receiver starts a service, not an activity",
          "startActivity" not in SRC["BootReceiver.kt"] and
          "ZeroTrustVpnService.reconnect" in SRC["BootReceiver.kt"],
          "Android 10 forbids background activity starts")

    if "android.permission.RECEIVE_BOOT_COMPLETED" in perms:
        check("something actually receives BOOT_COMPLETED",
              any("android.intent.action.BOOT_COMPLETED" ==
                  a.get(f"{{{AND_NS}}}name")
                  for r in app.findall("receiver")
                  for f in r.findall("intent-filter") for a in f.findall("action")))

    check("backups are off and not half-configured",
          app.get(f"{{{AND_NS}}}allowBackup") == "false" and
          app.get(f"{{{AND_NS}}}fullBackupContent") is None,
          "allowBackup=false next to backup rules reads as though some of the "
          "account token might be backed up")
    check("cleartext is refused",
          app.get(f"{{{AND_NS}}}networkSecurityConfig") is not None,
          "no network security config — the account token is a bearer credential")

    print("\n[5] the app is buildable and branded")
    check("the Gradle wrapper is present",
          all(os.path.exists(os.path.join(ANDROID, f)) for f in
              ("gradlew", "gradlew.bat", "gradle/wrapper/gradle-wrapper.jar",
               "gradle/wrapper/gradle-wrapper.properties")),
          "the README and CLAUDE.md both say to run ./gradlew; it did not exist")
    check("gradlew is executable",
          os.access(os.path.join(ANDROID, "gradlew"), os.X_OK))
    check("the sources can be parsed without the SDK",
          os.access(os.path.join(ANDROID, "syntax-check.sh"), os.X_OK))

    strings = ET.parse(os.path.join(
        ANDROID, "app/src/main/res/values/strings.xml")).getroot()
    app_name = next(s.text for s in strings if s.get("name") == "app_name")
    check("the launcher name is the brand mark", app_name == "0trustvpn",
          f"launcher says {app_name!r}; the site and the in-app mark say "
          "'0trustvpn'")
    check("the in-app wordmark agrees", '"trustvpn"' in SRC["MainActivity.kt"])

    gradle = open(os.path.join(ANDROID, "app", "build.gradle.kts")).read()
    themes = ET.parse(os.path.join(
        ANDROID, "app/src/main/res/values/themes.xml")).getroot()
    for style in themes.findall("style"):
        parent = style.get("parent", "")
        if parent.startswith(("Theme.Material3", "Theme.MaterialComponents")):
            check(f"{style.get('name')}'s parent theme has a dependency",
                  "com.google.android.material:material" in gradle,
                  f"{parent} ships in com.google.android.material, which this "
                  "app does not depend on — resource linking fails at build time")

    # Region codes: CLAUDE.md's recurring bug class #1.
    stale = re.findall(r'"(ams|fra|lon|sto|nyc|sjc|sgp|tyo)"', ALL_KT)
    check("no stale region codes in the app", not stale, sorted(set(stale)))
    st, live = H.call("GET", "/api/v1/regions")
    live_codes = {r["code"] for r in live["regions"]}
    fallback = set(re.findall(r'Region\("([a-z]{3})"', SRC["AppState.kt"]))
    check("the app's offline region fallback matches the live mesh",
          fallback == live_codes, f"app {sorted(fallback)} vs API {sorted(live_codes)}")

    print("\n[6] auth is the token header, never Bearer")
    check("the app sends X-Account-Token",
          SRC["ApiClient.kt"].count('"X-Account-Token"') >= 3)
    # Match a header actually being set, not the comment in ApiClient.kt that
    # explains why we do not use one.
    check("and never an Authorization header",
          not re.search(r'\.header\(\s*"Authorization"', ALL_KT) and
          not re.search(r'"Bearer ', ALL_KT))

    print("\n[7] the Windows installer")
    wxs_path = os.path.join(WIN, "0trust.wxs")
    wxs = open(wxs_path).read()
    wroot = ET.parse(wxs_path).getroot()
    W = "{http://wixtoolset.org/schemas/v4/wxs}"

    comps = {c.get("Id") for c in wroot.iter(W + "Component")}
    refs = {c.get("Id") for c in wroot.iter(W + "ComponentRef")}
    check("every ComponentRef resolves", not (refs - comps), sorted(refs - comps))

    for el in wroot.iter():
        src_attr = el.get("SourceFile") or el.get("Source")
        if not src_attr or "$(" in src_attr:
            continue
        p = os.path.join(WIN, src_attr.replace("\\", "/"))
        check(f"{src_attr} exists", os.path.exists(p),
              "the build fails on a clean checkout without it")

    check("the icon is a real multi-resolution .ico",
          _ico_sizes(os.path.join(WIN, "resources", "0trust.ico")) >= {16, 32, 48, 256},
          str(sorted(_ico_sizes(os.path.join(WIN, "resources", "0trust.ico")))))
    check("and can be regenerated from source",
          os.path.exists(os.path.join(WIN, "resources", "make-icon.py")))

    scripted = [ca.get("Id") for ca in wroot.iter(W + "CustomAction")
                if (ca.get("Script") or "").lower() in ("vbscript", "jscript")]
    check("no scripted custom action", not scripted,
          f"{scripted} — VBScript is deprecated on Windows and being removed, "
          "and a MsgBox from InstallExecuteSequence hangs every silent install")

    # A per-machine package must not keep its component state per-user.
    permachine = wroot.find(W + "Package").get("Scope") == "perMachine"
    if permachine:
        hkcu_keypaths = [rv.get("Key") for rv in wroot.iter(W + "RegistryValue")
                         if rv.get("Root") == "HKCU"]
        check("no per-user registry in a per-machine package", not hkcu_keypaths,
              f"{hkcu_keypaths} — ICE38/ICE57: the component is reference-counted "
              "against whichever admin ran setup")

    check("uninstall stops the tunnel",
          "disconnect" in wxs and "REMOVE=" in wxs,
          "the WireGuardTunnel$0trust0 service kept running after the client "
          "that owns it was removed")
    check("uninstall deletes the tunnel config",
          W + "RemoveFile" in {e.tag for e in wroot.iter()},
          "the config holds the device's WireGuard private key")

    header = wxs[:wxs.index("-->")]
    check("the build command in the header names both extensions it needs",
          "WixToolset.UI.wixext" in header and "WixToolset.Util.wixext" in header,
          "ui:WixUI and util:PermissionEx are both used; without -ext for each "
          "the documented command does not build")

    check("the build script exists rather than being pasted in the README",
          os.path.exists(os.path.join(WIN, "build.ps1")))

    # The page has to offer the file the build actually writes.
    page = open(os.path.join(H.REPO, "web", "download.html")).read()
    ps1 = open(os.path.join(WIN, "build.ps1")).read()
    m = re.search(r'/releases/([\d.]+)/(0trust-[\w.-]+\.msi)', page)
    if m:
        version, offered = m.groups()
        produced = re.search(r'\$out = "([^"]+)"', ps1)
        expected = produced.group(1).replace("$Version", version).replace("$a", "x64") \
                   if produced else "?"
        check("the download page links the file the build produces",
              offered == expected, f"page offers {offered}, build writes {expected}")

finally:
    H.shutdown()

print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
if FAIL:
    print("  failures: " + ", ".join(FAIL))
sys.exit(1 if FAIL else 0)
