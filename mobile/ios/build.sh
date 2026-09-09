#!/usr/bin/env bash
# ============================================================================
# Build, archive and export the 0trustvpn iOS app from the command line.
# ============================================================================
# NOTHING HAS EVER RUN THIS. There is no Swift toolchain and no Apple SDK in
# the environment it was written in, and none of what it drives — xcodegen,
# xcodebuild, codesigning against a real team — has a Linux equivalent to
# rehearse against. It is written from the documented behaviour of those
# tools. Treat the first run on a Mac as the gate, exactly as with the app
# sources themselves, and expect to fix something.
#
# It exists anyway because the alternative was a README telling you to open
# Xcode and click, and a release process made of clicks is one that drifts
# without anybody noticing.
#
#   ./build.sh --version 0.1.0 --build 1 --team ABCDE12345
#   ./build.sh --version 0.1.0 --build 7 --team ABCDE12345 --export app-store
#   ./build.sh --check                    # everything checkable without a Mac
#
# ---------------------------------------------------------------------------
# On signing, since Windows made the opposite choice
# ---------------------------------------------------------------------------
# The MSI ships unsigned on purpose: an Authenticode certificate costs money
# and its absence lands on the customer as a SmartScreen warning we explain in
# advance. There is no equivalent decision available here. iOS will not
# install an unsigned application at all — not with a warning, not with a
# setting, not from our own site. The $99/yr Developer Program membership IS
# the signature, App Review is the only distribution channel to the public,
# and the packet-tunnel entitlement has to be granted by Apple before any of
# it applies. That is why iOS is the longest-lead item on the launch list and
# why the download page offers the WireGuard QR path instead of promising an
# app.
# ============================================================================
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

VERSION=""
BUILD=""
TEAM=""
EXPORT="none"
SCHEME="0trust"
CHECK_ONLY=0

die() { printf '\033[0;31m[!]\033[0m %s\n' "$*" >&2; exit 1; }
say() { printf '\033[0;33m[+]\033[0m %s\n' "$*"; }
ok()  { printf '\033[0;32m[✓]\033[0m %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --build)   BUILD="${2:-}";   shift 2 ;;
    --team)    TEAM="${2:-}";    shift 2 ;;
    --export)  EXPORT="${2:-}";  shift 2 ;;
    --scheme)  SCHEME="${2:-}";  shift 2 ;;
    --check)   CHECK_ONLY=1;     shift ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) die "unknown flag: $1" ;;
  esac
done

case "$EXPORT" in
  none|development|app-store) ;;
  *) die "--export must be none, development or app-store (got '$EXPORT')" ;;
esac

# --------------------------------------------------------------- checks ----
# Run the cheap ones first. An archive takes minutes; a font whose PostScript
# name nobody asks for takes a second to catch and produces an app that looks
# wrong rather than one that fails.
say "checking the bundled faces"
./fetch-fonts.sh --check

say "checking the sources structurally"
./syntax-check.sh

if [[ $CHECK_ONLY -eq 1 ]]; then
  ok "everything checkable without a Mac passes"
  exit 0
fi

# ----------------------------------------------------------------- host ----
[[ "$(uname -s)" == "Darwin" ]] || die \
  "iOS builds need macOS. Xcode, the iOS SDK and codesign exist nowhere else,
   and there is no cross-compiler. Run --check here and the rest on a Mac."

need() { command -v "$1" >/dev/null 2>&1 || die "$1 not found. $2"; }
need xcodebuild "Install Xcode from the App Store, then: sudo xcode-select -s /Applications/Xcode.app"
need xcodegen   "brew install xcodegen"

[[ -n "$VERSION" ]] || die "--version is required (e.g. --version 0.1.0)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--version must look like 1.2.3"
# App Store Connect rejects a build number it has already seen for a version,
# and the rejection arrives by email after the upload, not at build time.
[[ -n "$BUILD" ]] || die "--build is required: an integer, higher than every
   build already uploaded for version $VERSION. App Store Connect refuses a
   repeat, and it tells you by email after the upload rather than now."
[[ "$BUILD" =~ ^[0-9]+$ ]] || die "--build must be an integer"

if [[ "$EXPORT" != "none" && -z "$TEAM" ]]; then
  die "--export $EXPORT needs --team <TEAMID>. Find it at
   https://developer.apple.com/account under Membership Details."
fi

# ------------------------------------------------------------- generate ----
say "generating 0trust.xcodeproj from project.yml"
xcodegen generate

ARCHIVE="build/0trust-$VERSION.xcarchive"
rm -rf "$ARCHIVE" build/export
mkdir -p build

SETTINGS=(MARKETING_VERSION="$VERSION" CURRENT_PROJECT_VERSION="$BUILD")
[[ -n "$TEAM" ]] && SETTINGS+=(DEVELOPMENT_TEAM="$TEAM")

say "archiving $SCHEME $VERSION ($BUILD)"
# generic/platform=iOS, not a simulator destination: the packet-tunnel
# extension does not run in the Simulator, so a simulator build proves
# nothing about the only part of this app that is hard.
xcodebuild archive \
  -project 0trust.xcodeproj \
  -scheme "$SCHEME" \
  -configuration Release \
  -destination 'generic/platform=iOS' \
  -archivePath "$ARCHIVE" \
  "${SETTINGS[@]}"

ok "archive at $ARCHIVE"

if [[ "$EXPORT" == "none" ]]; then
  echo
  echo "  No export requested. Open it in Xcode's Organizer, or re-run with"
  echo "  --export app-store once the packet-tunnel entitlement is granted."
  exit 0
fi

# --------------------------------------------------------------- export ----
# Written per-build rather than committed: an ExportOptions.plist carries a
# team id, and a committed one is either somebody's real team id in git or a
# placeholder that silently exports for the wrong account.
PLIST="build/ExportOptions.plist"
method="$EXPORT"
[[ "$method" == "app-store" ]] && method="app-store-connect"
cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>$method</string>
    <key>teamID</key>
    <string>$TEAM</string>
    <key>signingStyle</key>
    <string>automatic</string>
    <key>uploadSymbols</key>
    <true/>
    <!-- Bitcode is gone from the toolchain; asking for it fails the export. -->
    <key>compileBitcode</key>
    <false/>
</dict>
</plist>
PLIST_EOF

say "exporting ($method)"
xcodebuild -exportArchive \
  -archivePath "$ARCHIVE" \
  -exportOptionsPlist "$PLIST" \
  -exportPath build/export

ipa="$(find build/export -name '*.ipa' | head -1)"
[[ -n "$ipa" ]] || die "export produced no .ipa — read the log above"
ok "exported $ipa"

cat <<NOTE

  Next, and deliberately not automated here:

    xcrun altool --upload-app -f "$ipa" -t ios \\
      --apiKey <KEY_ID> --apiIssuer <ISSUER_ID>

  Uploading needs an App Store Connect API key, and a script that takes one
  as an argument is a script that puts it in your shell history. Use
  Transporter.app, or export the key through the environment yourself.

  The .ipa does NOT go into releases/ and is not covered by SHA256SUMS.
  Customers never receive this file: Apple re-signs and re-packages what it
  distributes, so a hash of these bytes matches nothing anybody can download,
  and publishing one would be a verification step that cannot succeed.
NOTE
