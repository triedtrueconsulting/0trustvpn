# 0trustvpn — iOS app

A branded SwiftUI client with its own WireGuard packet-tunnel extension. It
does what the Android app does: sign in with an account token, pick entry and
exit regions, connect, manage the devices on the account.

**The source is complete. Nobody has compiled it.** There is no Swift compiler
in the environment this was written in, and SwiftUI, NetworkExtension and
Security have no Linux implementation to compile against even if there were.
Everything below about what is verified, and what is not, is meant literally.

## Building it

```bash
brew install xcodegen
cd mobile/ios
xcodegen generate          # writes 0trust.xcodeproj from project.yml
open 0trust.xcodeproj
```

The `.xcodeproj` is generated and deliberately not committed: a `project.pbxproj`
is a large machine-written file that conflicts on every branch and hides what
actually changed. `project.yml` is the reviewable source of the same
information.

Then, in Xcode:

1. Set your team on both targets (`0trust` and `0trustTunnel`).
2. Confirm the App Group `group.vpn.zerotrust.app` exists on the Developer
   portal and is enabled on both targets. If the two disagree the app writes a
   config the extension cannot read, and `startTunnel` fails with "no
   configuration".
3. Drop the five font files into `0trust/Resources/` (Instrument Serif,
   JetBrains Mono Regular/Medium/Bold, IBM Plex Sans). They are listed in
   `UIAppFonts`; without them the type falls back to system faces and the app
   simply looks wrong rather than breaking.
4. Build to a **device**. The Network Extension does not run in the Simulator.

## What Apple requires before this can ship

This is the part that is not engineering, and it is why iOS was deferred from
v0.1 in the first place:

- **Apple Developer Program** — $99/yr, and an organisation enrolment needs a
  D-U-N-S number, which takes its own time.
- **The Network Extension entitlement** (`packet-tunnel-provider`) is not
  self-serve. You request it from Apple and wait; approval is measured in
  weeks and can be refused.
- **App Review for VPN apps is strict.** Expect questions about what is
  logged, who operates the servers, and why an app collects no account
  identity. Guideline 5.4 requires a VPN app to be published by an
  organisation, not an individual, and to declare that it does not sell data.
- **Export compliance.** `ITSAppUsesNonExemptEncryption` is set with the
  exemption for standard published cryptography, which is what WireGuard is.

Until all of that is done, the QR-export path in the desktop GUI remains the
supported way onto iOS: it hands the official WireGuard app a config with no
obstacles at all.

## What is actually verified, and what is not

Checked automatically on every push, by `tests/emulation/test_ios.py` against a
**live control plane**:

- every `CodingKeys` entry exists in the real JSON the API returns — the
  camelCase/snake_case mismatch that once broke the Android client entirely
  would fail this
- auth is `X-Account-Token`, never `Authorization: Bearer`
- region codes come from `/api/v1/regions` rather than a literal, and no stale
  code from the earlier design is present
- the device keypair is persisted, not regenerated per connect (the bug that
  burned the account device cap on Android)
- the device cap and the trial length are rendered from the server, never
  compiled in
- `startTunnel` actually starts the adapter and reports failure rather than
  calling back with success
- `::/0` is always claimed; a v6 address is only added when the exit provides
  one
- both targets carry the same App Group, keychain group and NE entitlement,
  and the app loads the bundle id the extension is really built with

Checked by `syntax-check.sh`: delimiters balance, no placeholder
(`fatalError`/`TODO`) survives, every framework a file uses is imported.

**Not checked by anything here: whether it compiles.** No Swift toolchain, no
Apple SDKs. `xcodegen generate && xcodebuild` on a Mac is the real gate, and it
has not been run. Expect to fix compile errors on the first build.

## Layout

```
project.yml                     XcodeGen spec — the buildable definition
0trust/App/                     the app target
  App.swift                     @main entry
  ContentView.swift             sign-in, status, routing, account, devices
  AppState.swift                the only place tunnel lifecycle is driven
  Theme.swift                   the shared warm-dark palette and button styles
  Info.plist, 0trust.entitlements
0trust/Shared/                  compiled into BOTH targets
  APIClient.swift               the wire contract; mirrors client/internal/api
  DeviceIdentity.swift          the keypair, generated once and kept
  Keychain.swift                token + private key, shared with the extension
  WgConfig.swift                wg-quick serializer + the App Group handoff
0trust/Tunnel/                  the packet-tunnel extension
  PacketTunnelProvider.swift    WireGuardKit adapter
  Info.plist, Tunnel.entitlements
```

`Shared/` is in both targets on purpose: the extension is started by iOS on
its own — on-demand, or after a reboot under Always-on VPN — with the app not
running, so it has to be able to read the config and the keys by itself.
