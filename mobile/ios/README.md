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
cd mobile/ios
./build.sh --check                                    # runs anywhere, no Mac
brew install xcodegen                                 # on the Mac
./build.sh --version 0.1.0 --build 1 --team <TEAMID>
```

`build.sh --check` is worth running before you rent or borrow a Mac: it
verifies the bundled faces and the source structure, and it is the same first
step the real build takes. Everything after it needs macOS, and the script
says so rather than failing obscurely.

`--export app-store` adds the export step; without it you get an `.xcarchive`
to open in Xcode's Organizer. Signing is not optional and there is nothing to
buy separately — see the header of `build.sh` for why iOS gets no equivalent
of the deliberately-unsigned Windows MSI.

To work in the IDE instead:

```bash
xcodegen generate && open 0trust.xcodeproj
```

The `.xcodeproj` is generated and deliberately not committed: a `project.pbxproj`
is a large machine-written file that conflicts on every branch and hides what
actually changed. `project.yml` is the reviewable source of the same
information.

Then, in Xcode:

1. Set your team on both targets (`0trust` and `0trustTunnel`), or pass
   `--team` to `build.sh`.
2. Confirm the App Group `group.vpn.zerotrust.app` exists on the Developer
   portal and is enabled on both targets. If the two disagree the app writes a
   config the extension cannot read, and `startTunnel` fails with "no
   configuration".
3. Build to a **device**. The Network Extension does not run in the Simulator,
   so a clean Simulator build proves nothing about the hard part.

### The fonts

They are committed, in `0trust/Resources/`, rather than being a step you have
to remember. `Font.custom` takes a PostScript name and **does not fail when
one does not resolve** — it substitutes the system font. A missing file
therefore produces an app that builds, launches and connects, and just looks
wrong, with nothing reporting a problem.

`./fetch-fonts.sh` regenerates them from upstream and names each file after
the PostScript name read out of the file itself, so what `UIAppFonts`
registers and what `Theme.swift` asks for cannot drift apart. `--check`
verifies that with no network, and `build.sh` runs it first. All three
families are OFL 1.1; `0trust/Resources/FONTS.md` has the details.

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

Checked by `fetch-fonts.sh --check`: every face `Theme.swift` asks for is a
file that is present, named by its own PostScript name, and registered in
`UIAppFonts` — the mismatch that would otherwise ship silently.

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
0trust/Resources/               the five bundled faces, and their licences
build.sh                        archive + export; --check runs without a Mac
fetch-fonts.sh                  refresh the faces; --check verifies them
syntax-check.sh                 structural check over the Swift sources
```

`Shared/` is in both targets on purpose: the extension is started by iOS on
its own — on-demand, or after a reboot under Always-on VPN — with the app not
running, so it has to be able to read the config and the keys by itself.
