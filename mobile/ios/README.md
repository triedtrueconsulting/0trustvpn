# 0trust — iOS app (skeleton, not built for v0.1)

> **This is intentionally not finished.** iOS is out of scope for the
> initial 0trust release. The QR-export flow lets iOS users connect via
> the official WireGuard app from the App Store, which is good enough
> for v0.1. This directory remains as a starting point for a future
> branded iOS app, but is **not on the launch path**.
>
> Reasons iOS was deferred:
> - Apple Developer Program: $99/yr recurring
> - Network Extension entitlement requires explicit Apple approval
>   (takes weeks, can be denied)
> - App Store review for VPN apps is strict and slow
> - The QR-export path covers the iOS use case with zero of those
>   obstacles
>
> Revisit after launch once you have revenue + customers asking for it.

- A SwiftUI app shell with the same visual language as the desktop GUI
  (warm dark palette, Instrument Serif, JetBrains Mono).
- A `NEPacketTunnelProvider` extension scaffold that loads a WireGuard
  config and brings the tunnel up.
- An API client that talks to the same `/api/v1/*` endpoints as the CLI.

## What you (or a mobile developer you hire) still need to do

1. **Open in Xcode 15+** and create a real project file (`0trust.xcodeproj`).
   The files in this directory are pure source — there's no `project.pbxproj`
   because that's a generated, IDE-coupled file that's easier to recreate
   than to edit by hand.

2. **Add the WireGuardKit Swift package**:
   `https://git.zx2c4.com/wireguard-apple` — this is the official Apple
   WireGuard library. It provides the kernel module bindings.

3. **Enable two App capabilities** in Xcode:
   - "Network Extensions" → "Packet Tunnel"
   - "App Groups" (so the main app and the tunnel extension can share state)

4. **Register two bundle IDs** in your Apple Developer account:
   - `vpn.zerotrust.app`        (the main app)
   - `vpn.zerotrust.app.tunnel` (the tunnel extension)

5. **Provision** both with App Store / Ad Hoc / Developer profiles. The
   Network Extension entitlement needs explicit Apple approval — file the
   request at <https://developer.apple.com/contact/request/networking-extension/>.

6. **Build / submit**. App Store review will ask about your privacy practices;
   point them at your published no-logs audit (see `docs/AUDIT.md`).

## Project layout

```
ios/
├── 0trust/App/                Main app (SwiftUI)
│   ├── App.swift              @main entry point
│   ├── ContentView.swift      Login / connect / status screens
│   ├── Theme.swift            Colors, fonts (matches desktop)
│   ├── APIClient.swift        Wraps /api/v1/account, /wg/register
│   └── State.swift            ObservableObject for app state
└── 0trust/Tunnel/             Packet Tunnel extension
    ├── PacketTunnelProvider.swift   Hooks into NetworkExtension
    └── Info.plist             Extension manifest
```

## Realistic timeline

If you have a Swift developer:
- **Week 1-2**: Get the skeleton building, App Group sharing working.
- **Week 3-4**: Account login flow, multi-hop region picker, polish.
- **Week 5-6**: TestFlight rollout, fixing platform quirks.
- **Week 7+**: App Store review iterations (typically 1-3 cycles for a VPN app).

If you don't have a Swift developer, the QR-code path (`0trust export` →
official WireGuard app) gets you to launch immediately.
