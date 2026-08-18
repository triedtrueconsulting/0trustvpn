# 0trust VPN — Android app

A real Android app, not a skeleton. Builds with Android Studio Hedgehog (2023.1.1) or later, produces a working APK that uses the official `wireguard-android` library for the data plane.

```
mobile/android/
├── build.gradle.kts            Project plugins
├── settings.gradle.kts         Module declaration + repos
├── gradle.properties           AGP / Kotlin / Compose flags
├── gradle/wrapper/             Gradle 8.10 wrapper
├── keystore.properties         (NOT committed — see below)
└── app/
    ├── build.gradle.kts        Module deps + signing
    ├── proguard-rules.pro      Keep rules for WireGuard JNI
    └── src/main/
        ├── AndroidManifest.xml
        ├── java/vpn/zerotrust/app/
        │   ├── MainActivity.kt          Full Compose UI
        │   ├── AppState.kt              ViewModel + encrypted prefs
        │   ├── ApiClient.kt             OkHttp + kotlinx.serialization
        │   ├── ZeroTrustVpnService.kt   Foreground VpnService
        │   ├── WgConfig.kt              Maps API response to wg config
        │   ├── BootReceiver.kt          Auto-connect on boot
        │   └── Theme.kt                 Material 3 dark theme
        └── res/                         Icons, colors, strings, backup rules
```

## What it does

- Login with the 16-character account token from `0trustvpn.com`
- Connect / disconnect a real WireGuard tunnel via the official `wireguard-android` library (GoBackend, userspace)
- Single-hop or multi-hop routing across the three jurisdictions (Switzerland, Iceland, Romania)
- Persistent foreground notification while connected, with a "Disconnect" action
- Settings: auto-connect on device boot, sign out
- Encrypted token storage via `EncryptedSharedPreferences` keyed to the device Keystore
- Material 3 dark theme matching the 0trust web design system

## What it deliberately does NOT do (yet)

- **No QSTile (quick settings toggle)** — `v0.2`
- **No widget** — `v0.2`
- **No kill switch beyond what VpnService provides** — `v0.2`

## Build

### Prerequisites

1. **Android Studio Hedgehog (2023.1.1+)** — required for AGP 8.5 and the Kotlin Compose Compiler plugin
2. **JDK 17** — bundled with Android Studio
3. **Android SDK 34** — install via SDK Manager
4. **NDK** (required by `wireguard-android` for the Go runtime) — install via SDK Manager → SDK Tools → "NDK (Side by side)"

### First build

```bash
cd mobile/android
./gradlew assembleDebug
```

Output: `app/build/outputs/apk/debug/app-debug.apk` (~12-15 MB; mostly Go runtime + Compose).

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

## Release build (signed)

You need an upload keystore. Generate one **once** and store it safely — losing it means you can't update an app published to Play.

```bash
keytool -genkeypair -alias zerotrust-upload -keyalg RSA -keysize 4096 \
        -validity 10000 -keystore zerotrust-upload.jks
```

Create `mobile/android/keystore.properties` (gitignored):

```properties
storeFile=/absolute/path/to/zerotrust-upload.jks
storePassword=<keystore-password>
keyAlias=zerotrust-upload
keyPassword=<key-password>
```

Then:

```bash
./gradlew assembleRelease    # APK for sideload / F-Droid
./gradlew bundleRelease      # AAB for Play Store
```

## Distribution

| Channel | Pros | Cons |
|---------|------|------|
| **Direct .apk download** from `0trustvpn.com/releases/0.1.0/` | Zero third-party visibility; users sideload | Friction (enable "unknown sources") |
| **F-Droid** | Auto-updates, source-built reproducibly by F-Droid, fully open distribution | Smaller audience; submission review takes ~2 weeks |
| **Google Play Store** | Largest audience, smoothest UX | $25 fee, strict VPN-app review, Google sees install events |

For a privacy product, the sequence we recommend is: direct download first (immediate), F-Droid second (gives auto-updates without Google), Play Store last (audience reach, accepting the tradeoff). All three can coexist.

### F-Droid metadata

When you're ready to submit, the file at `metadata/vpn.zerotrust.app.yml` in your fdroiddata fork should look like:

```yaml
Categories:
  - Internet
  - Security
License: GPL-3.0-or-later
WebSite: https://0trustvpn.com/
SourceCode: https://github.com/0trust/cli
IssueTracker: https://github.com/0trust/cli/issues
AutoName: 0trust VPN

RepoType: git
Repo: https://github.com/0trust/cli

Builds:
  - versionName: '0.1.0'
    versionCode: 1
    commit: v0.1.0
    subdir: mobile/android/app
    gradle:
      - yes

AutoUpdateMode: Version
UpdateCheckMode: Tags
CurrentVersion: '0.1.0'
CurrentVersionCode: 1
```

## Updates

1. Bump `versionCode` (must monotonically increase) and `versionName` in `app/build.gradle.kts`
2. Tag the commit: `git tag v0.1.1`
3. `./gradlew bundleRelease`
4. Upload to your chosen distribution channels
5. F-Droid auto-detects the new tag and rebuilds

## Pre-launch verification checklist

- [ ] Login with a real token issued by your control plane
- [ ] Single-hop connect to each of `zur`, `rey`, `buc`
- [ ] Multi-hop across each entry → exit pair (6 valid combinations)
- [ ] Disconnect cleanly tears down the tunnel
- [ ] VPN-consent dialog appears on first connect, not on subsequent ones
- [ ] Notification appears on connect and dismisses on disconnect
- [ ] Auto-connect-on-boot reconnects after a device reboot (if enabled)
- [ ] Sign out clears the encrypted prefs (verify with `adb shell run-as vpn.zerotrust.app cat shared_prefs/zerotrust_secure.xml`)

If anything misbehaves, the usual suspects are:
- ProGuard stripped a `wireguard-android` JNI class — add a `-keep` rule
- Android SDK / NDK version mismatch — run `./gradlew --refresh-dependencies`
- Malformed `/api/v1/wg/register` response — check `adb logcat | grep 0trust-vpn`
