# 0trust VPN — Android app

A real Android app, not a skeleton. Builds with Android Studio Hedgehog (2023.1.1) or later, produces a working APK that uses the official `wireguard-android` library for the data plane.

```
mobile/android/
├── build.gradle.kts            Project plugins
├── settings.gradle.kts         Module declaration + repos
├── gradle.properties           AGP / Kotlin / Compose flags
├── gradlew, gradlew.bat        Gradle wrapper scripts
├── gradle/wrapper/             Gradle 8.10.2 wrapper + jar
├── syntax-check.sh             Parse the Kotlin without the Android SDK
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
        │   ├── ZeroTrustVpnService.kt   Foreground service driving GoBackend
        │   ├── TunnelBootstrap.kt       Device identity + register -> config
        │   ├── WgConfig.kt              Maps API response to wg config
        │   ├── BootReceiver.kt          Reconnect after a restart
        │   └── Theme.kt                 Material 3 dark theme
        └── res/                         Icons, colors, strings, network config
```

## What it does

- Login with the 16-character account token from `0trustvpn.com`
- Connect / disconnect a real WireGuard tunnel via the official `wireguard-android` library (GoBackend, userspace)
- Single-hop or multi-hop routing across the three jurisdictions (Switzerland, Iceland, Romania)
- Persistent foreground notification while connected, with a "Disconnect" action
- Device manager: see every registered device, remove one to free a slot
- Settings: reconnect after restart, a pointer to Android's Always-on VPN
  (the real kill switch), the control-plane address for self-hosted
  deployments, sign out
- Encrypted token *and device private key* storage via
  `EncryptedSharedPreferences` keyed to the device Keystore. The keypair is
  generated once and kept: registration is idempotent on the public key, so
  reconnecting reuses the same device and the same mesh IP instead of
  registering a new one and eating the account's device cap
- Material 3 dark theme matching the 0trust web design system

## What it deliberately does NOT do (yet)

- **No QSTile (quick settings toggle)** — `v0.2`
- **No widget** — `v0.2`
- **No in-app kill switch** — Android's own Always-on VPN with "Block
  connections without VPN" is stronger than anything an app can do for itself,
  and Settings links straight to it. An app-level imitation would be a weaker
  thing wearing the same name.
- **No in-app trial signup** — the proof-of-work flow lives on the website;
  the app takes the token it produces.

## Build

### Prerequisites

1. **Android Studio Hedgehog (2023.1.1+)** — required for AGP 8.5 and the Kotlin Compose Compiler plugin
2. **JDK 17** — bundled with Android Studio
3. **Android SDK 34** — install via SDK Manager
4. **Android SDK Build-Tools 34** — install via SDK Manager

No NDK is needed: `com.wireguard.android:tunnel` ships the Go data plane as
prebuilt `.so` libraries in the AAR.

### Checking the sources without the SDK

A full build needs the Android SDK and network access to Google's Maven repo.
Where you have neither — a locked-down CI network, a headless box — this parses
every Kotlin file with the real compiler front-end, which is enough to catch
anything malformed:

```bash
./syntax-check.sh
```

It downloads the Kotlin compiler from Maven Central on first run and filters
out the `unresolved reference` errors that the absent Android classpath
guarantees. Syntax errors are the failure it reports, and it should always
pass.

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
AutoName: 0trustvpn

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
- [ ] Reconnect-after-restart brings the tunnel back after a reboot (if enabled)
- [ ] Connecting twice does NOT create a second device — check the device list
      before and after, and confirm the mesh IP is unchanged
- [ ] The device list shows every device, and removing one frees a slot
- [ ] The device count reads against the real cap for the plan (a trial account
      shows the trial cap, not 8)
- [ ] Always-on VPN can be enabled for the app in system settings — if Android
      refuses, the merged manifest has more than one VpnService again
- [ ] Sign out stops the tunnel AND clears the encrypted prefs (verify with
      `adb shell run-as vpn.zerotrust.app cat shared_prefs/zerotrust_secure.xml`)

If anything misbehaves, the usual suspects are:
- ProGuard stripped a `wireguard-android` JNI class — add a `-keep` rule
- Android SDK / NDK version mismatch — run `./gradlew --refresh-dependencies`
- Malformed `/api/v1/wg/register` response — check `adb logcat | grep 0trust-vpn`
