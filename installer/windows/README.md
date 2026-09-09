# 0trustvpn — Windows installer

Build a signed MSI installer for the 0trust client. End users get a normal
Windows installer experience: double-click MSI, click through, app appears
in Start Menu and Add/Remove Programs.

```
installer/windows/
├── 0trust.wxs          WiX v4 source
├── License.rtf         Shown by the installer
├── resources/
│   ├── 0trust.ico      App icon (generated + committed)
│   ├── make-icon.py    Regenerates it; stdlib only
│   └── README.txt      Icon notes
└── README.md           (this file)
```

## Prerequisites (build host)

Windows 10/11 or Windows Server. **The MSI can only be built on Windows**
because WiX v4 ships as a .NET tool and signtool requires the Windows SDK.

Install:

```powershell
# .NET 6 or later (for WiX)
winget install Microsoft.DotNet.SDK.8

# WiX Toolset v4
dotnet tool install --global wix

# Windows SDK (for signtool.exe; only needed if you're signing)
winget install Microsoft.WindowsSDK.10
```

## Build

```powershell
# One-time: the two WiX extensions this installer uses
wix extension add -g WixToolset.UI.wixext
wix extension add -g WixToolset.Util.wixext

# Cross-compile the Go client for Windows from your repo root
cd client
make windows               # dist\0trust-windows-amd64.exe + -arm64.exe
cd ..\installer\windows

# x64
wix build 0trust.wxs `
    -arch x64 `
    -d Version=0.1.0 `
    -d BinaryDir=..\..\client\dist `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    -o 0trust-0.1.0-x64.msi

# ARM64 — same source, different -arch and -d Arch
wix build 0trust.wxs `
    -arch arm64 `
    -d Version=0.1.0 -d Arch=arm64 `
    -d BinaryDir=..\..\client\dist `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    -o 0trust-0.1.0-arm64.msi
```

The icon is already committed; `resources/make-icon.py` regenerates it if the
mark changes.

The output `0trust-0.1.0-x64.msi` (~6-7 MB) is now installable. It's
unsigned at this point — Windows SmartScreen will throw a warning on first
launch. Sign it before distributing.

## Sign — or decide not to, deliberately

Signing is optional in the mechanical sense and consequential in every other.
**Unsigned is a legitimate choice** (0trust ships unsigned as of this writing)
but it is a choice about what your customers experience, so make it knowingly:

- SmartScreen blocks the download until they click through "Keep anyway".
- First run shows the blue "Windows protected your PC" box with
  **Unknown publisher**; they need "More info → Run anyway".
- It does not improve over time. SmartScreen reputation attaches to the
  signing certificate, and for unsigned files to the exact file hash — which
  changes with every release, so the warning resets each time.

If you ship unsigned, build with `-UnsignedOnPurpose` (the script otherwise
ends in a red "do not ship" warning, which is the right default for everyone
who did not mean it), and make sure `web/download.html` tells customers what
they will see and points them at the PGP-signed checksums instead. That page
currently does. **If you later start signing, that section has to go** —
apologising for a warning that no longer appears is claim-vs-reality drift in
the other direction.

The PGP signature over `SHA256SUMS` is a different thing and is NOT optional.
It is what lets a customer verify the bytes are the ones you built, and with
no Authenticode signature it is the only integrity check they have left.
`scripts/release.sh` produces it and `preflight.sh`'s `installers-signed` gate
is about that signature, not about Authenticode — so it still passes on an
unsigned MSI.

### If you do want a certificate

Options:

| Provider | Approx. cost | Notes |
|----------|--------------|-------|
| DigiCert OV (Organization Validation) | $400/yr | SmartScreen "reputation" builds over weeks |
| DigiCert EV (Extended Validation) | $700/yr | Hardware token, immediate SmartScreen trust |
| SSL.com (cheaper alternative) | $200-500/yr | Same trust chain, fewer brand expectations |
| Sectigo OV | $200/yr | Cheapest viable option |

There is also **Azure Trusted Signing** at roughly $10/month, which is an
order of magnitude cheaper than the table above — Microsoft's own service,
same SmartScreen trust. The catch is identity validation: organisations
generally need three years of verifiable history, which a newly registered
GmbH does not have. Worth checking before assuming the prices above are the
floor.

EV gives immediate SmartScreen trust and is the strongest option for a
privacy product where customers checking the publisher field is part of the
trust model — but note what it actually proves: that a certificate authority
verified a company registration and took payment. It does not prove the file
is the one you built. The PGP signature does.

Once you have the cert:

```powershell
# Token-based EV cert: the cert is on a YubiKey or Token
signtool sign /n "0trust" `
              /tr http://timestamp.digicert.com `
              /td sha256 `
              /fd sha256 `
              0trust-0.1.0-x64.msi

# Verify the signature
signtool verify /pa /v 0trust-0.1.0-x64.msi
```

`/tr` adds a **timestamp** so the signature remains valid after the
certificate itself expires — important because installers stay in the wild
for years.

You should ALSO sign the .exe before bundling it into the MSI:

```powershell
signtool sign /n "0trust" /tr http://timestamp.digicert.com `
              /td sha256 /fd sha256 `
              ..\..\client\dist\0trust-windows-amd64.exe
```

That way Windows verifies the signature when the user runs `0trust.exe`
directly, not just when running the installer.

## Distribute

The signed MSI goes to `https://0trustvpn.com/releases/0.1.0/`. Update
the download page (`web/download.html`) to link to the MSI for Windows users
instead of the bare .exe.

Generate a SHA256 + PGP signature alongside:

```powershell
# In your release directory
sha256sum 0trust-0.1.0-x64.msi >> SHA256SUMS
gpg --detach-sign --armor SHA256SUMS   # re-sign after appending
```

Customers verify with the same `verify-release.sh` script as the other binaries.

## What the installer does

1. Installs `0trust.exe` to `C:\Program Files\0trust\`
2. Adds `C:\Program Files\0trust` to system PATH (so `0trust` works in any shell)
3. Creates Start Menu shortcut "0trustvpn" that launches `0trust.exe gui`
4. Creates the data directory `C:\ProgramData\0trust\` where tunnel configs live
5. Optional: desktop shortcut (checkbox during install)
6. Optional: auto-start on Windows login (checkbox during install)
7. Detects WireGuard for Windows — if missing, says so on the installer's
   final page, pointing the user at `https://wireguard.com/install/`. Does NOT
   block the install since the user might install WireGuard afterward, and
   says nothing at all during a silent install.
8. Registers an Uninstall entry that fully reverses all of the above. On
   uninstall it also runs `0trust disconnect` (which removes the
   `WireGuardTunnel$0trust0` service) and deletes `C:\ProgramData\0trust\`.
   That directory holds the tunnel config, and the config holds this device's
   WireGuard **private key** — leaving it behind after someone removes a
   privacy VPN is not a clean uninstall.

## What it deliberately does NOT do

- **Doesn't bundle WireGuard for Windows.** That installer is signed by
  ZX2C4 LLC (Jason Donenfeld) and we don't want to repackage someone else's
  signed binary under our cert. Users get the official one from
  wireguard.com.
- **Doesn't install a tray icon.** Planned for v0.2 once we settle the
  Go dependency story (`getlantern/systray` or native syscalls). For now
  users open the GUI from the Start Menu shortcut.
- **Doesn't auto-update.** Customers download new versions from the
  download page. Auto-update on a privacy product introduces a
  trust-anchored channel for forced updates; deliberately deferred.

## Build automation

`build.ps1` does everything above:

```powershell
.\build.ps1 -Version 0.1.0                                   # x64, unsigned
.\build.ps1 -Version 0.1.0 -Arch x64,arm64 -SignWith "0trust"
```

It checks the toolchain is present, adds the two WiX extensions, cross-compiles
the client for each architecture, signs the exe and the MSI when `-SignWith` is
given, verifies the resulting signature, and says loudly when it produced
unsigned output.
