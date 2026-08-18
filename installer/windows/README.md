# 0trust VPN — Windows installer

Build a signed MSI installer for the 0trust client. End users get a normal
Windows installer experience: double-click MSI, click through, app appears
in Start Menu and Add/Remove Programs.

```
installer/windows/
├── 0trust.wxs          WiX v4 source
├── License.rtf         Shown by the installer
├── resources/
│   ├── 0trust.ico      App icon (you provide; see resources/README.txt)
│   └── README.txt      Icon generation notes
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
cd installer\windows

# Make sure the icon is in place
ls resources\0trust.ico    # if missing, see resources\README.txt

# Cross-compile the Go client for Windows from your repo root
cd ..\..\client
make windows               # produces dist\0trust-windows-amd64.exe
cd ..\installer\windows

# Build the MSI
wix build 0trust.wxs `
    -arch x64 `
    -d Version=0.1.0 `
    -d BinaryDir=..\..\client\dist `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    -o 0trust-0.1.0-x64.msi
```

The output `0trust-0.1.0-x64.msi` (~6-7 MB) is now installable. It's
unsigned at this point — Windows SmartScreen will throw a warning on first
launch. Sign it before distributing.

## Sign

You need a **code-signing certificate**. Options:

| Provider | Approx. cost | Notes |
|----------|--------------|-------|
| DigiCert OV (Organization Validation) | $400/yr | SmartScreen "reputation" builds over weeks |
| DigiCert EV (Extended Validation) | $700/yr | Hardware token, immediate SmartScreen trust |
| SSL.com (cheaper alternative) | $200-500/yr | Same trust chain, fewer brand expectations |
| Sectigo OV | $200/yr | Cheapest viable option |

EV is the right choice for a privacy product where customers checking the
publisher field is part of the trust model.

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
3. Creates Start Menu shortcut "0trust VPN" that launches `0trust.exe gui`
4. Creates the data directory `C:\ProgramData\0trust\` where tunnel configs live
5. Optional: desktop shortcut (checkbox during install)
6. Optional: auto-start on Windows login (checkbox during install)
7. Detects WireGuard for Windows — if missing, shows a friendly post-install
   message pointing the user at `https://wireguard.com/install/`. Does NOT
   block the install since the user might install WireGuard afterward.
8. Registers an Uninstall entry that fully reverses all of the above.

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

The above commands are repetitive across releases. A `build.ps1`:

```powershell
param([Parameter(Mandatory=$true)][string]$Version)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "[+] Building 0trust client for Windows" -ForegroundColor Yellow
Push-Location ..\..\client
& make windows
Pop-Location

Write-Host "[+] Signing 0trust.exe" -ForegroundColor Yellow
signtool sign /n "0trust" /tr http://timestamp.digicert.com `
              /td sha256 /fd sha256 `
              ..\..\client\dist\0trust-windows-amd64.exe

Write-Host "[+] Building MSI" -ForegroundColor Yellow
wix build 0trust.wxs -arch x64 -d Version=$Version `
                                 -d BinaryDir=..\..\client\dist `
                                 -ext WixToolset.UI.wixext `
                                 -ext WixToolset.Util.wixext `
                                 -o "0trust-$Version-x64.msi"

Write-Host "[+] Signing MSI" -ForegroundColor Yellow
signtool sign /n "0trust" /tr http://timestamp.digicert.com `
              /td sha256 /fd sha256 `
              "0trust-$Version-x64.msi"

Write-Host "[✓] $PSScriptRoot\0trust-$Version-x64.msi" -ForegroundColor Green
```

Drop that in `installer/windows/build.ps1` and call as `.\build.ps1 -Version 0.1.0`.
