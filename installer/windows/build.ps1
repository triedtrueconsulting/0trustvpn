<#
.SYNOPSIS
    Build (and optionally sign) the 0trustvpn MSI installers.

.DESCRIPTION
    Cross-compiles the Go client, then builds one MSI per architecture. Signing
    is opt-in: pass -SignWith with the certificate subject name. Without it you
    get unsigned MSIs, which are fine for testing and NOT fine for release  - 
    SmartScreen will block them and the publisher field will read "Unknown".

    The README used to carry this script as a code block with "drop that in
    installer/windows/build.ps1". Instructions to create a file are not the
    same as the file, and the version in the prose drifted from the wix command
    above it - it was missing the extension flags the build needs.

.EXAMPLE
    .\build.ps1 -Version 0.1.0
    .\build.ps1 -Version 0.1.0 -SignWith "0trust" -Arch x64,arm64
#>
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [ValidateSet("x64", "arm64")][string[]]$Arch = @("x64"),
    [string]$SignWith = "",
    # Acknowledge that shipping unsigned is the intent, not an oversight.
    # Without it an unsigned build still ends in a red warning, because for
    # most people reaching that line it IS an oversight.
    [switch]$UnsignedOnPurpose,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# Go's name for the architecture is not WiX's name for it.
$goArch = @{ "x64" = "amd64"; "arm64" = "arm64" }

function Require-Tool($name, $hint) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "$name not found on PATH. $hint"
    }
}

Require-Tool "go"  "Install the Go toolchain: https://go.dev/dl/"
Require-Tool "wix" "dotnet tool install -g wix"
if ($SignWith) {
    Require-Tool "signtool" "Install the Windows SDK (Microsoft.WindowsSDK.10)."
}

# Both extensions are needed by 0trust.wxs (ui:WixUI, util:PermissionEx).
#
# Pinned to the toolset's own version. Unversioned, `wix extension add`
# resolves the newest published build, which on a WiX 7 CLI can leave the
# extension unusable - the add appears to work and `wix build` then fails
# with WIX0144 "could not be found", thirty seconds later and pointing at
# the wrong thing.
#
# And the result is CHECKED. These two lines ended in `| Out-Null`, which
# discards stdout and does nothing about the exit code, so a failed add was
# silent and the build died further on with a message that described a
# missing extension rather than a failed install of one.
Write-Host "[+] WiX extensions" -ForegroundColor Yellow
$wixVersion = ((wix --version) -split '\+')[0].Trim()

# 0trust.wxs targets WiX v4, and v4/v5 are MIT with no strings. Starting at
# v6 the toolset carries the Open Source Maintenance Fee: revenue-generating
# use requires paying it, and v7 refuses to run at all until the EULA is
# accepted (WIX7015). That is a commercial decision about THIS product's
# revenue, not something a build script may take on the operator's behalf  - 
# so it stops and explains rather than quietly running `wix eula accept`.
$wixMajor = [int]($wixVersion -split '\.')[0]
if ($wixMajor -ge 6) {
    Write-Host ""
    Write-Host "  WiX $wixVersion carries the Open Source Maintenance Fee." -ForegroundColor Yellow
    Write-Host "  0trust is a commercial product, so that is a licensing" -ForegroundColor Yellow
    Write-Host "  question, not a build flag. Two honest ways forward:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    1. Use the version 0trust.wxs was written for, which is" -ForegroundColor Yellow
    Write-Host "       outside the fee entirely:" -ForegroundColor Yellow
    Write-Host "         dotnet tool uninstall -g wix" -ForegroundColor Gray
    Write-Host "         dotnet tool install -g wix --version 5.*" -ForegroundColor Gray
    Write-Host ""
    Write-Host "    2. Pay the fee, then accept it on this machine:" -ForegroundColor Yellow
    Write-Host "         wix eula accept wix$wixMajor" -ForegroundColor Gray
    Write-Host "       https://docs.firegiant.com/wix/osmf/" -ForegroundColor Gray
    Write-Host ""
    throw "refusing to build against WiX $wixVersion without that decision being made"
}
foreach ($ext in @("WixToolset.UI.wixext", "WixToolset.Util.wixext")) {
    wix extension add -g "$ext/$wixVersion" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        # An older toolset may not publish a matching build; try unversioned
        # before giving up, but say which one actually landed.
        Write-Host "    $ext/$wixVersion unavailable - trying unversioned" `
                   -ForegroundColor Yellow
        wix extension add -g $ext 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "could not add $ext. Try manually: wix extension add -g $ext/$wixVersion"
        }
    }
}
# Prove they are there, rather than assuming the add did what it said.
$installed = (wix extension list -g 2>&1 | Out-String)
foreach ($ext in @("WixToolset.UI.wixext", "WixToolset.Util.wixext")) {
    if ($installed -notmatch [regex]::Escape($ext)) {
        throw ("$ext is still not installed after adding it. " +
               "'wix extension list -g' does not show it, and 0trust.wxs " +
               "cannot build without it.")
    }
    Write-Host "    $ext" -ForegroundColor DarkGray
}

if (-not (Test-Path "resources\0trust.ico")) {
    Write-Host "[+] Generating the icon" -ForegroundColor Yellow
    python3 resources\make-icon.py
}

Write-Host "[+] Building the client" -ForegroundColor Yellow
Push-Location ..\..\client
try {
    $env:CGO_ENABLED = "0"
    foreach ($a in $Arch) {
        $ga = $goArch[$a]
        $env:GOOS = "windows"; $env:GOARCH = $ga
        go build -trimpath -ldflags "-s -w" -o "dist\0trust-windows-$ga.exe" .\cmd\0trust
        if ($LASTEXITCODE -ne 0) { throw "go build failed for $ga" }
        Write-Host "    dist\0trust-windows-$ga.exe"
    }
} finally {
    Remove-Item Env:\GOOS, Env:\GOARCH -ErrorAction SilentlyContinue
    Pop-Location
}

# Sign the exe too, so Windows verifies it when the user runs 0trust.exe
# directly and not only when they run the installer.
if ($SignWith) {
    Write-Host "[+] Signing the client" -ForegroundColor Yellow
    foreach ($a in $Arch) {
        signtool sign /n $SignWith /tr $TimestampUrl /td sha256 /fd sha256 `
                 "..\..\client\dist\0trust-windows-$($goArch[$a]).exe"
        if ($LASTEXITCODE -ne 0) { throw "signtool failed on the $a client" }
    }
}

$built = @()
foreach ($a in $Arch) {
    $out = "0trust-$Version-$a.msi"
    Write-Host "[+] Building $out" -ForegroundColor Yellow
    wix build 0trust.wxs -arch $a `
        -d Version=$Version `
        -d Arch=$($goArch[$a]) `
        -d BinaryDir=..\..\client\dist `
        -ext WixToolset.UI.wixext `
        -ext WixToolset.Util.wixext `
        -o $out
    if ($LASTEXITCODE -ne 0) { throw "wix build failed for $a" }

    if ($SignWith) {
        Write-Host "[+] Signing $out" -ForegroundColor Yellow
        signtool sign /n $SignWith /tr $TimestampUrl /td sha256 /fd sha256 $out
        if ($LASTEXITCODE -ne 0) { throw "signtool failed on $out" }
        signtool verify /pa /v $out | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "signature did not verify on $out" }
    }
    $built += $out
}

Write-Host ""
foreach ($f in $built) {
    $size = [math]::Round((Get-Item $f).Length / 1MB, 1)
    Write-Host "[OK] $PSScriptRoot\$f  ($size MB)" -ForegroundColor Green
}
if (-not $SignWith) {
    Write-Host ""
    if ($UnsignedOnPurpose) {
        # A deliberate choice, so say what it costs rather than calling it a
        # mistake. The consequence is real and lands on the customer, not on
        # whoever built this.
        Write-Host "UNSIGNED, deliberately." -ForegroundColor Yellow
        Write-Host "  Customers will see SmartScreen block the download, and" `
                   -ForegroundColor Yellow
        Write-Host "  'Windows protected your PC / Unknown publisher' on first run." `
                   -ForegroundColor Yellow
        Write-Host "  web/download.html explains that to them and points at the" `
                   -ForegroundColor Yellow
        Write-Host "  PGP-signed checksums instead. Keep those two in step: if this" `
                   -ForegroundColor Yellow
        Write-Host "  ever IS signed, that page must stop apologising for it." `
                   -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Still sign SHA256SUMS with the release PGP key  - " -ForegroundColor Yellow
        Write-Host "  scripts/release.sh does it, and it is the only integrity" `
                   -ForegroundColor Yellow
        Write-Host "  check a customer has left." -ForegroundColor Yellow
    } else {
        Write-Host "UNSIGNED. Do not ship these unless that is a decision you have" `
                   -ForegroundColor Red
        Write-Host "made on purpose - re-run with -SignWith '<cert subject>', or" `
                   -ForegroundColor Red
        Write-Host "with -UnsignedOnPurpose if you know what it costs the customer." `
                   -ForegroundColor Red
    }
}
