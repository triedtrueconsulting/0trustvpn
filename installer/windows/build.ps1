<#
.SYNOPSIS
    Build (and optionally sign) the 0trustvpn MSI installers.

.DESCRIPTION
    Cross-compiles the Go client, then builds one MSI per architecture. Signing
    is opt-in: pass -SignWith with the certificate subject name. Without it you
    get unsigned MSIs, which are fine for testing and NOT fine for release —
    SmartScreen will block them and the publisher field will read "Unknown".

    The README used to carry this script as a code block with "drop that in
    installer/windows/build.ps1". Instructions to create a file are not the
    same as the file, and the version in the prose drifted from the wix command
    above it — it was missing the extension flags the build needs.

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
# Adding one that is already present is a no-op, so just make sure.
Write-Host "[+] WiX extensions" -ForegroundColor Yellow
wix extension add -g WixToolset.UI.wixext   | Out-Null
wix extension add -g WixToolset.Util.wixext | Out-Null

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
        Write-Host "  Still sign SHA256SUMS with the release PGP key —" -ForegroundColor Yellow
        Write-Host "  scripts/release.sh does it, and it is the only integrity" `
                   -ForegroundColor Yellow
        Write-Host "  check a customer has left." -ForegroundColor Yellow
    } else {
        Write-Host "UNSIGNED. Do not ship these unless that is a decision you have" `
                   -ForegroundColor Red
        Write-Host "made on purpose — re-run with -SignWith '<cert subject>', or" `
                   -ForegroundColor Red
        Write-Host "with -UnsignedOnPurpose if you know what it costs the customer." `
                   -ForegroundColor Red
    }
}
