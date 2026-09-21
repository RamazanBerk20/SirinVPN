param(
    [ValidateSet("x86_64", "aarch64")][string]$Architecture = "x86_64",
    [Parameter(Mandatory = $true)][string]$ServerX64,
    [Parameter(Mandatory = $true)][string]$ServerArm64,
    [Parameter(Mandatory = $true)][string]$RoutingDriver
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") { throw "Run this script on Windows with the MSVC Rust toolchain." }
foreach ($SirinTool in @("rustup", "cargo", "pnpm", "perl")) {
    if (-not (Get-Command $SirinTool -ErrorAction SilentlyContinue)) {
        throw "Install $SirinTool before packaging. Perl is required by the vendored SSH/OpenSSL build."
    }
}
$SirinRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$SirinTarget = "$Architecture-pc-windows-msvc"
$SirinBinaries = Join-Path $SirinRoot "apps/desktop/src-tauri/binaries"
$SirinWindows = Join-Path $SirinBinaries "windows"
$SirinCache = Join-Path $SirinRoot ".cache/windows-packaging"
New-Item -ItemType Directory -Force $SirinWindows, $SirinCache | Out-Null
$SirinDriverSource = (Resolve-Path $RoutingDriver).Path
$SirinDriverBytes = [System.IO.File]::ReadAllBytes($SirinDriverSource)
if ($SirinDriverBytes.Length -lt 512 -or [BitConverter]::ToUInt16($SirinDriverBytes, 0) -ne 0x5a4d) {
    throw "Pass the matching WDK-built SirinVPN .sys routing driver."
}
$SirinPeOffset = [BitConverter]::ToInt32($SirinDriverBytes, 60)
$SirinMachine = if ($Architecture -eq "x86_64") { 0x8664 } else { 0xaa64 }
if ($SirinPeOffset -lt 64 -or $SirinPeOffset + 24 -gt $SirinDriverBytes.Length -or
    [BitConverter]::ToUInt32($SirinDriverBytes, $SirinPeOffset) -ne 0x4550 -or
    [BitConverter]::ToUInt16($SirinDriverBytes, $SirinPeOffset + 4) -ne $SirinMachine) {
    throw "The routing driver's PE architecture does not match the Windows package."
}
Copy-Item -LiteralPath $SirinDriverSource -Destination (Join-Path $SirinWindows "sirinvpn-app-routing.sys") -Force

function Invoke-SirinCommand([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
function Copy-SirinElf([string]$Source, [string]$Name, [uint16]$Machine) {
    $SirinSource = (Resolve-Path $Source).Path
    $SirinBytes = [System.IO.File]::ReadAllBytes($SirinSource)
    if ($SirinBytes.Length -lt 64 -or $SirinBytes.Length -gt 67108864 -or
        $SirinBytes[0] -ne 0x7f -or $SirinBytes[1] -ne 0x45 -or $SirinBytes[2] -ne 0x4c -or $SirinBytes[3] -ne 0x46 -or
        $SirinBytes[4] -ne 2 -or $SirinBytes[5] -ne 1 -or [BitConverter]::ToUInt16($SirinBytes, 18) -ne $Machine) {
        throw "The $Name VPS payload is not the expected Linux ELF executable."
    }
    $SirinDestination = Join-Path $SirinBinaries $Name
    if (-not $SirinSource.Equals($SirinDestination, [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $SirinSource -Destination $SirinDestination -Force
    }
}

Copy-SirinElf $ServerX64 "sirinvpn-server-x86_64" 62
Copy-SirinElf $ServerArm64 "sirinvpn-server-aarch64" 183
$SirinVendor = Get-Content -Raw (Join-Path $SirinRoot "packaging/windows/wireguard-nt.json") | ConvertFrom-Json
$SirinArchive = Join-Path $SirinCache "wireguard-nt-$($SirinVendor.version).zip"
if (-not (Test-Path -LiteralPath $SirinArchive)) {
    Invoke-WebRequest -Uri $SirinVendor.url -OutFile $SirinArchive
}
if ((Get-FileHash -Algorithm SHA256 $SirinArchive).Hash.ToLowerInvariant() -ne $SirinVendor.archive_sha256) {
    throw "The WireGuardNT archive does not match the pinned SHA-256."
}
$SirinVendorArch = if ($Architecture -eq "x86_64") { "amd64" } else { "arm64" }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$SirinZip = [System.IO.Compression.ZipFile]::OpenRead($SirinArchive)
try {
    $SirinEntry = $SirinZip.GetEntry("wireguard-nt/bin/$SirinVendorArch/wireguard.dll")
    if ($null -eq $SirinEntry) { throw "WireGuardNT does not contain the selected Windows architecture." }
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($SirinEntry, (Join-Path $SirinWindows "wireguard.dll"), $true)
} finally { $SirinZip.Dispose() }
if ((Get-FileHash -Algorithm SHA256 (Join-Path $SirinWindows "wireguard.dll")).Hash.ToLowerInvariant() -ne $SirinVendor.dll_sha256.$SirinVendorArch) {
    throw "The WireGuardNT DLL does not match the pinned SHA-256."
}

$SirinPreviousJobs = $env:CARGO_BUILD_JOBS
$SirinPreviousRustFlags = $env:RUSTFLAGS
$env:RUSTFLAGS = "$SirinPreviousRustFlags -C target-feature=+crt-static".Trim()
if (-not $SirinPreviousJobs) { $env:CARGO_BUILD_JOBS = "2" }
Push-Location $SirinRoot
try {
    Invoke-SirinCommand "rustup" @("target", "add", $SirinTarget)
    Invoke-SirinCommand "cargo" @("build", "--locked", "--release", "--target", $SirinTarget, "-p", "sirinvpn-windows-service", "-p", "sirinvpn-cli")
    foreach ($SirinName in @("sirinvpn-windows-service.exe", "sirinvpn.exe")) {
        Copy-Item -LiteralPath (Join-Path $SirinRoot "target/$SirinTarget/release/$SirinName") -Destination $SirinWindows -Force
    }
    Push-Location (Join-Path $SirinRoot "apps/desktop")
    try {
        Invoke-SirinCommand "pnpm" @("install", "--frozen-lockfile")
        Invoke-SirinCommand "pnpm" @("exec", "tauri", "build", "--target", $SirinTarget, "--bundles", "nsis")
    } finally { Pop-Location }
} finally {
    Pop-Location
    $env:CARGO_BUILD_JOBS = $SirinPreviousJobs
    $env:RUSTFLAGS = $SirinPreviousRustFlags
}
Write-Output "Unsigned Windows packages: target/$SirinTarget/release/bundle/nsis"
Write-Output "Publish only after platform acceptance and release/AuthentiCode signing."
