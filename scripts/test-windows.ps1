param(
    [switch]$DisposableRuntime,
    [string]$InstalledDirectory,
    [string]$FixtureId
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") { throw "Native Windows is required; cross compilation does not qualify." }
$env:CARGO_BUILD_JOBS = "2"
$env:RUST_TEST_THREADS = "2"
function Invoke-SirinCheck([string]$Program, [string[]]$Arguments) {
    # A pipeline also waits for the GUI-subsystem service executable, so its
    # exit code cannot be confused with that of the previous native command.
    & $Program @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}
# Git for Windows' MSYS Perl is incomplete for the vendored MSVC OpenSSL build.
# Use native Windows Perl (for example Strawberry Perl), including these modules.
Invoke-SirinCheck "perl" @("-MIPC::Cmd", "-MLocale::Maketext::Simple", "-e", 'exit($^O eq q(MSWin32) ? 0 : 1)')
Invoke-SirinCheck "cargo" @("test", "--locked", "-p", "sirinvpn-platform", "-p", "sirinvpn-protocol", "-p", "sirinvpn-core", "-p", "sirinvpn-release", "-p", "sirinvpn-tunnel-model", "-p", "sirinvpn-windows-service")
Invoke-SirinCheck "cargo" @("check", "--locked", "-p", "sirinvpn-cli")
if (-not $DisposableRuntime) {
    Write-Output "Native unit/build checks completed. Privileged service/packet acceptance was NOT RUN."
    exit 0
}

# Create the marker only while preparing a NEW disposable Windows VM. This
# opt-in never turns an ordinary workstation or a CI host into a test fixture.
$SirinMarker = "C:\ProgramData\SirinVpnAcceptance\fixture.json"
$SirinMachine = Get-CimInstance Win32_ComputerSystem
if (($SirinMachine.Manufacturer + " " + $SirinMachine.Model) -notmatch "Virtual|KVM|QEMU|VMware|HVM") { throw "A disposable VM is required." }
$SirinFixture = Get-Content -Raw -LiteralPath $SirinMarker | ConvertFrom-Json
if ($SirinFixture.kind -ne "disposable_vm" -or $SirinFixture.id -ne $FixtureId -or -not $FixtureId) {
    throw "Fixture identity mismatch."
}
$SirinServiceExe = Join-Path (Resolve-Path -LiteralPath $InstalledDirectory).Path "sirinvpn-windows-service.exe"
$SirinCli = Join-Path (Resolve-Path -LiteralPath $InstalledDirectory).Path "sirinvpn.exe"
$SirinSentinel = Get-Service Dnscache
$SirinSentinelState = $SirinSentinel.Status
$SirinStatus = & $SirinCli --json status
if ($LASTEXITCODE -ne 0) { throw "Native status unavailable." }
$SirinState = ($SirinStatus | ConvertFrom-Json).local
if ($SirinState.state -ne "disconnected" -or $null -ne $SirinState.server_id -or $SirinState.kill_switch_enabled) {
    throw "Only a clean, disconnected fixture may run idle service acceptance."
}
try {
    Invoke-SirinCheck $SirinServiceExe @("--stop-service")
} finally {
    Invoke-SirinCheck $SirinServiceExe @("--install-service")
}
Invoke-SirinCheck $SirinCli @("status")
if ((Get-Service Dnscache).Status -ne $SirinSentinelState) { throw "Unrelated DNS service changed." }
Write-Output "Idle service stop/reinstall/status passed. Packet enforcement, cross-user requests, crash/reboot, signed driver, update and uninstall acceptance remain NOT RUN."
