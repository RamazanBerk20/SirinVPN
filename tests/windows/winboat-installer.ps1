param([Parameter(Mandatory=$true)][string]$FixtureId)
$ErrorActionPreference='Stop'
$shared='\\host.lan\Data'
$report=@{passed=$false;started=[DateTime]::UtcNow.ToString('o');checks=@()}
$desktop=$null;$installed=$false
function Run-Installer([string]$path,[string[]]$arguments){
 $process=Start-Process -FilePath $path -ArgumentList $arguments -PassThru
 try{if(-not $process.WaitForExit(180000)){$process.Kill();throw 'Installer timeout'};if($process.ExitCode -ne 0){throw "Installer failed: $($process.ExitCode)"}}finally{$process.Dispose()}
}
try{
 $marker=Get-Content -Raw 'C:\ProgramData\SirinVpnAcceptance\fixture.json' | ConvertFrom-Json
 if($marker.kind -ne 'disposable_vm' -or $marker.id -ne $FixtureId){throw 'Wrong fixture'}
 $machine=Get-CimInstance Win32_ComputerSystem
 if(($machine.Manufacturer+' '+$machine.Model) -notmatch 'QEMU|KVM|Virtual'){throw 'Disposable VM required'}
 $dir='C:\Program Files\SirinVPN'
 if((Test-Path $dir) -or (Get-Service SirinVPN -ErrorAction SilentlyContinue) -or (Get-Service SirinVPNAppRouting -ErrorAction SilentlyContinue)){throw 'Refusing existing installation'}
 $built=Get-Content -Raw "$shared\native-package-result.json" | ConvertFrom-Json
 if(-not $built.passed -or $built.artifacts.Count -ne 1){throw 'Native package not qualified'}
 $report.source=$built.source;$report.artifacts=$built.artifacts
 $artifact=$built.artifacts[0]
 if((Split-Path -Leaf $artifact.name) -ne $artifact.name){throw 'Unsafe artifact name'}
 $package=Join-Path 'C:\SirinAcceptance' $artifact.name
 Copy-Item -LiteralPath (Join-Path $shared $artifact.name) -Destination $package
 if((Get-FileHash $package -Algorithm SHA256).Hash.ToLowerInvariant() -ne $artifact.sha256){throw 'Installer digest mismatch'}
 $sentinel=(Get-Service Dnscache).Status.ToString()
 $installed=$true
 Run-Installer $package @('/S')
 if((Get-Service SirinVPN).Status -ne 'Running'){throw 'Installed service not running'}
 $state=& "$dir\sirinvpn.exe" --json status
 if($LASTEXITCODE -ne 0 -or ($state | ConvertFrom-Json).local.state -ne 'disconnected'){throw 'Installed CLI idle state unavailable'}
 $report.checks+=@{name='Exact native NSIS silently installs and starts authenticated idle service';passed=$true}
 $report.payloads=@()
 foreach($name in @('sirinvpn-desktop.exe','sirinvpn.exe','sirinvpn-windows-service.exe','wireguard.dll','sirinvpn-app-routing.sys')){
  $file=Join-Path $dir $name
  $report.payloads+=@{name=$name;sha256=(Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant();bytes=(Get-Item $file).Length}
 }
 $desktop=Start-Process -FilePath "$dir\sirinvpn-desktop.exe" -PassThru
 Start-Sleep -Seconds 15
 $desktop.Refresh()
 if($desktop.HasExited -or $desktop.MainWindowHandle -eq 0){throw 'Native desktop did not create a window'}
 $report.checks+=@{name='Installed Windows desktop creates a live window';passed=$true}
 @{stage='native-desktop-ready';pid=$desktop.Id} | ConvertTo-Json | Set-Content -Encoding UTF8 "$shared\native-installer-stage.json"
 Start-Sleep -Seconds 30
 [void]$desktop.CloseMainWindow();Start-Sleep -Seconds 2
 if((Get-Service SirinVPN).Status -ne 'Running'){throw 'Closing desktop stopped the service'}
 if(-not $desktop.HasExited){$desktop.Kill();$desktop.WaitForExit()}
 $report.checks+=@{name='Desktop close preserves idle networking service';passed=$true}
 Run-Installer $package @('/S')
 $state=& "$dir\sirinvpn.exe" --json status
 if($LASTEXITCODE -ne 0 -or ($state | ConvertFrom-Json).local.state -ne 'disconnected'){throw 'Same-version repair failed'}
 $report.checks+=@{name='Same-version native NSIS repair preserves authenticated idle state';passed=$true}
 Run-Installer "$dir\uninstall.exe" @('/S')
 $installed=$false
 [GC]::Collect();[GC]::WaitForPendingFinalizers();Start-Sleep -Seconds 2
 foreach($name in @('SirinVPN','SirinVPNAppRouting')){
  $output=& sc.exe query $name
  if($LASTEXITCODE -ne 1060){throw "Uninstall left service: $name"}
 }
 foreach($name in @('sirinvpn-desktop.exe','sirinvpn.exe','sirinvpn-windows-service.exe','wireguard.dll','sirinvpn-app-routing.sys')){if(Test-Path (Join-Path $dir $name)){throw 'Uninstall left installed executable'}}
 if((Get-Service Dnscache).Status.ToString() -ne $sentinel){throw 'Unrelated DNS service changed'}
 $report.checks+=@{name='Native NSIS uninstall removes service registrations and installed binaries; DNS service preserved';passed=$true}
 $report.passed=$true;$report.cleanup_complete=$true
}catch{$report.error=$_.Exception.Message}
finally{
 try{
  if($desktop -and -not $desktop.HasExited){$desktop.Kill();$desktop.WaitForExit()}
  if($installed -and (Test-Path "$dir\uninstall.exe")){
   Run-Installer "$dir\uninstall.exe" @('/S')
   if((Get-Service SirinVPN -ErrorAction SilentlyContinue) -or (Get-Service SirinVPNAppRouting -ErrorAction SilentlyContinue)){throw 'Cleanup left an owned service'}
   if(Test-Path "$dir\sirinvpn-desktop.exe"){throw 'Cleanup left installed desktop'}
   $report.cleanup_complete=$true
  }
 }catch{$report.cleanup_error=$_.Exception.Message;$report.cleanup_complete=$false;$report.passed=$false}
 $report.ended=[DateTime]::UtcNow.ToString('o');$report | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 "$shared\native-installer-result.json"
}
if(-not $report.passed){exit 1}
