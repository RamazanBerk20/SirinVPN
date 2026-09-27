param([Parameter(Mandatory=$true)][string]$FixtureId)
$ErrorActionPreference='Stop'
$shared='\\host.lan\Data'
$report=@{started=[DateTime]::UtcNow.ToString('o');passed=$false;checks=@();os=(Get-CimInstance Win32_OperatingSystem).Caption;build=[Environment]::OSVersion.Version.ToString()}
function Run-Checked([string]$exe,[string[]]$arguments,[bool]$success=$true){
 $info=New-Object System.Diagnostics.ProcessStartInfo
 $info.FileName=$exe;$info.Arguments=($arguments | ForEach-Object{'"'+$_+'"'}) -join ' ';$info.UseShellExecute=$false
 $process=New-Object System.Diagnostics.Process;$process.StartInfo=$info
 [void]$process.Start()
 if(-not $process.WaitForExit(180000)){$process.Kill();throw 'Native operation timed out'}
 $code=$process.ExitCode;$process.Dispose()
 if(($success -and $code -ne 0) -or (-not $success -and $code -eq 0)){throw "Unexpected native operation exit: $code"}
}
Start-Transcript -Path "C:\SirinAcceptance\native-runtime-setup.log" -Force
$installed=$false;$prepared=$false;$helper=$null;$connected=$false;$imported=$false;$account=$null;$peerDirectory=$null
try{
 $marker=Get-Content -Raw 'C:\ProgramData\SirinVpnAcceptance\fixture.json' | ConvertFrom-Json
 if($marker.kind -ne 'disposable_vm' -or $marker.id -ne $FixtureId){throw 'Wrong fixture'}
 $machine=Get-CimInstance Win32_ComputerSystem
 if(($machine.Manufacturer+' '+$machine.Model) -notmatch 'QEMU|KVM|Virtual'){throw 'Disposable virtual machine required'}
 $directory='C:\Program Files\SirinVPN'
 $meta=Get-Content -Raw "$shared\vps-fixture.json" | ConvertFrom-Json
 foreach($name in @('SirinVPN','SirinVPNAppRouting')){if(Get-Service $name -ErrorAction SilentlyContinue){throw 'Refusing existing service'}}
 if(Test-Path $directory){throw 'Refusing existing installation'}
 if(Test-Path 'C:\ProgramData\SirinVPN'){
  $prior=Get-Content -Raw "$shared\initial-native-runtime-result.json" | ConvertFrom-Json
  if(-not $prior.cleanup_complete -or $prior.vps_fixture -ne $meta.fixture){throw 'Refusing unrelated prior state'}
  if(@(Get-ChildItem 'C:\ProgramData\SirinVPN' -File -Force -Recurse).Count -ne 0){throw 'Prior fixture state is not empty'}
  Remove-Item -LiteralPath 'C:\ProgramData\SirinVPN' -Recurse
 }
 $built=Get-Content -Raw "$shared\native-complete-checks.json" | ConvertFrom-Json
 if(-not $built.passed){throw 'Native build not qualified'}
 $report.source=$built.source;$report.artifacts=$built.artifacts
 $meta=Get-Content -Raw "$shared\vps-fixture.json" | ConvertFrom-Json
 if($meta.kind -ne 'disposable_vm' -or $meta.host -ne '172.17.0.1'){throw 'Unexpected VPS fixture'}
 $report.vps_fixture=$meta.fixture
 $clock=Get-Content -Raw "$shared\fixture-clock.json" | ConvertFrom-Json
 $report.started_before_clock_correction=$report.started
 Set-Date -Date ([DateTimeOffset]::Parse($clock.utc).LocalDateTime) | Out-Null
 $report.started=[DateTime]::UtcNow.ToString('o')
 if((Get-FileHash -Algorithm SHA256 "$shared\fixture-export.sirin").Hash.ToLowerInvariant() -ne $meta.profile_export_sha256){throw 'Fixture export digest mismatch'}
 Copy-Item "$shared\fixture-export.sirin" 'C:\SirinAcceptance\fixture-export.sirin'
 function Invoke-Json([string[]]$arguments){
  $ErrorActionPreference='Continue'
  $output=& "$directory\sirinvpn.exe" --json @arguments 2>&1
  $code=$LASTEXITCODE;$ErrorActionPreference='Stop'
  if($code -ne 0){throw "CLI operation failed: $($arguments[0]) ($code): $($output -join ' ' )"}
  return (($output -join "`n") | ConvertFrom-Json)
 }
 function Probe-Underlay {
  $request=[System.Net.HttpWebRequest]::Create("http://172.17.0.1:$($meta.canary_port)/")
  $request.Proxy=$null;$request.Timeout=3000;$request.ReadWriteTimeout=3000;$request.KeepAlive=$false
  try{$response=$request.GetResponse();$reader=New-Object IO.StreamReader($response.GetResponseStream());try{$value=$reader.ReadToEnd() | ConvertFrom-Json;return ($value.nonce -eq $meta.canary_nonce)}finally{$reader.Dispose();$response.Dispose()}}catch{return $false}
 }
 foreach($artifact in $built.artifacts){if((Get-FileHash -Algorithm SHA256 "$shared\$($artifact.name)").Hash.ToLowerInvariant() -ne $artifact.sha256){throw 'Executable digest mismatch'}}
 $sentinel=(Get-Service Dnscache).Status.ToString()
 $helper='C:\Program Files\SirinAcceptance-helper-'+[Guid]::NewGuid().ToString('N')+'.exe'
 Copy-Item "$shared\sirinvpn-windows-service.exe" $helper
 Run-Checked $helper @('--prepare-install',$directory)
 $prepared=$true
 foreach($name in @('sirinvpn.exe','sirinvpn-windows-service.exe','sirinvpn-app-routing.sys','wireguard.dll')){Copy-Item "$shared\$name" "$directory\$name"}
 $report.checks+=@{name='Protected installation preparation';passed=$true}
 $service="$directory\sirinvpn-windows-service.exe"
 $dll="$directory\wireguard.dll";$original=[IO.File]::ReadAllBytes($dll);$tampered=[byte[]]$original.Clone();$tampered[$tampered.Length-1]=$tampered[$tampered.Length-1] -bxor 1
 [IO.File]::WriteAllBytes($dll,$tampered)
 try{Run-Checked $service @('--install-service') $false; if(Get-Service SirinVPN -ErrorAction SilentlyContinue){throw 'Tampered DLL installed a service'}}finally{[IO.File]::WriteAllBytes($dll,$original)}
 $report.checks+=@{name='Tampered WireGuardNT refused before service creation';passed=$true}
 Run-Checked $service @('--install-service');$installed=$true
 if((Get-Service SirinVPN).Status -ne 'Running'){throw 'Service did not start'}
 $status=& "$directory\sirinvpn.exe" --json status
 if($LASTEXITCODE -ne 0){throw 'CLI status failed'}
 $state=$status | ConvertFrom-Json
 $report.status=$state.local
 if($state.local.state -ne 'disconnected' -or $null -ne $state.local.server_id -or $state.local.kill_switch_enabled){throw 'Unexpected idle state'}
 $report.checks+=@{name='Native service starts and CLI observes disconnected state';passed=$true}
 # Link the already-built actual platform library into a small guarded fixture probe.
 $env:RUSTUP_HOME='C:\SirinAcceptance\rustup';$env:CARGO_HOME='C:\SirinAcceptance\cargo'
 $library=Get-ChildItem 'C:\SirinAcceptance\target\debug\deps\libsirinvpn_platform-*.rlib' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
 if(-not $library){throw 'Native platform library unavailable'}
 Copy-Item "$PSScriptRoot\dpapi-probe.rs" 'C:\SirinAcceptance\dpapi-probe.rs'
 $ErrorActionPreference='Continue'
 & 'C:\SirinAcceptance\cargo\bin\rustc.exe' +1.97.1 --edition=2024 'C:\SirinAcceptance\dpapi-probe.rs' -L 'dependency=C:\SirinAcceptance\target\debug\deps' --extern "sirinvpn_platform=$($library.FullName)" -o "$directory\acceptance-dpapi.exe"
 $code=$LASTEXITCODE;$ErrorActionPreference='Stop'
 if($code -ne 0){throw 'Native DPAPI fixture probe compilation failed'}
 Copy-Item "$PSScriptRoot\pipe-probe.rs" 'C:\SirinAcceptance\pipe-probe.rs'
 $probeCompiled=$false
 foreach($windowsLibrary in (Get-ChildItem 'C:\SirinAcceptance\target\debug\deps\libwindows_sys-*.rlib' | Sort-Object LastWriteTime -Descending)){
  $ErrorActionPreference='Continue'
  & 'C:\SirinAcceptance\cargo\bin\rustc.exe' +1.97.1 --edition=2024 'C:\SirinAcceptance\pipe-probe.rs' -L 'dependency=C:\SirinAcceptance\target\debug\deps' --extern "sirinvpn_platform=$($library.FullName)" --extern "windows_sys=$($windowsLibrary.FullName)" -o "$directory\acceptance-pipe.exe"
  $code=$LASTEXITCODE;$ErrorActionPreference='Stop'
  if($code -eq 0){$probeCompiled=$true;break}
 }
 if(-not $probeCompiled){throw 'Pipe boundary probe failed to compile'}
 $report.dpapi_probe=@{source_sha256=(Get-FileHash 'C:\SirinAcceptance\dpapi-probe.rs' -Algorithm SHA256).Hash.ToLowerInvariant();platform_rlib_sha256=(Get-FileHash $library.FullName -Algorithm SHA256).Hash.ToLowerInvariant();exe_sha256=(Get-FileHash "$directory\acceptance-dpapi.exe" -Algorithm SHA256).Hash.ToLowerInvariant()}
 $peerName='SirinAcc'+[Guid]::NewGuid().ToString('N').Substring(0,8)
 $peerPassword=ConvertTo-SecureString ('Qa8!'+[Guid]::NewGuid().ToString('N')) -AsPlainText -Force
 $account=New-LocalUser -Name $peerName -Password $peerPassword -Description 'Disposable SirinVPN acceptance only' -AccountNeverExpires
 $group=Get-LocalGroup -SID 'S-1-5-32-545'
 if(-not ((Get-LocalGroupMember -Group $group).SID.Value -contains $account.SID.Value)){Add-LocalGroupMember -Group $group -Member $account}
 $peerDirectory=Join-Path 'C:\Users\Public' $peerName
 New-Item -ItemType Directory -Path $peerDirectory | Out-Null
 & icacls.exe $peerDirectory /grant ("*$($account.SID.Value):(OI)(CI)M") | Out-Null
 if($LASTEXITCODE -ne 0){throw 'Fixture account directory ACL failed'}
 Run-Checked "$directory\acceptance-dpapi.exe" @('create-user',"$peerDirectory\user.bin")
 Run-Checked "$directory\acceptance-dpapi.exe" @('create-machine',"$peerDirectory\machine.bin")
 Run-Checked "$directory\acceptance-dpapi.exe" @('read-user',"$peerDirectory\user.bin")
 $cipherHash=(Get-FileHash "$peerDirectory\user.bin" -Algorithm SHA256).Hash
 Copy-Item "$PSScriptRoot\peer.ps1" "$peerDirectory\peer.ps1"
 function Run-Peer([string]$phase){
  $info=New-Object System.Diagnostics.ProcessStartInfo
  $info.FileName='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
  $info.Arguments="-NoProfile -ExecutionPolicy Bypass -File `"$peerDirectory\peer.ps1`" -Phase $phase"
  $info.UserName=$account.Name;$info.Domain=$env:COMPUTERNAME;$info.Password=$peerPassword;$info.LoadUserProfile=$true;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
  $process=New-Object System.Diagnostics.Process;$process.StartInfo=$info
  [void]$process.Start()
  if(-not $process.WaitForExit(90000)){$process.Kill();throw 'Fixture peer timeout'}
  $code=$process.ExitCode;$process.Dispose()
  $peer=Get-Content -Raw "$peerDirectory\$phase.json" | ConvertFrom-Json
  $report["peer_$phase"]=$peer
  if($code -ne 0 -or -not $peer.passed -or $peer.sid -ne $account.SID.Value){throw "Fixture peer failed: $phase ($code): $($peer.error)"}
  if((Get-FileHash "$peerDirectory\user.bin" -Algorithm SHA256).Hash -ne $cipherHash){throw 'User-scope control ciphertext changed'}
 }
 Run-Peer 'idle'
 $report.checks+=@{name='Other account: user DPAPI denied, machine DPAPI control succeeds, idle pipe status succeeds';passed=$true}

 # Change only the registered account while the original SYSTEM process remains
 # running: authentication must reject it before sending the status request.
 $originalPid=(Get-CimInstance Win32_Service -Filter "Name='SirinVPN'").ProcessId
 try {
  & sc.exe config SirinVPN obj= 'NT AUTHORITY\LocalService' | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Fixture service account change failed'}
  $ErrorActionPreference='Continue'
  $denied=& "$directory\sirinvpn.exe" --json status 2>&1
  $code=$LASTEXITCODE;$ErrorActionPreference='Stop'
  if($code -eq 0 -or ($denied -join "`n") -notmatch 'could not be authenticated'){throw 'Changed service account was not rejected'}
  if((Get-CimInstance Win32_Service -Filter "Name='SirinVPN'").ProcessId -ne $originalPid){throw 'Service changed during identity negative control'}
 }finally{
  & sc.exe config SirinVPN obj= LocalSystem | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Fixture service account restoration failed'}
 }
 Run-Peer 'idle'
 $report.checks+=@{name='Mismatched SCM account rejected with unchanged SYSTEM pipe and PID; restored identity accepted';passed=$true}

 Run-Checked $service @('--stop-service')
 if((Get-Service SirinVPN).Status -ne 'Stopped'){throw 'Service failed to stop'}
 Run-Checked $service @('--install-service')
 if((Get-Service SirinVPN).Status -ne 'Running'){throw 'Service failed to restart'}
 $report.checks+=@{name='Idle service stop/reinstall';passed=$true}
 $report.driver=@{status=(Get-Service SirinVPNAppRouting).Status.ToString();signature=(Get-AuthenticodeSignature "$directory\sirinvpn-app-routing.sys").Status.ToString()}
 if((Get-Service Dnscache).Status.ToString() -ne $sentinel){throw 'Unrelated DNS service changed'}
 $report.checks+=@{name='Unrelated DNS service preserved';passed=$true}
 if(@(Invoke-Json @('server','list')).Count -ne 0){throw 'Refusing an existing Windows profile'}
 if(-not (Probe-Underlay)){throw 'Controlled underlay baseline unavailable'}
 $report.checks+=@{name='Ordinary application underlay positive control';passed=$true}
 @{stage='awaiting-fixture-backup-password';fixture=$meta.fixture} | ConvertTo-Json | Set-Content -Encoding UTF8 "$shared\native-runtime-stage.json"
 Run-Checked "$directory\sirinvpn.exe" @('--json','server','import','--input','C:\SirinAcceptance\fixture-export.sirin')
 $imported=$true
 $profiles=@(Invoke-Json @('server','list'))
 if($profiles.Count -ne 1 -or $profiles[0].id -ne $meta.server_id){throw 'Imported profile identity mismatch'}
 $report.checks+=@{name='Encrypted fixture backup imports into native Windows storage';passed=$true}
 $report.transports=@()
 foreach($transport in @('direct','obfuscated','tls','tcp')){
  $connected=$true
  $null=Invoke-Json @('connect',$meta.server_id,'--transport',$transport,'--kill-switch')
  $deadline=[DateTime]::UtcNow.AddSeconds(80)
  do{$local=(Invoke-Json @('status')).local;if($local.state -eq 'connected'){break};Start-Sleep -Milliseconds 500}while([DateTime]::UtcNow -lt $deadline)
  if($local.state -ne 'connected' -or $local.kill_switch_state -ne 'armed'){throw "Transport not connected/protected: $transport"}
  $ping=& ping.exe -n 3 -w 3000 10.77.0.1
  if($LASTEXITCODE -ne 0 -or [regex]::Matches(($ping -join "`n"),'TTL=').Count -ne 3){throw 'Private tunnel ping failed'}
  Clear-DnsClientCache
  $answer=Resolve-DnsName windows-fixture.test -DnsOnly -ErrorAction Stop
  if(-not (@($answer | Where-Object {$_.IPAddress -eq '10.77.0.1'}).Count)){throw 'Private DNS record did not resolve'}
  if(Probe-Underlay){throw 'Ordinary application escaped the protected endpoint route'}
  if($transport -eq 'direct'){
   $epoch=$local.counter_epoch
   Run-Peer 'owned'
   $after=(Invoke-Json @('status')).local
   if($after.state -ne 'connected' -or $after.server_id -ne $meta.server_id -or $after.counter_epoch -ne $epoch){throw 'Other account changed the active owner session'}
   $report.checks+=@{name='Other account cannot read or disconnect the owner session; original session survives';passed=$true}
  }

  $report.transports+=@{requested=$transport;actual=$local.transport;connected=$true;private_ping=$true;private_dns=$true;underlay_blocked=$true;kill_switch=$local.kill_switch_state;application_routing_supported=$local.application_routing_supported}
  $null=Invoke-Json @('disconnect');$connected=$false
  if(-not (Probe-Underlay)){throw 'Disconnect failed to restore underlay'}
 }
 $report.checks+=@{name='Four native transports, private DNS, guarded underlay and disconnect restoration';passed=$true}
 $connected=$true
 $null=Invoke-Json @('connect',$meta.server_id,'--transport','direct','--kill-switch','--automatic-reconnect')
 $before=(Invoke-Json @('status')).local
 if($before.state -ne 'connected'){throw 'Crash fixture not connected'}
 # A guarded stop retains persistent WFP protection while removing service-owned networking.
 Run-Checked $service @('--stop-service')
 for($i=0;$i -lt 3;$i++){if(Probe-Underlay){throw 'Underlay escaped while VPN service was stopped'}}
 $report.checks+=@{name='Persistent WFP blocks three ordinary-app probes while service stopped';passed=$true}
 Run-Checked $service @('--install-service')
 $deadline=[DateTime]::UtcNow.AddSeconds(90)
 do{$local=(Invoke-Json @('status')).local;if($local.state -eq 'connected'){break};Start-Sleep -Milliseconds 500}while([DateTime]::UtcNow -lt $deadline)
 if($local.state -ne 'connected'){throw 'Native session did not recover after service restart'}
 $null=Invoke-Json @('disconnect');$connected=$false
 if(-not (Probe-Underlay)){throw 'Final disconnect failed to restore underlay'}
 $report.checks+=@{name='Service restart reconstructs intent and final Disconnect restores underlay';passed=$true}
 Run-Checked "$directory\sirinvpn.exe" @('server','remove',$meta.server_id);$imported=$false
 if(@(Invoke-Json @('server','list')).Count -ne 0){throw 'Fixture profile remains'}
 $report.checks+=@{name='Native profile/credential removal acknowledged and profile absent';passed=$true}
 if((Get-Service Dnscache).Status.ToString() -ne $sentinel){throw 'Unrelated DNS service changed'}
 $report.passed=$true
}catch{$report.error=$_.Exception.Message;Write-Output $_}
finally{
 try{
  if($connected){Run-Checked "$directory\sirinvpn-windows-service.exe" @('--install-service');$null=Invoke-Json @('disconnect');$connected=$false}
  if($imported){Run-Checked "$directory\sirinvpn.exe" @('server','remove',$meta.server_id);$imported=$false}
  if(Test-Path 'C:\SirinAcceptance\fixture-export.sirin'){Remove-Item -LiteralPath 'C:\SirinAcceptance\fixture-export.sirin'}
  if($prepared){Run-Checked $helper @('--uninstall-from','C:\Program Files\SirinVPN');if((Get-Service SirinVPN -ErrorAction SilentlyContinue) -or (Get-Service SirinVPNAppRouting -ErrorAction SilentlyContinue)){throw 'Owned services remain'};Remove-Item -LiteralPath 'C:\Program Files\SirinVPN' -Recurse; $report.checks+=@{name='Native uninstall removes both owned SCM registrations';passed=$true}}
  if($helper -and (Test-Path $helper)){Remove-Item -LiteralPath $helper}

  if($account){
   $peerProfile=Get-CimInstance Win32_UserProfile -Filter ("SID='"+$account.SID.Value+"'")
   if($peerProfile -and -not $peerProfile.Loaded){$peerProfile | Remove-CimInstance}
   Remove-LocalUser -SID $account.SID
   if(Get-LocalUser -SID $account.SID -ErrorAction SilentlyContinue){throw 'Fixture account remains'}
  }
  if($peerDirectory -and (Test-Path $peerDirectory)){Remove-Item -LiteralPath $peerDirectory -Recurse}
  $report.cleanup_complete=$true
 }catch{$report.cleanup_complete=$false;$report.passed=$false;$report.cleanup_error=$_.Exception.Message}
 $report.ended=[DateTime]::UtcNow.ToString('o')
 $report | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 "$shared\native-runtime-result.json"
 Stop-Transcript
 Copy-Item -LiteralPath "C:\SirinAcceptance\native-runtime-setup.log" -Destination "$shared\native-runtime-setup.log"
}

if(-not $report.passed){exit 1}
