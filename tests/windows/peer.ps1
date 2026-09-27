param([ValidateSet('idle','owned')][string]$Phase)
$ErrorActionPreference='Stop'
$report=@{passed=$false;sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
try {
 $probe='C:\Program Files\SirinVPN\acceptance-dpapi.exe'
 & $probe read-user "$PSScriptRoot\user.bin"
 $report.user_exit_code=$LASTEXITCODE
 if($LASTEXITCODE -ne 42){throw 'Other account unexpectedly decrypted the user-scope fixture'}
 & $probe read-machine "$PSScriptRoot\machine.bin"
 $report.machine_exit_code=$LASTEXITCODE
 if($LASTEXITCODE -ne 0){throw 'Machine-scope readable control failed'}
 $ErrorActionPreference='Continue'
 $report.pipe_probe=((& 'C:\Program Files\SirinVPN\acceptance-pipe.exe' 2>&1) -join "`n")
 $report.pipe_probe_exit_code=$LASTEXITCODE
 if($LASTEXITCODE -ne 0){throw 'Pipe identity or spoofing negative control failed'}
 $status=& 'C:\Program Files\SirinVPN\sirinvpn.exe' --json status 2>&1
 $code=$LASTEXITCODE;$ErrorActionPreference='Stop'
 $report.status_exit_code=$code;$report.status_text=($status -join "`n")
 if($Phase -eq 'idle'){
  if($code -ne 0 -or (($status -join "`n") | ConvertFrom-Json).local.state -ne 'disconnected'){throw 'Idle pipe positive control failed'}
 }else{
  if($code -eq 0 -or ($status -join "`n") -notmatch 'Another Windows user controls'){throw 'Cross-user status did not report ownership denial'}
  $ErrorActionPreference='Continue'
  $disconnect=& 'C:\Program Files\SirinVPN\sirinvpn.exe' --json disconnect 2>&1
  $code=$LASTEXITCODE;$ErrorActionPreference='Stop'
  if($code -eq 0 -or ($disconnect -join "`n") -notmatch 'Another Windows user controls'){throw 'Cross-user Disconnect did not report ownership denial'}
 }
 $report.passed=$true
}catch{$report.error=$_.Exception.Message;$report.detail=$_.ToString()}
$report | ConvertTo-Json | Set-Content -Encoding UTF8 "$PSScriptRoot\$Phase.json"
if(-not $report.passed){exit 1}
