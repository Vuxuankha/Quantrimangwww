param(
    [string]$ConfigPath = "$PSScriptRoot\config.json"
)

$ErrorActionPreference = 'SilentlyContinue'
$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$since = (Get-Date).AddHours(-[int]$config.HoursBack)
$reportDir = [Environment]::ExpandEnvironmentVariables([string]$config.ReportDirectory)
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$jsonPath = Join-Path $reportDir "daily_audit_$stamp.json"
$htmlPath = Join-Path $reportDir "daily_audit_$stamp.html"

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding($Category,$Severity,$Item,$Details) {
    $findings.Add([pscustomobject]@{
        Time = (Get-Date).ToString('s')
        Category = $Category
        Severity = $Severity
        Item = $Item
        Details = $Details
    })
}

# 1) System / Security / Application logs
foreach ($id in $config.EventIds) {
    $logs = if ($id -in 4624,4625,4672) { @('Security') } else { @('System','Application') }
    foreach ($log in $logs) {
        $events = Get-WinEvent -FilterHashtable @{LogName=$log; Id=[int]$id; StartTime=$since} -MaxEvents 200
        if ($events) {
            $sev = if ($id -in 41,6008,4625) { 'WARN' } else { 'INFO' }
            Add-Finding 'EventLog' $sev "Event ID $id ($log)" ("Count={0}; Latest={1}" -f @($events).Count, $events[0].TimeCreated)
        }
    }
}

$failed = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$since} -MaxEvents 1000
if (@($failed).Count -ge [int]$config.FailedLoginWarnCount) {
    Add-Finding 'Security' 'HIGH' 'Failed logons' ("{0} failed logons in last {1}h" -f @($failed).Count, $config.HoursBack)
}

# 2) CPU / memory / disks
$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$os = Get-CimInstance Win32_OperatingSystem
$memUsedPct = [math]::Round((1 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize))*100,1)
Add-Finding 'Resource' ($(if($cpu -ge $config.CpuWarnPercent){'WARN'}else{'INFO'})) 'CPU' "$cpu%"
Add-Finding 'Resource' ($(if($memUsedPct -ge $config.MemoryWarnPercent){'WARN'}else{'INFO'})) 'Memory' "$memUsedPct% used"
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
    if ($_.Size -gt 0) {
        $freePct=[math]::Round(($_.FreeSpace/$_.Size)*100,1)
        Add-Finding 'Resource' ($(if($freePct -lt $config.DiskFreeWarnPercent){'WARN'}else{'INFO'})) "Disk $($_.DeviceID)" "$freePct% free"
    }
}

# 3) Services
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' } | ForEach-Object {
    Add-Finding 'Service' 'WARN' $_.Name ("Automatic service is {0}" -f $_.State)
}

# 4) Firewall / network / listening ports
Get-NetFirewallProfile | ForEach-Object {
    Add-Finding 'Firewall' ($(if($_.Enabled){'INFO'}else{'WARN'})) $_.Name ("Enabled={0}; DefaultInbound={1}; DefaultOutbound={2}" -f $_.Enabled,$_.DefaultInboundAction,$_.DefaultOutboundAction)
}
$listen = Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
$expected = @($config.ExpectedListeningPorts | ForEach-Object {[int]$_})
$listen | Group-Object LocalPort | Sort-Object Name | ForEach-Object {
    $p=[int]$_.Name
    $sev = if ($expected.Count -gt 0 -and $p -notin $expected) {'REVIEW'} else {'INFO'}
    Add-Finding 'Network' $sev "Listening TCP $p" ("Bindings={0}" -f $_.Count)
}

# 5) Microsoft Defender (when present)
if ($config.CheckDefender) {
    $mp = Get-MpComputerStatus
    if ($mp) {
        Add-Finding 'Defender' ($(if($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled){'INFO'}else{'WARN'})) 'Protection status' ("AV={0}; RTP={1}; SigAge={2}d" -f $mp.AntivirusEnabled,$mp.RealTimeProtectionEnabled,$mp.AntivirusSignatureAge)
        Get-MpThreatDetection | Where-Object {$_.InitialDetectionTime -ge $since} | ForEach-Object {
            Add-Finding 'Defender' 'HIGH' $_.ThreatName ("Detected={0}; ActionSuccess={1}" -f $_.InitialDetectionTime,$_.ActionSuccess)
        }
    }
}

# 6) Local administrators / RDP
try {
    Get-LocalGroupMember -Group 'Administrators' | ForEach-Object {
        Add-Finding 'Account' 'REVIEW' 'Local Administrators' $_.Name
    }
} catch {}
$rdp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections
if ($rdp) {
    Add-Finding 'RemoteAccess' 'INFO' 'RDP' ($(if($rdp.fDenyTSConnections -eq 0){'Enabled'}else{'Disabled'}))
}

# 7) Installed hotfix freshness
$latestHotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($latestHotfix) {
    Add-Finding 'Patch' 'INFO' 'Latest hotfix' ("{0} installed {1}" -f $latestHotfix.HotFixID,$latestHotfix.InstalledOn)
}

# 8) Backup path freshness
foreach ($path in @($config.BackupPaths)) {
    if (Test-Path $path) {
        $latest = Get-ChildItem $path -File -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) {
            $age=((Get-Date)-$latest.LastWriteTime).TotalHours
            Add-Finding 'Backup' ($(if($age -le 30){'INFO'}else{'WARN'})) $path ("Latest={0}; AgeHours={1:N1}" -f $latest.FullName,$age)
        } else { Add-Finding 'Backup' 'WARN' $path 'No backup file found' }
    } else { Add-Finding 'Backup' 'WARN' $path 'Path not found' }
}

$summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    GeneratedAt = (Get-Date).ToString('s')
    HoursBack = $config.HoursBack
    High = @($findings | Where-Object Severity -eq 'HIGH').Count
    Warn = @($findings | Where-Object Severity -eq 'WARN').Count
    Review = @($findings | Where-Object Severity -eq 'REVIEW').Count
    Findings = $findings
}
$summary | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $jsonPath

$css = @'
<style>
body{font-family:Segoe UI,Arial;margin:24px} table{border-collapse:collapse;width:100%}th,td{padding:7px;border-bottom:1px solid #ddd;text-align:left}.HIGH{background:#ffd7d7}.WARN{background:#fff2cc}.REVIEW{background:#e4d7ff}h1{margin-bottom:4px}.meta{color:#666}
</style>
'@
$rows = $findings | ForEach-Object { "<tr class='$($_.Severity)'><td>$($_.Time)</td><td>$($_.Category)</td><td>$($_.Severity)</td><td>$($_.Item)</td><td>$($_.Details)</td></tr>" }
$html = "<html><head>$css</head><body><h1>Daily Server Audit</h1><div class='meta'>$($summary.ComputerName) - $($summary.GeneratedAt) | HIGH=$($summary.High) WARN=$($summary.Warn) REVIEW=$($summary.Review)</div><table><tr><th>Time</th><th>Category</th><th>Severity</th><th>Item</th><th>Details</th></tr>$($rows -join '')</table></body></html>"
Set-Content -Encoding UTF8 -Path $htmlPath -Value $html

Write-Host "Report: $htmlPath"
Write-Host "JSON:   $jsonPath"
if ($summary.High -gt 0) { exit 2 } elseif ($summary.Warn -gt 0) { exit 1 } else { exit 0 }
