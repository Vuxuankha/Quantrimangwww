param(
  [string]$RunAt = '07:30',
  [string]$TaskName = 'Daily Server Audit'
)
$script = Join-Path $PSScriptRoot 'Daily-Audit.ps1'
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`""
$trigger = New-ScheduledTaskTrigger -Daily -At $RunAt
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Description 'Automated daily Windows Server audit' -Force
Write-Host "Installed scheduled task '$TaskName' at $RunAt"
