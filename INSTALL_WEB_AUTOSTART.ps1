$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
$Python = Join-Path $Root '.venv\Scripts\pythonw.exe'
$RuntimeDB = Join-Path $Root 'runtime_data\database\network_automation.db'
if (!(Test-Path $Python)) { throw 'Run INSTALL_WEB.bat first.' }
if (!(Test-Path $RuntimeDB)) { throw 'Import your data or create an empty runtime first.' }
$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$Action = New-ScheduledTaskAction -Execute $Python -Argument ('"' + (Join-Path $Root 'run_web_background.py') + '"') -WorkingDirectory $Root
$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $Identity
$Principal = New-ScheduledTaskPrincipal -UserId $Identity -LogonType Interactive -RunLevel Limited
$Settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'NetworkAutomation Web' -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
Write-Host 'Installed for current user logon; not a boot-time Windows service.'
Write-Host 'No elevated runlevel, no saved Windows password. Starts on next logon.'
Write-Host 'To run now: Start-ScheduledTask -TaskName "NetworkAutomation Web"'
