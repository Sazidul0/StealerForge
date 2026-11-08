@echo off
setlocal
mkdir C:\StealerForge 2>nul
copy /Y C:\OEM\agent.py C:\StealerForge\agent.py
start /wait "" C:\OEM\python-installer.exe /quiet InstallAllUsers=1 TargetDir=C:\StealerForge\Python Include_test=0 Include_launcher=0 PrependPath=0
if not exist C:\StealerForge\Python\pythonw.exe exit /b 1
netsh advfirewall firewall add rule name="StealerForge CAPE Agent" dir=in action=allow protocol=TCP localport=8000
powershell -NoProfile -ExecutionPolicy Bypass -File C:\OEM\register-agent.ps1
if errorlevel 1 exit /b 1
rem Victim persona, browsers, canary data and telemetry; results in C:\StealerForge\provision.json.
C:\StealerForge\Python\python.exe C:\OEM\provision.py > C:\StealerForge\provision.log 2>&1
rem Written last: the host treats a matching recipe as "provisioning finished".
copy /Y C:\OEM\recipe.txt C:\StealerForge\recipe.txt
echo ready>C:\StealerForge\ready.txt
exit /b 0
