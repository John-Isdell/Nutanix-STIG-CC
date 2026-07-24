@echo off
setlocal
title Nutanix STIG Control Center Installer
cd /d "%~dp0"

if /I "%~1"=="--elevated" goto install
fltmc.exe >nul 2>nul
if errorlevel 1 (
  echo Windows needs one administrator approval to register the per-user
  echo login task. The Control Center itself will run with limited privileges.
  echo.
  set "NUTANIX_STIG_INSTALLER=%~f0"
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$p = Start-Process -FilePath $env:NUTANIX_STIG_INSTALLER -ArgumentList '--elevated' -Verb RunAs -Wait -PassThru; exit $p.ExitCode"
  exit /b %errorlevel%
)

:install
echo Installing Nutanix STIG Control Center...
echo This one-time setup registers the localhost supervisor at login.
echo.
where python.exe >nul 2>nul
if %errorlevel%==0 (
  python.exe "%~dp0control_center.py" install
) else (
  py.exe -3 "%~dp0control_center.py" install
)
if errorlevel 1 (
  echo.
  echo Installation failed. Review the message above.
  pause
)
