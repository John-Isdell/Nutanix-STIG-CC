@echo off
setlocal
cd /d "%~dp0"
where python.exe >nul 2>nul
if %errorlevel%==0 (
  python.exe "%~dp0control_center.py" status
) else (
  py.exe -3 "%~dp0control_center.py" status
)
echo.
pause
