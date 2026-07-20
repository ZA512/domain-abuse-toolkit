@echo off
setlocal
title Domain Abuse Toolkit - Tests
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\test-toolkit.ps1"
echo.
if errorlevel 1 (
  echo ECHEC - certains controles ne passent pas.
) else (
  echo SUCCES - tous les controles passent.
)
pause
endlocal

