@echo off
setlocal
title Domain Abuse Toolkit - Arret
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\stop-toolkit.ps1"
if errorlevel 1 (
  echo.
  echo L'arret a echoue. Consultez le message ci-dessus.
  pause
)
endlocal

