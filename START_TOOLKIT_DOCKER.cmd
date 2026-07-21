@echo off
setlocal
title Domain Abuse Toolkit - Docker
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-toolkit-docker.ps1"
if errorlevel 1 (
  echo.
  echo Le demarrage Docker a echoue. Consultez le message ci-dessus.
  pause
)
endlocal
