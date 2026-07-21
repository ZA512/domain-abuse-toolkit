@echo off
setlocal
title Domain Abuse Toolkit - Arret Docker
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\stop-toolkit-docker.ps1"
if errorlevel 1 (
  echo.
  echo L'arret Docker a echoue. Consultez le message ci-dessus.
  pause
)
endlocal
