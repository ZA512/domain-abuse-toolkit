@echo off
setlocal
title Domain Abuse Toolkit - Demarrage
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-toolkit.ps1"
if errorlevel 1 (
  echo.
  echo Le demarrage a echoue. Consultez le message ci-dessus.
  pause
)
endlocal

