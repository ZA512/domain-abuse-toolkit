@echo off
setlocal
title Domain Abuse Toolkit - Collecte technique passive
echo.
echo ATTENTION : ce mode autorise la collecte DNS/HTTP/TLS apres un clic confirme.
echo L'ouverture d'un dossier ne declenche aucune collecte.
echo Utilisez uniquement des cibles pour lesquelles vous etes autorise.
echo.
set /p "DAT_CONFIRM=Entrer OUI pour continuer : "
if /I not "%DAT_CONFIRM%"=="OUI" (
  echo Activation annulee.
  pause
  exit /b 1
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-toolkit.ps1" -EnableNetworkCollection
if errorlevel 1 (
  echo.
  echo Le demarrage a echoue. Consultez le message ci-dessus.
  pause
)
endlocal
