[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8080
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'WSL est introuvable.'
}

$stopCommand = @"
set -eu
PIDFILE="`$HOME/.local/share/domain-abuse-toolkit/server-$Port.pid"
if [ ! -f "`$PIDFILE" ]; then
  exit 2
fi
PID="`$(cat "`$PIDFILE")"
if kill -0 "`$PID" 2>/dev/null; then
  kill "`$PID"
fi
rm -f "`$PIDFILE"
"@.Trim()

$stopCommandBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($stopCommand))
& wsl.exe sh -c "printf %s $stopCommandBase64 | base64 -d | sh"
switch ($LASTEXITCODE) {
    0 { Write-Host 'Domain Abuse Toolkit est arrete.' -ForegroundColor Green }
    2 { Write-Host "Aucun serveur Domain Abuse Toolkit actif n'a ete trouve." -ForegroundColor Yellow }
    default { throw "L'arret du serveur a echoue avec le code $LASTEXITCODE." }
}
