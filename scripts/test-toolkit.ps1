[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function ConvertTo-BashLiteral {
    param([Parameter(Mandatory)][string]$Value)
    if ($Value.Contains([char]39)) {
        throw "Le chemin du projet ne doit pas contenir de guillemet simple."
    }
    return ([char]39) + $Value + ([char]39)
}

$repositoryRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path

Write-Host 'Domain Abuse Toolkit - controles automatiques' -ForegroundColor Green

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'WSL est requis pour lancer les tests sur ce poste.'
}

$wslRepositoryRoot = (& wsl.exe wslpath -a -u $repositoryRoot).Trim()
if ($LASTEXITCODE -ne 0 -or -not $wslRepositoryRoot) {
    throw 'Impossible de convertir le chemin du projet pour WSL.'
}
$repoLiteral = ConvertTo-BashLiteral -Value $wslRepositoryRoot

$testCommand = @"
set -eu
REPO=$repoLiteral
VENV="`$HOME/.local/share/domain-abuse-toolkit/venv-dev"
mkdir -p "`$(dirname "`$VENV")"
if [ ! -x "`$VENV/bin/python" ]; then
  python3 -m venv "`$VENV"
fi
"`$VENV/bin/python" -m pip install --disable-pip-version-check -q -e "`$REPO[dev]"
cd "`$REPO"
"`$VENV/bin/ruff" check .
"`$VENV/bin/pytest"
"@.Trim()

$testCommandBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($testCommand))
& wsl.exe sh -c "printf %s $testCommandBase64 | base64 -d | sh"
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host 'Tous les controles passent.' -ForegroundColor Green
