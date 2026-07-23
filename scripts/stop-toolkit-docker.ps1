[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path

$docker = Get-Command 'docker.exe' -ErrorAction SilentlyContinue
if (-not $docker) {
    throw 'Docker Desktop est requis pour ce lanceur.'
}

& $docker.Source compose --project-directory $repositoryRoot down
if ($LASTEXITCODE -ne 0) {
    throw "L'arret Docker Compose a echoue."
}

Write-Host 'Domain Abuse Toolkit Docker est arrete. Les dossiers sont conserves.' -ForegroundColor Green
