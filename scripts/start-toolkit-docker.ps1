[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8080,

    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repositoryRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$applicationUrl = "http://127.0.0.1:$Port/"

Write-Host 'Domain Abuse Toolkit - Docker (mode sur)' -ForegroundColor Green
Write-Host 'Verification de Docker Desktop...'

$docker = Get-Command 'docker.exe' -ErrorAction SilentlyContinue
if (-not $docker) {
    throw 'Docker Desktop est requis pour ce lanceur.'
}

& $docker.Source version --format '{{.Server.Version}}' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Desktop doit etre demarre.'
}

$previousHostPort = $env:DAT_HOST_PORT
try {
    $env:DAT_HOST_PORT = $Port
    Write-Host 'Construction et demarrage du conteneur local...'
    & $docker.Source compose --project-directory $repositoryRoot up --detach --build --wait
    if ($LASTEXITCODE -ne 0) {
        throw 'Le demarrage Docker Compose a echoue.'
    }
}
finally {
    if ($null -eq $previousHostPort) {
        Remove-Item Env:DAT_HOST_PORT -ErrorAction SilentlyContinue
    }
    else {
        $env:DAT_HOST_PORT = $previousHostPort
    }
}

Write-Host "Application disponible sur $applicationUrl" -ForegroundColor Green
Write-Host 'Collecte reseau, captures live, IA et envois externes : desactives.' -ForegroundColor Yellow
if (-not $NoBrowser) {
    Start-Process $applicationUrl
}
