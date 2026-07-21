[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8080,

    [switch]$NoBrowser,

    [switch]$EnableNetworkCollection,

    [switch]$EnableScreenshots,

    [switch]$ForceCaptureImageBuild,

    [ValidatePattern('^[a-z]{2}(-[A-Z]{2})?$')]
    [string]$UiLanguage = 'en',

    [ValidateSet('Normal', 'Hidden')]
    [string]$ServerWindowStyle = 'Normal'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function ConvertTo-BashLiteral {
    param([Parameter(Mandatory)][string]$Value)
    if ($Value.Contains([char]39)) {
        throw "Le chemin du projet ne doit pas contenir de guillemet simple."
    }
    return ([char]39) + $Value + ([char]39)
}

function Get-ToolkitHealth {
    param([Parameter(Mandatory)][string]$Uri)
    try {
        $response = Invoke-RestMethod -Method Get -Uri $Uri -TimeoutSec 2
        if ($response.status -eq 'ok') {
            return $response
        }
    }
    catch {
        return $null
    }
    return $null
}

$repositoryRoot = (Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).Path
$healthUrl = "http://127.0.0.1:$Port/health"
$applicationUrl = "http://127.0.0.1:$Port/"

Write-Host 'Domain Abuse Toolkit' -ForegroundColor Green
Write-Host 'Verification des prerequis...'

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    throw 'WSL est requis pour ce lanceur. Installez WSL/Ubuntu puis relancez.'
}

$existing = Get-ToolkitHealth -Uri $healthUrl
if ($existing) {
    Write-Host "L'application est deja disponible (version $($existing.version))." -ForegroundColor Yellow
    if (-not $NoBrowser) {
        Start-Process $applicationUrl
    }
    exit 0
}

$pythonVersionOutput = (& wsl.exe python3 --version 2>&1).Trim()
if ($LASTEXITCODE -ne 0 -or $pythonVersionOutput -notmatch '^Python (\d+)\.(\d+)') {
    throw 'Python 3 est introuvable dans la distribution WSL par defaut.'
}
$pythonVersion = "$($Matches[1]).$($Matches[2])"
if ([int]$Matches[1] -lt 3 -or ([int]$Matches[1] -eq 3 -and [int]$Matches[2] -lt 12)) {
    throw "Python 3.12 minimum est requis dans WSL. Version detectee : $pythonVersion"
}

$wslRepositoryRoot = (& wsl.exe wslpath -a -u $repositoryRoot).Trim()
if ($LASTEXITCODE -ne 0 -or -not $wslRepositoryRoot) {
    throw 'Impossible de convertir le chemin du projet pour WSL.'
}

$repoLiteral = ConvertTo-BashLiteral -Value $wslRepositoryRoot
$networkCollectionValue = if ($EnableNetworkCollection) { 'true' } else { 'false' }
$screenshotValue = if ($EnableScreenshots) { 'true' } else { 'false' }
$captureDockerCommand = ''
if ($EnableScreenshots) {
    $captureDockerImage = 'domain-abuse-toolkit-capture:1.0'
    $docker = Get-Command 'docker.exe' -ErrorAction SilentlyContinue
    if (-not $docker) {
        throw 'Docker Desktop est requis pour isoler le navigateur de capture.'
    }
    & $docker.Source version --format '{{.Server.Version}}' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'Docker Desktop doit etre demarre pour activer la capture isolee.'
    }
    $captureImageIds = @(& $docker.Source image ls --quiet `
        --filter "reference=$captureDockerImage")
    $captureImageExists = $captureImageIds.Count -gt 0
    if ($captureImageExists -and -not $ForceCaptureImageBuild) {
        Write-Host "Image de capture existante reutilisee : $captureDockerImage" -ForegroundColor Green
    }
    else {
        Write-Host 'Preparation du conteneur de capture isole...'
        $captureBuildSucceeded = $false
        for ($captureBuildAttempt = 1; $captureBuildAttempt -le 3; $captureBuildAttempt++) {
            & $docker.Source build --quiet --tag $captureDockerImage `
                --file (Join-Path $repositoryRoot 'docker\capture\Dockerfile') $repositoryRoot
            if ($LASTEXITCODE -eq 0) {
                $captureBuildSucceeded = $true
                break
            }
            if ($captureBuildAttempt -lt 3) {
                Write-Host "Docker est temporairement indisponible. Nouvelle tentative ($($captureBuildAttempt + 1)/3)..." -ForegroundColor Yellow
                Start-Sleep -Seconds 2
            }
        }
        if (-not $captureBuildSucceeded) {
            throw 'La preparation du conteneur de capture a echoue apres trois tentatives.'
        }
    }
    $captureDockerCommand = (& wsl.exe wslpath -a -u $docker.Source).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $captureDockerCommand) {
        throw 'Impossible de localiser Docker depuis WSL.'
    }
}
$setupCommand = @"
set -eu
REPO=$repoLiteral
VENV="`$HOME/.local/share/domain-abuse-toolkit/venv"
mkdir -p "`$(dirname "`$VENV")"
if [ ! -x "`$VENV/bin/python" ]; then
  python3 -m venv "`$VENV"
fi
"`$VENV/bin/python" -m pip install --disable-pip-version-check -q -e "`$REPO"
"@.Trim()

Write-Host "Preparation de l'environnement Python $pythonVersion..."
$setupCommandBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($setupCommand))
& wsl.exe sh -c "printf %s $setupCommandBase64 | base64 -d | sh"
if ($LASTEXITCODE -ne 0) {
    throw 'La preparation Python a echoue.'
}

$serverCommand = @"
set -eu
REPO=$repoLiteral
VENV="`$HOME/.local/share/domain-abuse-toolkit/venv"
cd "`$REPO"
export DAT_DATA_DIR="`$HOME/.local/share/domain-abuse-toolkit/case-data"
export DAT_PORT=$Port
export DAT_PUBLIC_BASE_URL="http://127.0.0.1:$Port"
export DAT_UI_LANGUAGE="$UiLanguage"
export DAT_ENABLE_NETWORK_COLLECTION=$networkCollectionValue
export DAT_ENABLE_RDAP_COLLECTION=$networkCollectionValue
export DAT_ENABLE_SCREENSHOTS=$screenshotValue
export DAT_CAPTURE_DOCKER_COMMAND="$captureDockerCommand"
export DAT_CAPTURE_DOCKER_IMAGE="domain-abuse-toolkit-capture:1.0"
mkdir -p "`$HOME/.local/share/domain-abuse-toolkit"
echo "`$`$" > "`$HOME/.local/share/domain-abuse-toolkit/server-$Port.pid"
exec "`$VENV/bin/python" -m uvicorn domain_abuse_toolkit.main:app --host 127.0.0.1 --port $Port
"@.Trim()

$serverCommandBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($serverCommand))
$serverPowerShell = @"
`$Host.UI.RawUI.WindowTitle = 'Domain Abuse Toolkit - Serveur (fermer pour arreter)'
Write-Host 'Serveur Domain Abuse Toolkit' -ForegroundColor Green
Write-Host 'Pour arreter : Ctrl+C ou fermez cette fenetre.' -ForegroundColor Yellow
& wsl.exe sh -c "printf %s $serverCommandBase64 | base64 -d | sh"
if (`$LASTEXITCODE -ne 0) {
    Write-Host "Le serveur s'est arrete avec le code `$LASTEXITCODE." -ForegroundColor Red
    Read-Host 'Appuyez sur Entree pour fermer'
}
"@

$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($serverPowerShell))
$serverProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-EncodedCommand', $encodedCommand
) -WindowStyle $ServerWindowStyle -PassThru

Write-Host 'Demarrage du serveur...'
$health = $null
for ($attempt = 0; $attempt -lt 60; $attempt++) {
    Start-Sleep -Milliseconds 500
    $health = Get-ToolkitHealth -Uri $healthUrl
    if ($health) {
        break
    }
    if ($serverProcess.HasExited) {
        throw "La fenetre serveur s'est fermee avant que l'application soit disponible."
    }
}

if (-not $health) {
    throw "Le serveur n'a pas repondu sur $applicationUrl dans le delai imparti."
}

Write-Host "Pret : $applicationUrl" -ForegroundColor Green
if ($EnableNetworkCollection) {
    Write-Host 'Collecte passive DNS/HTTP/TLS/RDAP activee : aucun contact sans clic et confirmation.' -ForegroundColor Yellow
}
else {
    Write-Host 'Le mode test ne contacte aucun site cible.' -ForegroundColor Cyan
}
if ($EnableScreenshots) {
    Write-Host 'Rendu visuel hors ligne actif : JavaScript et reseau bloques dans le navigateur.' -ForegroundColor Yellow
}
Write-Host 'Fermez la fenetre serveur ou utilisez Ctrl+C pour arreter.'

if (-not $NoBrowser) {
    Start-Process $applicationUrl
}
