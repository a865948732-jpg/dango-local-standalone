[CmdletBinding()]
param(
    [switch]$BuildFrontend
)

$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPython = Join-Path $projectDir '.venv\Scripts\python.exe'

function Resolve-Python311 {
    $pyLauncher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($null -ne $pyLauncher) {
        $version = (& $pyLauncher.Source -3.11 -c 'import sys; print(sys.version_info[:2])' 2>$null | Out-String).Trim()
        if ($version -eq '(3, 11)') {
            return @{ Command = $pyLauncher.Source; Args = @('-3.11') }
        }
    }

    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($null -ne $python) {
        $version = (& $python.Source -c 'import sys; print(sys.version_info[:2])' 2>$null | Out-String).Trim()
        if ($version -eq '(3, 11)') {
            return @{ Command = $python.Source; Args = @() }
        }
    }

    throw 'Python 3.11 was not found. Install Python 3.11.x and add it to PATH.'
}

$runtime = Resolve-Python311
if (-not (Test-Path -LiteralPath $venvPython)) {
    Write-Host 'Creating Python virtual environment...'
    & $runtime.Command @($runtime.Args) -m venv (Join-Path $projectDir '.venv')
}

if (-not (Test-Path -LiteralPath $venvPython)) {
    throw "Could not create virtual environment: $venvPython"
}

Write-Host 'Installing Python dependencies...'
& $venvPython -m pip install --disable-pip-version-check --upgrade pip
& $venvPython -m pip install --disable-pip-version-check -r (Join-Path $projectDir 'requirements.lock.txt')

$settingsTemplate = Join-Path $projectDir 'config-templates\roxy.settings.example.json'
$settingsPath = Join-Path $projectDir 'roxy.settings.json'
if ((Test-Path -LiteralPath $settingsTemplate) -and -not (Test-Path -LiteralPath $settingsPath)) {
    Copy-Item -LiteralPath $settingsTemplate -Destination $settingsPath
}

if ($BuildFrontend) {
    $npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if ($null -eq $npm) {
        throw 'npm was not found. Install Node.js LTS before using -BuildFrontend.'
    }
    $frontend = Join-Path $projectDir 'webui\frontend'
    Push-Location $frontend
    try {
        & $npm.Source ci
        & $npm.Source run build
    } finally {
        Pop-Location
    }
}

Write-Host ''
Write-Host 'Setup complete. Run .\start_public.ps1 -OpenBrowser to open the page.' -ForegroundColor Green
