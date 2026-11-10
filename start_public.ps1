[CmdletBinding()]
param(
    [switch]$OpenBrowser,
    [int]$Port = 8765
)

$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $projectDir '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $python)) {
    & (Join-Path $projectDir 'setup_windows.ps1')
}
if (-not (Test-Path -LiteralPath $python)) {
    throw "Python virtual environment is missing: $python"
}

Set-Location $projectDir
$env:PYTHONUTF8 = '1'
$arguments = @('start_webui.py', '--host', '127.0.0.1', '--port', [string]$Port)
if (-not $OpenBrowser) {
    $arguments += '--no-browser'
}
& $python @arguments
exit $LASTEXITCODE
