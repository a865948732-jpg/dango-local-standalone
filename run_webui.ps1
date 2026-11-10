$ErrorActionPreference = 'Stop'
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $projectDir '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $python)) {
    throw "Python virtual environment not found: $python"
}

# Keep this optional integration local to Dango, not the Windows user environment.
$roxyConfigPath = Join-Path $projectDir 'roxy.local.json'
if (Test-Path -LiteralPath $roxyConfigPath) {
    $roxySettings = Get-Content -LiteralPath $roxyConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $roxyKeys = @(
        'ROXY_API_BASE', 'ROXY_WORKSPACE_ID', 'ROXY_PROJECT_ID',
        'REPO0810_ROXY_LEGACY_ROOT', 'REPO0810_ROXY_PYTHON'
    )
    foreach ($property in $roxySettings.PSObject.Properties) {
        if ($property.Name -notin $roxyKeys) {
            throw 'Unexpected key in local Roxy configuration'
        }
    }
    foreach ($key in $roxyKeys) {
        $property = $roxySettings.PSObject.Properties[$key]
        if ($null -eq $property -or $property.Value -isnot [string] -or
            [string]::IsNullOrWhiteSpace($property.Value)) {
            throw "Missing or invalid local Roxy setting: $key"
        }
        [Environment]::SetEnvironmentVariable($key, $property.Value, 'Process')
    }
}

Set-Location $projectDir
$env:PYTHONUTF8 = '1'
$statusLog = Join-Path $projectDir 'service-status.log'
Add-Content -LiteralPath $statusLog -Encoding UTF8 -Value ((Get-Date -Format o) + ' start wrapper_pid=' + $PID + ' listen=127.0.0.1:8765')
$serverExitCode = 1
try {
    & $python '-X' 'utf8' 'start_webui.py' '--no-browser' '--host' '127.0.0.1' '--port' '8765'
    $serverExitCode = $LASTEXITCODE
} finally {
    Add-Content -LiteralPath $statusLog -Encoding UTF8 -Value ((Get-Date -Format o) + ' stop exit_code=' + $serverExitCode)
}
exit $serverExitCode
