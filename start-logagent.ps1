<#
  Starts your trained model (if present) and the logagent dashboard.
    start-logagent.ps1          normal user (Security event log is skipped)
    start-logagent.ps1 -Admin   elevated, so failed logons / account changes / audit-log events are included
  Closing this window stops both.
#>
param([switch]$Admin, [switch]$NoBrowser, [int]$Port = 8765, [int]$ModelPort = 8081)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if ($Admin -and -not $isAdmin) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Admin -Port $Port -ModelPort $ModelPort"
    exit
}

$Host.UI.RawUI.WindowTitle = 'logagent'
if (-not (Test-Path logagent.toml)) { Copy-Item config.example.toml logagent.toml }
New-Item -ItemType Directory -Force data | Out-Null

function Test-Url($url) {
    try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 $url | Out-Null; return $true } catch { return $false }
}

# --- model server
$model = $null
$trainPy = Join-Path $PSScriptRoot '.venv-train\Scripts\python.exe'
$haveAdapter = (Get-ChildItem -Path models -Filter adapter -Directory -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1)
if (Test-Url "http://127.0.0.1:$ModelPort/v1/models") {
    Write-Host "[model] already running on :$ModelPort"
} elseif ((Test-Path $trainPy) -and $haveAdapter) {
    Write-Host "[model] starting your trained model on :$ModelPort (log: data\model.log) ..."
    $env:HF_HUB_DISABLE_SYMLINKS_WARNING = '1'
    $env:PYTHONIOENCODING = 'utf-8'
    $model = Start-Process -FilePath $trainPy -ArgumentList '-W', 'ignore', 'trainer\serve.py', '--port', $ModelPort `
        -WindowStyle Hidden -PassThru -RedirectStandardOutput data\model.log -RedirectStandardError data\model.err.log
    $deadline = (Get-Date).AddSeconds(180)
    while (-not (Test-Url "http://127.0.0.1:$ModelPort/v1/models")) {
        if ($model.HasExited) { Write-Warning "[model] exited early; see data\model.err.log. Continuing with rules only."; $model = $null; break }
        if ((Get-Date) -gt $deadline) { Write-Warning "[model] not ready after 180 s; continuing (dashboard shows model status)."; break }
        Start-Sleep -Seconds 2
    }
    if ($model) { Write-Host "[model] ready" }
} else {
    Write-Warning "[model] no trained model found (models\*\adapter) - running with rules only."
}

# --- dashboard
Write-Host "[dashboard] http://127.0.0.1:$Port/   privilege: $(if ($isAdmin) {'admin'} else {'user'})   (close this window to stop)"
try {
    $uiArgs = @('-m', 'logagent', 'ui', '--port', $Port)
    if ($NoBrowser) { $uiArgs += '--no-browser' }
    & python @uiArgs
} finally {
    if ($model -and -not $model.HasExited) { Stop-Process -Id $model.Id -Force; Write-Host "[model] stopped" }
}
