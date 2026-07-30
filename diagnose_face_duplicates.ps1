$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = "C:\Users\HP\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"

if (-not (Test-Path $python)) {
    $python = Join-Path $projectRoot ".venv\Scripts\python.exe"
}

if (-not (Test-Path $python)) {
    $python = Join-Path $projectRoot ".venv2\Scripts\python.exe"
}

if (-not (Test-Path $python)) {
    $python = "python"
}

if (-not $env:MYSQL_PASSWORD) {
    $securePassword = Read-Host "Enter the MySQL app-user password" -AsSecureString
    $credential = [System.Net.NetworkCredential]::new("", $securePassword)
    $env:MYSQL_PASSWORD = $credential.Password
}

try {
    Push-Location $projectRoot
    & $python diagnose_face_duplicates.py
    if ($LASTEXITCODE -ne 0) {
        throw "Face duplicate diagnostic failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
