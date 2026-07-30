$env:MYSQL_HOST = "localhost"
$env:MYSQL_PORT = "3306"
$env:MYSQL_USER = "bioaccess_app"
$securePassword = Read-Host "Enter the MySQL bioaccess_app password (not your Amen Jireh login password)" -AsSecureString
$credential = [System.Net.NetworkCredential]::new("", $securePassword)
$env:MYSQL_PASSWORD = $credential.Password
$env:MYSQL_DATABASE = "mydatabase"
$env:MYSQL_SSL_MODE = "REQUIRED"
$env:DOTNET_ROOT_X86 = "$PSScriptRoot\tools\dotnet-x86"
$env:ALLOW_SQLITE_FALLBACK = "0"
$projectRoot = $PSScriptRoot
$env:PYTHONPATH = "$projectRoot\vendorlibs;$projectRoot"

Set-Location $projectRoot
$python = "C:\Users\HP\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if (-not (Test-Path $python)) {
    throw "The BioAccess Python runtime was not found."
}
Write-Host "Starting BioAccess... Keep this terminal open while using the application." -ForegroundColor Cyan
& $python -m biometric_app.main
if ($LASTEXITCODE -ne 0) {
    throw "BioAccess stopped with exit code $LASTEXITCODE. Review the error shown above."
}
