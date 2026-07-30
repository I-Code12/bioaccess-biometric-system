$mysql = "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe"
$sqlFile = Join-Path $PSScriptRoot "sql\setup_database_restrictions.sql"

if (-not (Test-Path $mysql)) {
    throw "MySQL executable was not found at $mysql"
}

if (-not (Test-Path $sqlFile)) {
    throw "Database restrictions SQL file was not found at $sqlFile"
}

$securePassword = Read-Host "Enter the MySQL root/admin password" -AsSecureString
$credential = [System.Net.NetworkCredential]::new("", $securePassword)
$env:MYSQL_PWD = $credential.Password

try {
    Write-Host "Applying BioAccess database roles, permissions, and restricted grants..." -ForegroundColor Cyan
    Get-Content -Raw -Path $sqlFile | & $mysql -uroot --ssl-mode=REQUIRED
    if ($LASTEXITCODE -ne 0) {
        throw "Database restrictions setup failed with exit code $LASTEXITCODE."
    }
    Write-Host "Database restrictions setup completed successfully." -ForegroundColor Green
}
finally {
    Remove-Item Env:\MYSQL_PWD -ErrorAction SilentlyContinue
}
