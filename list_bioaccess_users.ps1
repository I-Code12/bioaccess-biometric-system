$mysql = "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe"

if (-not (Test-Path $mysql)) {
    throw "MySQL executable was not found at $mysql"
}

$securePassword = Read-Host "Enter the MySQL root/admin password" -AsSecureString
$credential = [System.Net.NetworkCredential]::new("", $securePassword)
$env:MYSQL_PWD = $credential.Password

$sql = @"
USE mydatabase;

SELECT u.user_id,
       u.username,
       u.full_name,
       u.account_status,
       GROUP_CONCAT(DISTINCT r.role_name ORDER BY r.role_name) AS roles,
       GROUP_CONCAT(DISTINCT p.permission_name ORDER BY p.permission_name) AS permissions
FROM users u
LEFT JOIN user_roles ur ON ur.user_id = u.user_id
LEFT JOIN roles r ON r.role_id = ur.role_id
LEFT JOIN role_permissions rp ON rp.role_id = r.role_id
LEFT JOIN permissions p ON p.permission_id = rp.permission_id
GROUP BY u.user_id, u.username, u.full_name, u.account_status
ORDER BY u.username;
"@

try {
    Write-Host "Listing BioAccess users, roles, and permissions..." -ForegroundColor Cyan
    $sql | & $mysql -uroot --ssl-mode=REQUIRED -D mydatabase --table
    if ($LASTEXITCODE -ne 0) {
        throw "User listing failed with exit code $LASTEXITCODE."
    }
}
finally {
    Remove-Item Env:\MYSQL_PWD -ErrorAction SilentlyContinue
}
