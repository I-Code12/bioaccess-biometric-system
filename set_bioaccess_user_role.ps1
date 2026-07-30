$mysql = "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe"

if (-not (Test-Path $mysql)) {
    throw "MySQL executable was not found at $mysql"
}

$username = Read-Host "Enter the BioAccess username to update"
$roleName = Read-Host "Enter role to assign (admin, administrator, invigilator, registrar, biometric_officer)"

if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($roleName)) {
    throw "Username and role are required."
}

$allowedRoles = @("admin", "administrator", "invigilator", "registrar", "biometric_officer")
if ($allowedRoles -notcontains $roleName.Trim().ToLower()) {
    throw "Unsupported role '$roleName'. Allowed roles: $($allowedRoles -join ', ')"
}

$securePassword = Read-Host "Enter the MySQL root/admin password" -AsSecureString
$credential = [System.Net.NetworkCredential]::new("", $securePassword)
$env:MYSQL_PWD = $credential.Password

$safeUsername = $username.Trim().ToLower().Replace("\", "\\").Replace("'", "''")
$safeRole = $roleName.Trim().ToLower().Replace("\", "\\").Replace("'", "''")

$sql = @"
USE mydatabase;

INSERT INTO user_roles (user_id, role_id)
SELECT u.user_id, r.role_id
FROM users u
JOIN roles r ON r.role_name = '$safeRole'
WHERE u.username = '$safeUsername'
  AND NOT EXISTS (
      SELECT 1 FROM user_roles existing
      WHERE existing.user_id = u.user_id
        AND existing.role_id = r.role_id
  );

SELECT u.username,
       u.full_name,
       GROUP_CONCAT(DISTINCT r.role_name ORDER BY r.role_name) AS roles,
       GROUP_CONCAT(DISTINCT p.permission_name ORDER BY p.permission_name) AS permissions
FROM users u
LEFT JOIN user_roles ur ON ur.user_id = u.user_id
LEFT JOIN roles r ON r.role_id = ur.role_id
LEFT JOIN role_permissions rp ON rp.role_id = r.role_id
LEFT JOIN permissions p ON p.permission_id = rp.permission_id
WHERE u.username = '$safeUsername'
GROUP BY u.user_id, u.username, u.full_name;
"@

try {
    Write-Host "Assigning role '$safeRole' to '$safeUsername'..." -ForegroundColor Cyan
    $sql | & $mysql -uroot --ssl-mode=REQUIRED -D mydatabase --table
    if ($LASTEXITCODE -ne 0) {
        throw "Role assignment failed with exit code $LASTEXITCODE."
    }
    Write-Host "Role assignment completed." -ForegroundColor Green
}
finally {
    Remove-Item Env:\MYSQL_PWD -ErrorAction SilentlyContinue
}
