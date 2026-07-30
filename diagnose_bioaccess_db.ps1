$mysql = "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe"

if (-not (Test-Path $mysql)) {
    throw "MySQL executable was not found at $mysql"
}

$securePassword = Read-Host "Enter the MySQL bioaccess_app password" -AsSecureString
$credential = [System.Net.NetworkCredential]::new("", $securePassword)
$env:MYSQL_PWD = $credential.Password

$sql = @"
SELECT 'connection' AS check_name, 'ok' AS result;

SELECT 'active_students' AS check_name, COUNT(*) AS result
FROM students
WHERE account_status = 'active';

SELECT 'completed_biometric_records' AS check_name, COUNT(*) AS result
FROM students s
JOIN biometric_data b ON b.student_id = s.student_id
WHERE s.account_status = 'active'
  AND b.enrollment_status = 'completed';

SELECT 'usable_fingerprint_records' AS check_name, COUNT(*) AS result
FROM students s
JOIN biometric_data b ON b.student_id = s.student_id
WHERE s.account_status = 'active'
  AND b.enrollment_status = 'completed'
  AND b.fingerprint_template IS NOT NULL;

SELECT 'usable_face_records' AS check_name, COUNT(*) AS result
FROM students s
JOIN biometric_data b ON b.student_id = s.student_id
WHERE s.account_status = 'active'
  AND b.enrollment_status = 'completed'
  AND b.face_embedding IS NOT NULL;

SELECT 'access_events_table_exists' AS check_name, COUNT(*) AS result
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = 'mydatabase'
  AND TABLE_NAME = 'access_events';

SELECT s.student_id AS internal_id,
       s.student_index AS student_id,
       CONCAT(s.first_name, ' ', s.last_name) AS full_name,
       s.account_status,
       b.enrollment_status,
       IF(b.fingerprint_template IS NULL, 'missing', 'present') AS fingerprint_template,
       IF(b.face_embedding IS NULL, 'missing', 'present') AS face_template,
       b.fingerprint_algorithm,
       b.face_algorithm
FROM students s
LEFT JOIN biometric_data b ON b.student_id = s.student_id
ORDER BY s.student_id DESC
LIMIT 10;
"@

try {
    Write-Host "Checking BioAccess database communication and biometric records..." -ForegroundColor Cyan
    $sql | & $mysql -ubioaccess_app --ssl-mode=REQUIRED -D mydatabase --table
    if ($LASTEXITCODE -ne 0) {
        throw "Database diagnostic failed with exit code $LASTEXITCODE."
    }
}
finally {
    Remove-Item Env:\MYSQL_PWD -ErrorAction SilentlyContinue
}
