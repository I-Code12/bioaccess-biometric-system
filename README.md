# Biometric Desktop App

A desktop biometric authentication scaffold for a final-year project using:

- OpenCV YuNet face detection and SFace recognition
- Futronic FS80 fingerprint service hooks
- PySide6 desktop UI
- MySQL database
- AES-encrypted biometric storage

## Project structure

```text
biometric_app/
  main.py
  app.py
  config.py
  models.py
  rbac.py
  services/
    db_service.py
    face_service.py
    fingerprint_service.py
  ui/
    main_window.py
    access_control_page.py
    dashboard_page.py
    register_page.py
    verify_page.py
```

## Setup

1. Install MySQL server and ensure it's running.

2. Create a virtual environment.

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Set up the MySQL database:

```bash
python setup_mysql.py
```

Or configure environment variables for your MySQL setup:

```bash
set MYSQL_HOST=localhost
set MYSQL_PORT=3306
set MYSQL_USER=bioaccess_app
set MYSQL_PASSWORD=your_password
set MYSQL_DATABASE=mydatabase
set MYSQL_SSL_MODE=REQUIRED
set ALLOW_SQLITE_FALLBACK=0
```

5. Run the app:

```bash
python -m biometric_app.main
```

## Encryption

Biometric data is encrypted with AES-256-GCM before being stored in MySQL. Each payload uses a unique nonce and authenticated encryption so tampering is detected during decryption.

The application generates a 256-bit key automatically on first run and protects it with Windows DPAPI in `data/biometric_aes256.dpapi`. The raw key is not stored in the project. For managed deployments, an external 32-byte URL-safe base64 key can instead be supplied through `BIOMETRIC_AES256_KEY`.

```bash
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

2. Set it as an environment variable before running the app:

```bash
set BIOMETRIC_AES256_KEY=your_generated_key_here
```

MySQL transport encryption is mandatory. The launcher uses TLS and the server is configured to reject unencrypted connections.

## MySQL Database

The application is now configured to use MySQL as the primary database backend. The database service automatically creates the required tables (`users` and `verification_logs`) when the application starts.

The application opens on a login page. With the managed `mydatabase` schema,
staff accounts are created by an administrator from the Access Control page.
Passwords are stored as salted PBKDF2 hashes, never as plain text, and failed
sign-ins lock the account after five attempts.

By default, the app now expects the security-focused `mydatabase` MySQL schema and does not silently fall back to SQLite. This schema provides users, role-based permissions, audit logs, students, exams, biometric records, and verification history. If you intentionally want local fallback storage for testing, set:

```bash
set ALLOW_SQLITE_FALLBACK=1
```

The desktop application connects with the restricted `bioaccess_app` MySQL account. The launcher requests its password at runtime so database credentials are not stored in the project. The MySQL `root` account must be reserved for database administration.

## Role-based access control

Run the following once with the MySQL root/administrator password after a new
installation or RBAC upgrade:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup_database_restrictions.ps1
```

The operational roles are:

- **Administrator:** full access, staff accounts, roles, and account status.
- **Registrar:** student directory, registration, and biometric enrollment.
- **Biometric Officer:** student directory, biometric re-enrollment, and verification.
- **Invigilator:** entry, exit, and identity verification only.

The interface hides unavailable sections, and the database service repeats each
permission check before protected data is read or changed. Role changes and
denied actions are recorded in the audit log. An administrator cannot change or
disable their own signed-in account, and the final active administrator is
protected from removal.

## Biometric template versions

- Face templates use OpenCV SFace version 2. Enrollment captures three aligned,
  quality-checked samples and stores their normalized representative embedding.
- Fingerprint templates use Futronic FTRAPI minutiae version 4. Official
  enrollment captures the same finger three times; verification uses the
  Futronic 1:N matcher and rejects no-match or ambiguous results.
- Older HOG face templates and ridge-grid fingerprint templates are deliberately
  rejected. Re-enroll existing users after upgrading so incompatible templates
  cannot cause accidental matches.

**verification_logs table:**
- `id` (INT, AUTO_INCREMENT, PRIMARY KEY)
- `user_id` (INT, FOREIGN KEY)
- `method` (VARCHAR(50))
- `status` (VARCHAR(20))
- `details` (TEXT)
- `created_at` (DATETIME)

## Fingerprint scanner support

BioAccess currently targets the Futronic FS80 through the official 32-bit
FTRAPI recognition library and `ftrScanAPI` capture library. The packaged app
includes a 32-bit helper and runtime so the 64-bit desktop interface can use the
vendor SDK safely.

Windows Hello enrollment is not required. Each student must instead complete
BioAccess's official three-scan enrollment with the same finger. The resulting
minutiae template is encrypted before it is stored.
