USE mydatabase;

CREATE TABLE IF NOT EXISTS access_events (
    event_id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NULL,
    subject_name VARCHAR(150) NULL,
    subject_student_id VARCHAR(50) NULL,
    access_type VARCHAR(10) NOT NULL,
    biometric_status VARCHAR(20) NOT NULL,
    access_status VARCHAR(20) NOT NULL,
    remarks TEXT NULL,
    device_name VARCHAR(100) NULL,
    location VARCHAR(100) NULL,
    verified_by INT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_access_events_student_time (student_id, created_at),
    INDEX idx_access_events_type_status (access_type, access_status)
);

INSERT IGNORE INTO permissions (permission_name, description) VALUES
    ('*', 'Full BioAccess application access'),
    ('verify_students', 'Run examination entry, exit, and identity verification'),
    ('view_students', 'View the protected student directory'),
    ('register_students', 'Register student demographic records'),
    ('enrol_biometrics', 'Enroll and re-enroll student biometric templates'),
    ('manage_users', 'Deactivate student records and manage protected student actions'),
    ('manage_accounts', 'Create staff accounts and manage their roles and sign-in status'),
    ('generate_reports', 'Generate operational and audit reports'),
    ('manage_exams', 'Create and manage examination schedules');

INSERT IGNORE INTO roles (role_name, description) VALUES
    ('admin', 'System administrator with full BioAccess permissions'),
    ('administrator', 'System administrator alias with full BioAccess permissions'),
    ('system_developer', 'System owner and developer with full BioAccess permissions'),
    ('invigilator', 'Examination officer allowed to verify students'),
    ('registrar', 'Officer allowed to register students and enroll biometrics'),
    ('biometric_officer', 'Officer allowed to manage biometric enrollment and verification');

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
JOIN permissions p ON p.permission_name = '*'
WHERE r.role_name IN ('admin', 'administrator', 'system_developer')
  AND NOT EXISTS (
      SELECT 1 FROM role_permissions existing
      WHERE existing.role_id = r.role_id
        AND existing.permission_id = p.permission_id
  );

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
JOIN permissions p ON p.permission_name = 'verify_students'
WHERE r.role_name = 'invigilator'
  AND NOT EXISTS (
      SELECT 1 FROM role_permissions existing
      WHERE existing.role_id = r.role_id
        AND existing.permission_id = p.permission_id
  );

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
JOIN permissions p ON p.permission_name IN ('register_students', 'enrol_biometrics')
WHERE r.role_name = 'registrar'
  AND NOT EXISTS (
      SELECT 1 FROM role_permissions existing
      WHERE existing.role_id = r.role_id
        AND existing.permission_id = p.permission_id
  );

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
JOIN permissions p ON p.permission_name IN ('verify_students', 'enrol_biometrics', 'view_students')
WHERE r.role_name = 'biometric_officer'
  AND NOT EXISTS (
      SELECT 1 FROM role_permissions existing
      WHERE existing.role_id = r.role_id
        AND existing.permission_id = p.permission_id
  );

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
JOIN permissions p ON p.permission_name = 'view_students'
WHERE r.role_name = 'registrar'
  AND NOT EXISTS (
      SELECT 1 FROM role_permissions existing
      WHERE existing.role_id = r.role_id
        AND existing.permission_id = p.permission_id
  );

GRANT SELECT, INSERT, UPDATE ON mydatabase.users TO 'bioaccess_app'@'localhost';
GRANT SELECT ON mydatabase.roles TO 'bioaccess_app'@'localhost';
GRANT SELECT ON mydatabase.permissions TO 'bioaccess_app'@'localhost';
GRANT SELECT, INSERT, DELETE ON mydatabase.user_roles TO 'bioaccess_app'@'localhost';
GRANT SELECT ON mydatabase.role_permissions TO 'bioaccess_app'@'localhost';
GRANT SELECT, INSERT ON mydatabase.audit_logs TO 'bioaccess_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON mydatabase.students TO 'bioaccess_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON mydatabase.biometric_data TO 'bioaccess_app'@'localhost';
GRANT SELECT, INSERT ON mydatabase.verification_logs TO 'bioaccess_app'@'localhost';
GRANT SELECT, INSERT ON mydatabase.access_events TO 'bioaccess_app'@'localhost';

FLUSH PRIVILEGES;
