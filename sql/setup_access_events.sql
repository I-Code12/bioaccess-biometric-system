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

GRANT SELECT, INSERT ON mydatabase.access_events TO 'bioaccess_app'@'localhost';
FLUSH PRIVILEGES;
