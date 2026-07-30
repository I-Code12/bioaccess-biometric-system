from __future__ import annotations

import sqlite3
import subprocess
import hashlib
import hmac
import secrets
import os
import json
from datetime import datetime
from pathlib import Path

from biometric_app.config import (
    ALLOW_SQLITE_FALLBACK,
    DB_PATH,
    MYSQL_DATABASE,
    MYSQL_EXECUTABLE,
    MYSQL_HOST,
    MYSQL_PASSWORD,
    MYSQL_PORT,
    MYSQL_USER,
    MYSQL_SSL_CA,
    MYSQL_SSL_MODE,
)
from biometric_app.models import AccountRecord, UserRecord, VerificationResult
from biometric_app.rbac import (
    ENROL_BIOMETRICS,
    FULL_ACCESS,
    MANAGE_ACCOUNTS,
    MANAGE_STUDENTS,
    REGISTER_STUDENTS,
    ROLE_LABELS,
    VERIFY_STUDENTS,
)
from biometric_app.services.encryption_service import EncryptionService


class AuthorizationError(PermissionError):
    """Raised when the signed-in account is not permitted to perform an action."""


class DatabaseService:
    def __init__(
        self,
        host: str = MYSQL_HOST,
        port: int = MYSQL_PORT,
        user: str = MYSQL_USER,
        password: str = MYSQL_PASSWORD,
        database: str = MYSQL_DATABASE,
        mysql_executable: str = MYSQL_EXECUTABLE,
        mysql_ssl_mode: str = MYSQL_SSL_MODE,
        mysql_ssl_ca: Path = MYSQL_SSL_CA,
        allow_sqlite_fallback: bool = ALLOW_SQLITE_FALLBACK,
        sqlite_path: Path = DB_PATH,
        encryption_service: EncryptionService | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.mysql_executable = mysql_executable
        self.mysql_ssl_mode = mysql_ssl_mode
        self.mysql_ssl_ca = Path(mysql_ssl_ca)
        self.allow_sqlite_fallback = allow_sqlite_fallback
        self.sqlite_path = Path(sqlite_path)
        self.encryption_service = encryption_service or EncryptionService()
        self.backend = "mysql"
        self.last_error: str | None = None
        self.current_account_id: int | None = None
        self.current_account: AccountRecord | None = None

    def initialize(self) -> None:
        if self.database.lower() == "mydatabase":
            try:
                required = self._run_mysql(
                    "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'mydatabase' AND TABLE_NAME IN ('users','roles','user_roles','permissions','audit_logs','students','biometric_data','verification_logs');",
                    capture_output=True,
                    headers=["total"],
                )
                if not required or int(required[0]["total"]) != 8:
                    raise RuntimeError("The mydatabase security schema is incomplete.")
                try:
                    self._ensure_access_event_storage()
                except RuntimeError as exc:
                    self.last_error = f"Entry/Exit storage is not ready: {exc}"
                self.backend = "mysql"
                return
            except RuntimeError as exc:
                self.last_error = str(exc)
                if not self.allow_sqlite_fallback:
                    raise
                self.backend = "sqlite"
                with self._connect_sqlite() as connection:
                    self._initialize_sqlite(connection)
                    self._ensure_sqlite_access_event_storage(connection)
                return
        try:
            self._run_mysql(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id INT AUTO_INCREMENT PRIMARY KEY,
                    full_name VARCHAR(100) NOT NULL,
                    student_id VARCHAR(50) NOT NULL UNIQUE,
                    department VARCHAR(100) NULL,
                    level VARCHAR(20) NULL,
                    gender VARCHAR(10) NULL,
                    phone VARCHAR(20) NULL,
                    email VARCHAR(100) NULL,
                    face_embedding LONGBLOB,
                    fingerprint_template LONGBLOB,
                    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS verification_logs (
                    log_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NULL,
                    verification_mode VARCHAR(30) NOT NULL,
                    fingerprint_status VARCHAR(20) NULL DEFAULT 'NOT_USED',
                    face_status VARCHAR(20) NULL DEFAULT 'NOT_USED',
                    final_status VARCHAR(20) NOT NULL,
                    device_name VARCHAR(100) NULL,
                    location VARCHAR(100) NULL,
                    remarks TEXT NULL,
                    verification_time TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE
                );

                CREATE TABLE IF NOT EXISTS accounts (
                    account_id INT AUTO_INCREMENT PRIMARY KEY,
                    display_name VARCHAR(100) NOT NULL,
                    username VARCHAR(100) NOT NULL UNIQUE,
                    password_hash VARCHAR(128) NOT NULL,
                    password_salt VARCHAR(64) NOT NULL,
                    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
                    last_login_at TIMESTAMP NULL
                );

                CREATE TABLE IF NOT EXISTS login_logs (
                    login_id INT AUTO_INCREMENT PRIMARY KEY,
                    account_id INT NULL,
                    username_attempted VARCHAR(100) NOT NULL,
                    status VARCHAR(20) NOT NULL,
                    login_time TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(account_id) REFERENCES accounts(account_id) ON DELETE SET NULL
                );

                ALTER TABLE verification_logs
                    ADD COLUMN IF NOT EXISTS subject_name VARCHAR(100) NULL AFTER user_id,
                    ADD COLUMN IF NOT EXISTS subject_student_id VARCHAR(50) NULL AFTER subject_name,
                    ADD COLUMN IF NOT EXISTS event_type VARCHAR(30) NOT NULL DEFAULT 'VERIFICATION' AFTER subject_student_id;

                UPDATE verification_logs logs
                INNER JOIN users users_table ON users_table.user_id = logs.user_id
                SET
                    logs.subject_name = COALESCE(logs.subject_name, users_table.full_name),
                    logs.subject_student_id = COALESCE(logs.subject_student_id, users_table.student_id)
                WHERE logs.user_id IS NOT NULL;
                """
            )
            self.backend = "mysql"
            try:
                self._ensure_access_event_storage()
            except RuntimeError as exc:
                self.last_error = f"Entry/Exit storage is not ready: {exc}"
            return
        except RuntimeError as exc:
            self.last_error = str(exc)
            if not self.allow_sqlite_fallback:
                raise RuntimeError(
                    "Unable to connect to the MySQL database "
                    f"'{self.database}' on {self.host}:{self.port} as user '{self.user}'. "
                    "Set MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE, "
                    "and MYSQL_EXECUTABLE correctly, or set ALLOW_SQLITE_FALLBACK=1 if you intentionally want local SQLite."
                ) from exc
            self.backend = "sqlite"

        with self._connect_sqlite() as connection:
            self._initialize_sqlite(connection)
            self._ensure_sqlite_access_event_storage(connection)

    def create_account(self, display_name: str, username: str, password: str) -> AccountRecord:
        display_name = display_name.strip()
        username = username.strip().lower()
        if not display_name or not username:
            raise ValueError("Display name and username are required.")
        if len(username) < 3:
            raise ValueError("Username must contain at least 3 characters.")
        if len(password) < 12:
            raise ValueError("Password must contain at least 12 characters.")
        if not all((any(c.islower() for c in password), any(c.isupper() for c in password), any(c.isdigit() for c in password), any(not c.isalnum() for c in password))):
            raise ValueError("Password must include uppercase, lowercase, number, and symbol characters.")
        salt = secrets.token_hex(16)
        password_hash = self._hash_password(password, salt)
        now = datetime.utcnow()
        if self.backend == "mysql":
            if self.database.lower() == "mydatabase":
                encoded_hash = f"pbkdf2_sha256$310000${salt}${password_hash}"
                existing = self._run_mysql(f"SELECT COUNT(*) FROM users WHERE username = '{self._escape_sql(username)}';", True, ["total"])
                if existing and int(existing[0]["total"]) > 0:
                    raise ValueError("That username is already in use.")
                self._run_mysql(f"""
                    INSERT INTO users (username, password_hash, full_name, account_status, failed_login_attempts, created_at)
                    VALUES ('{self._escape_sql(username)}', '{encoded_hash}', '{self._escape_sql(display_name)}', 'active', 0, '{now.strftime('%Y-%m-%d %H:%M:%S')}');
                    INSERT INTO user_roles (user_id, role_id)
                    SELECT u.user_id, r.role_id FROM users u JOIN roles r ON r.role_name = 'invigilator'
                    WHERE u.username = '{self._escape_sql(username)}';
                """)
                rows = self._run_mysql(f"SELECT user_id FROM users WHERE username = '{self._escape_sql(username)}' LIMIT 1;", True, ["user_id"])
                return AccountRecord(int(rows[0]["user_id"]), display_name, username)
            existing = self._run_mysql(f"SELECT COUNT(*) FROM accounts WHERE username = '{self._escape_sql(username)}';", True, ["total"])
            if existing and int(existing[0]["total"]) > 0:
                raise ValueError("That username is already in use.")
            self._run_mysql(f"INSERT INTO accounts (display_name, username, password_hash, password_salt, created_at) VALUES ('{self._escape_sql(display_name)}', '{self._escape_sql(username)}', '{password_hash}', '{salt}', '{now.strftime('%Y-%m-%d %H:%M:%S')}');")
            rows = self._run_mysql(f"SELECT account_id FROM accounts WHERE username = '{self._escape_sql(username)}' LIMIT 1;", True, ["account_id"])
            return AccountRecord(int(rows[0]["account_id"]), display_name, username)
        with self._connect_sqlite() as connection:
            try:
                cursor = connection.execute("INSERT INTO accounts (display_name, username, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?)", (display_name, username, password_hash, salt, now.isoformat()))
                connection.commit()
            except sqlite3.IntegrityError as exc:
                raise ValueError("That username is already in use.") from exc
        return AccountRecord(int(cursor.lastrowid), display_name, username)

    def authenticate(self, username: str, password: str) -> AccountRecord | None:
        username = username.strip().lower()
        if self.backend == "mysql":
            if self.database.lower() == "mydatabase":
                rows = self._run_mysql(f"SELECT user_id, full_name, username, password_hash, account_status, failed_login_attempts FROM users WHERE username = '{self._escape_sql(username)}' LIMIT 1;", True, ["account_id", "display_name", "username", "password_hash", "account_status", "failed_login_attempts"])
                account = rows[0] if rows else None
                success = bool(account) and account["account_status"] == "active" and self._verify_encoded_password(password, account["password_hash"])
                account_id = int(account["account_id"]) if success else None
                self._record_login(username, account_id, success)
                if not success:
                    return None
                access = self._get_account_access(account_id)
                return AccountRecord(account_id, account["display_name"], account["username"], access["roles"], access["permissions"])
            rows = self._run_mysql(f"SELECT account_id, display_name, username, password_hash, password_salt FROM accounts WHERE username = '{self._escape_sql(username)}' LIMIT 1;", True, ["account_id", "display_name", "username", "password_hash", "password_salt"])
            account = rows[0] if rows else None
        else:
            with self._connect_sqlite() as connection:
                row = connection.execute("SELECT id AS account_id, display_name, username, password_hash, password_salt FROM accounts WHERE username = ? LIMIT 1", (username,)).fetchone()
                account = dict(row) if row else None
        success = bool(account) and hmac.compare_digest(self._hash_password(password, account["password_salt"]), account["password_hash"])
        account_id = int(account["account_id"]) if success else None
        self._record_login(username, account_id, success)
        return AccountRecord(account_id, account["display_name"], account["username"], ("local_admin",), frozenset({"*"})) if success else None

    def set_current_account(self, account: AccountRecord) -> None:
        self.current_account = account
        self.current_account_id = account.id

    def clear_current_account(self) -> None:
        self.current_account = None
        self.current_account_id = None

    def has_permission(self, permission: str) -> bool:
        account = self.current_account
        if account is None or self.current_account_id is None:
            return False
        managed_mysql = (
            self.backend == "mysql" and self.database.lower() == "mydatabase"
        )
        if not managed_mysql:
            if FULL_ACCESS in account.permissions:
                return True
            return permission in account.permissions

        status_rows = self._run_mysql(
            f"SELECT account_status FROM users WHERE user_id = {int(account.id)} LIMIT 1;",
            True,
            ["account_status"],
        )
        if not status_rows or status_rows[0]["account_status"] != "active":
            return False
        return (
            FULL_ACCESS in account.permissions
            or permission in account.permissions
        )

    def require_permissions(self, *permissions: str, require_all: bool = True) -> None:
        if not permissions:
            return
        decisions = [self.has_permission(permission) for permission in permissions]
        allowed = all(decisions) if require_all else any(decisions)
        if allowed:
            return

        permission_text = ", ".join(permissions)
        self._record_authorization_denial(permission_text)
        raise AuthorizationError(
            "This account is not permitted to perform that action. "
            "Ask an administrator to review the assigned role."
        )

    def _record_authorization_denial(self, permission_text: str) -> None:
        if (
            self.backend != "mysql"
            or self.database.lower() != "mydatabase"
            or self.current_account_id is None
        ):
            return
        try:
            self._run_mysql(
                f"""
                INSERT INTO audit_logs
                    (user_id, action, entity_type, description, device_information, created_at)
                VALUES
                    ({int(self.current_account_id)}, 'ACCESS_DENIED', 'authorization',
                     'Denied permission check: {self._escape_sql(permission_text)}.',
                     'BioAccess Desktop App', UTC_TIMESTAMP());
                """
            )
        except RuntimeError:
            pass

    def _get_account_access(self, account_id: int) -> dict:
        rows = self._run_mysql(f"""
            SELECT GROUP_CONCAT(DISTINCT r.role_name ORDER BY r.role_name),
                   GROUP_CONCAT(DISTINCT p.permission_name ORDER BY p.permission_name)
            FROM users u
            LEFT JOIN user_roles ur ON ur.user_id = u.user_id
            LEFT JOIN roles r ON r.role_id = ur.role_id
            LEFT JOIN role_permissions rp ON rp.role_id = r.role_id
            LEFT JOIN permissions p ON p.permission_id = rp.permission_id
            WHERE u.user_id = {int(account_id)} GROUP BY u.user_id;
        """, True, ["roles", "permissions"])
        if not rows:
            return {"roles": (), "permissions": frozenset()}
        roles_value = rows[0].get("roles") or ""
        permissions_value = rows[0].get("permissions") or ""
        return {
            "roles": tuple(filter(None, roles_value.split(","))),
            "permissions": frozenset(filter(None, permissions_value.split(","))),
        }

    def get_available_roles(self) -> list[dict]:
        self.require_permissions(MANAGE_ACCOUNTS)
        if self.backend != "mysql" or self.database.lower() != "mydatabase":
            return [{"name": "local_admin", "label": "Local Administrator"}]
        rows = self._run_mysql(
            """
            SELECT role_name, description
            FROM roles
            WHERE role_name NOT IN ('administrator', 'system_developer')
            ORDER BY CASE role_name
                WHEN 'admin' THEN 1
                WHEN 'registrar' THEN 2
                WHEN 'biometric_officer' THEN 3
                WHEN 'invigilator' THEN 4
                ELSE 5
            END, role_name;
            """,
            True,
            ["name", "description"],
        )
        return [
            {
                "name": row["name"],
                "label": ROLE_LABELS.get(
                    row["name"], row["name"].replace("_", " ").title()
                ),
                "description": row["description"] or "",
            }
            for row in rows
        ]

    def get_operator_accounts(self) -> list[dict]:
        self.require_permissions(MANAGE_ACCOUNTS)
        if self.backend != "mysql" or self.database.lower() != "mydatabase":
            account = self.current_account
            return (
                [
                    {
                        "id": account.id,
                        "username": account.username,
                        "display_name": account.display_name,
                        "status": "active",
                        "failed_login_attempts": 0,
                        "last_login": "",
                        "roles": account.roles,
                        "role_label": "Local Administrator",
                    }
                ]
                if account
                else []
            )
        rows = self._run_mysql(
            """
            SELECT u.user_id, u.username, u.full_name, u.account_status,
                   u.failed_login_attempts, u.last_login,
                   GROUP_CONCAT(DISTINCT r.role_name ORDER BY r.role_name)
            FROM users u
            LEFT JOIN user_roles ur ON ur.user_id = u.user_id
            LEFT JOIN roles r ON r.role_id = ur.role_id
            WHERE u.username IS NOT NULL
            GROUP BY u.user_id, u.username, u.full_name, u.account_status,
                     u.failed_login_attempts, u.last_login
            ORDER BY u.full_name, u.username;
            """,
            True,
            [
                "id",
                "username",
                "display_name",
                "status",
                "failed_login_attempts",
                "last_login",
                "roles",
            ],
        )
        accounts: list[dict] = []
        for row in rows:
            role_names = tuple(filter(None, (row["roles"] or "").split(",")))
            role_labels: list[str] = []
            for role_name in role_names:
                label = ROLE_LABELS.get(
                    role_name, role_name.replace("_", " ").title()
                )
                if label not in role_labels:
                    role_labels.append(label)
            accounts.append(
                {
                    "id": int(row["id"]),
                    "username": row["username"],
                    "display_name": row["display_name"],
                    "status": row["status"],
                    "failed_login_attempts": int(
                        row["failed_login_attempts"] or 0
                    ),
                    "last_login": row["last_login"] or "",
                    "roles": role_names,
                    "role_label": ", ".join(role_labels) or "No role assigned",
                }
            )
        return accounts

    def create_operator_account(
        self,
        display_name: str,
        username: str,
        password: str,
        role_name: str,
    ) -> int:
        self.require_permissions(MANAGE_ACCOUNTS)
        if self.backend != "mysql" or self.database.lower() != "mydatabase":
            raise ValueError(
                "Managed staff accounts require the BioAccess MySQL security database."
            )
        display_name, username = self._validate_account_fields(
            display_name, username, password
        )
        role_name = role_name.strip().lower()
        if not self._managed_role_exists(role_name):
            raise ValueError("Select a valid BioAccess role.")

        salt = secrets.token_hex(16)
        password_hash = self._hash_password(password, salt)
        encoded_hash = f"pbkdf2_sha256$310000${salt}${password_hash}"
        existing = self._run_mysql(
            f"SELECT COUNT(*) FROM users WHERE username = '{self._escape_sql(username)}';",
            True,
            ["total"],
        )
        if existing and int(existing[0]["total"]) > 0:
            raise ValueError("That username is already in use.")

        self._run_mysql(
            f"""
            INSERT INTO users
                (username, password_hash, full_name, account_status,
                 failed_login_attempts, created_at)
            VALUES
                ('{self._escape_sql(username)}', '{encoded_hash}',
                 '{self._escape_sql(display_name)}', 'active', 0, UTC_TIMESTAMP());
            INSERT INTO user_roles (user_id, role_id)
            SELECT u.user_id, r.role_id
            FROM users u
            JOIN roles r ON r.role_name = '{self._escape_sql(role_name)}'
            WHERE u.username = '{self._escape_sql(username)}';
            INSERT INTO audit_logs
                (user_id, action, entity_type, description, device_information, created_at)
            VALUES
                ({int(self.current_account_id)}, 'ACCOUNT_CREATED', 'user',
                 'Created staff account {self._escape_sql(username)} with role {self._escape_sql(role_name)}.',
                 'BioAccess Desktop App', UTC_TIMESTAMP());
            """
        )
        rows = self._run_mysql(
            f"SELECT user_id FROM users WHERE username = '{self._escape_sql(username)}' LIMIT 1;",
            True,
            ["user_id"],
        )
        return int(rows[0]["user_id"])

    def replace_operator_role(self, account_id: int, role_name: str) -> None:
        self.require_permissions(MANAGE_ACCOUNTS)
        account_id = int(account_id)
        role_name = role_name.strip().lower()
        if account_id == self.current_account_id:
            raise ValueError(
                "For safety, you cannot change your own role while signed in."
            )
        if not self._managed_role_exists(role_name):
            raise ValueError("Select a valid BioAccess role.")
        if self._is_last_active_administrator(account_id) and role_name not in {
            "admin",
            "administrator",
        }:
            raise ValueError(
                "The last active administrator cannot be changed to a non-administrator role."
            )
        self._run_mysql(
            f"""
            DELETE FROM user_roles WHERE user_id = {account_id};
            INSERT INTO user_roles (user_id, role_id)
            SELECT {account_id}, role_id FROM roles
            WHERE role_name = '{self._escape_sql(role_name)}';
            INSERT INTO audit_logs
                (user_id, action, entity_type, description, device_information, created_at)
            VALUES
                ({int(self.current_account_id)}, 'ROLE_CHANGED', 'authorization',
                 'Assigned role {self._escape_sql(role_name)} to staff account ID {account_id}.',
                 'BioAccess Desktop App', UTC_TIMESTAMP());
            """
        )

    def set_operator_status(self, account_id: int, status: str) -> None:
        self.require_permissions(MANAGE_ACCOUNTS)
        account_id = int(account_id)
        status = status.strip().lower()
        if status not in {"active", "disabled"}:
            raise ValueError("Account status must be active or disabled.")
        if account_id == self.current_account_id:
            raise ValueError(
                "For safety, you cannot disable or unlock your own signed-in account."
            )
        if status != "active" and self._is_last_active_administrator(account_id):
            raise ValueError("The last active administrator cannot be disabled.")
        self._run_mysql(
            f"""
            UPDATE users
            SET account_status = '{status}',
                failed_login_attempts = CASE WHEN '{status}' = 'active' THEN 0
                                             ELSE failed_login_attempts END
            WHERE user_id = {account_id};
            INSERT INTO audit_logs
                (user_id, action, entity_type, description, device_information, created_at)
            VALUES
                ({int(self.current_account_id)}, 'ACCOUNT_STATUS_CHANGED', 'user',
                 'Changed staff account ID {account_id} to {status}.',
                 'BioAccess Desktop App', UTC_TIMESTAMP());
            """
        )

    def _managed_role_exists(self, role_name: str) -> bool:
        if self.backend != "mysql" or self.database.lower() != "mydatabase":
            return role_name == "local_admin"
        rows = self._run_mysql(
            f"SELECT COUNT(*) FROM roles WHERE role_name = '{self._escape_sql(role_name)}';",
            True,
            ["total"],
        )
        return bool(rows) and int(rows[0]["total"]) == 1

    def _is_last_active_administrator(self, account_id: int) -> bool:
        rows = self._run_mysql(
            f"""
            SELECT
                EXISTS(
                    SELECT 1 FROM user_roles ur
                    JOIN roles r ON r.role_id = ur.role_id
                    WHERE ur.user_id = {int(account_id)}
                      AND r.role_name IN ('admin', 'administrator')
                ),
                (
                    SELECT COUNT(DISTINCT u.user_id)
                    FROM users u
                    JOIN user_roles ur ON ur.user_id = u.user_id
                    JOIN roles r ON r.role_id = ur.role_id
                    WHERE u.account_status = 'active'
                      AND r.role_name IN ('admin', 'administrator')
                );
            """,
            True,
            ["is_admin", "active_admin_count"],
        )
        return bool(rows) and int(rows[0]["is_admin"]) == 1 and int(
            rows[0]["active_admin_count"]
        ) <= 1

    @staticmethod
    def _validate_account_fields(
        display_name: str, username: str, password: str
    ) -> tuple[str, str]:
        display_name = display_name.strip()
        username = username.strip().lower()
        if not display_name or not username:
            raise ValueError("Full name and username are required.")
        if len(username) < 3:
            raise ValueError("Username must contain at least 3 characters.")
        if len(password) < 12:
            raise ValueError("Password must contain at least 12 characters.")
        if not all(
            (
                any(c.islower() for c in password),
                any(c.isupper() for c in password),
                any(c.isdigit() for c in password),
                any(not c.isalnum() for c in password),
            )
        ):
            raise ValueError(
                "Password must include uppercase, lowercase, number, and symbol characters."
            )
        return display_name, username

    def _record_login(self, username: str, account_id: int | None, success: bool) -> None:
        now = datetime.utcnow()
        if self.backend == "mysql":
            if self.database.lower() == "mydatabase":
                account_sql = "NULL" if account_id is None else str(account_id)
                if success:
                    account_update = f"UPDATE users SET failed_login_attempts = 0, last_login = '{now.strftime('%Y-%m-%d %H:%M:%S')}' WHERE user_id = {account_id};"
                else:
                    account_update = f"""
                        UPDATE users
                        SET failed_login_attempts = failed_login_attempts + 1,
                            account_status = CASE WHEN failed_login_attempts + 1 >= 5 THEN 'locked' ELSE account_status END
                        WHERE username = '{self._escape_sql(username)}';
                    """
                self._run_mysql(f"""
                    INSERT INTO audit_logs (user_id, action, entity_type, description, device_information, created_at)
                    VALUES ({account_sql}, '{'LOGIN_SUCCESS' if success else 'LOGIN_FAILED'}', 'authentication',
                            'Login {'succeeded' if success else 'failed'} for username {self._escape_sql(username)}.',
                            'BioAccess Desktop App', '{now.strftime('%Y-%m-%d %H:%M:%S')}');
                    {account_update}
                """)
                return
            account_sql = "NULL" if account_id is None else str(account_id)
            update_sql = f"UPDATE accounts SET last_login_at = '{now.strftime('%Y-%m-%d %H:%M:%S')}' WHERE account_id = {account_id};" if success else ""
            self._run_mysql(f"INSERT INTO login_logs (account_id, username_attempted, status, login_time) VALUES ({account_sql}, '{self._escape_sql(username)}', '{'SUCCESS' if success else 'FAILED'}', '{now.strftime('%Y-%m-%d %H:%M:%S')}'); {update_sql}")
            return
        with self._connect_sqlite() as connection:
            connection.execute("INSERT INTO login_logs (account_id, username_attempted, status, login_time) VALUES (?, ?, ?, ?)", (account_id, username, "SUCCESS" if success else "FAILED", now.isoformat()))
            if success:
                connection.execute("UPDATE accounts SET last_login_at = ? WHERE id = ?", (now.isoformat(), account_id))
            connection.commit()

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 310_000).hex()

    @classmethod
    def _verify_encoded_password(cls, password: str, encoded: str) -> bool:
        try:
            algorithm, iterations, salt, expected = encoded.split("$", 3)
            if algorithm != "pbkdf2_sha256":
                return False
            actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations)).hex()
            return hmac.compare_digest(actual, expected)
        except (ValueError, TypeError):
            return False

    def add_user(
        self,
        full_name: str,
        student_id: str,
        face_embedding: dict | list[float] | None,
        fingerprint_template: bytes | None,
        programme: str = "Not specified",
        department: str | None = None,
        level: str | None = None,
        email: str | None = None,
        phone: str | None = None,
    ) -> int:
        self.require_permissions(REGISTER_STUDENTS, ENROL_BIOMETRICS)
        if not full_name or not full_name.strip():
            raise ValueError("Full name cannot be empty")
        if not student_id or not student_id.strip():
            raise ValueError("Student ID cannot be empty")

        student_id = student_id.strip()
        full_name = full_name.strip()
        programme = programme.strip()
        if not programme:
            raise ValueError("Programme cannot be empty")
        department = department.strip() if department else None
        level = level.strip() if level else None
        email = email.strip().lower() if email else None
        phone = phone.strip() if phone else None

        if self._student_id_exists(student_id):
            raise ValueError(f"Student ID '{student_id}' is already registered. Please use a different ID.")

        created_at = datetime.utcnow()
        encrypted_embedding = (
            self.encryption_service.encrypt_json(face_embedding) if face_embedding else None
        )
        encrypted_template = (
            self.encryption_service.encrypt_bytes(fingerprint_template)
            if fingerprint_template
            else None
        )

        if self.backend == "mysql":
            if self.database.lower() == "mydatabase":
                name_parts = full_name.split(maxsplit=1)
                first_name = name_parts[0]
                last_name = name_parts[1] if len(name_parts) > 1 else "-"
                embedding_sql = f"UNHEX('{encrypted_embedding.hex()}')" if encrypted_embedding is not None else "NULL"
                template_sql = f"UNHEX('{encrypted_template.hex()}')" if encrypted_template is not None else "NULL"
                actor_sql = "NULL" if self.current_account_id is None else str(self.current_account_id)
                fingerprint_quality_sql = "NULL"
                fingerprint_algorithm_sql = "NULL"
                if fingerprint_template:
                    try:
                        fingerprint_metadata = json.loads(fingerprint_template.decode("utf-8"))
                        quality_value = float(fingerprint_metadata.get("quality_score", 0))
                        quality_percent = (
                            quality_value * 10
                            if int(fingerprint_metadata.get("version", 0)) >= 4
                            else quality_value * 100
                        )
                        fingerprint_quality_sql = str(round(quality_percent, 2))
                        algorithm_name = fingerprint_metadata.get(
                            "algorithm",
                            "Futronic FTRAPI minutiae",
                        )
                        algorithm_version = fingerprint_metadata.get("version", 4)
                        fingerprint_algorithm_sql = (
                            f"'{self._escape_sql(str(algorithm_name) + ' v' + str(algorithm_version))}'"
                        )
                    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                        pass
                department_sql = "NULL" if department is None else f"'{self._escape_sql(department)}'"
                level_sql = "NULL" if level is None else f"'{self._escape_sql(level)}'"
                email_sql = "NULL" if email is None else f"'{self._escape_sql(email)}'"
                phone_sql = "NULL" if phone is None else f"'{self._escape_sql(phone)}'"
                self._run_mysql(f"""
                    INSERT INTO students (student_index, first_name, last_name, programme, department, level, email, phone, account_status, created_at)
                    VALUES ('{self._escape_sql(student_id)}', '{self._escape_sql(first_name)}', '{self._escape_sql(last_name)}',
                            '{self._escape_sql(programme)}', {department_sql}, {level_sql}, {email_sql}, {phone_sql},
                            'active', '{created_at.strftime('%Y-%m-%d %H:%M:%S')}');
                    INSERT INTO biometric_data (
                        student_id, fingerprint_template, face_embedding, fingerprint_quality,
                        fingerprint_algorithm, face_algorithm, encryption_algorithm,
                        enrollment_device, enrolled_by, enrollment_status, created_at
                    )
                    SELECT student_id, {template_sql}, {embedding_sql}, {fingerprint_quality_sql},
                           {fingerprint_algorithm_sql}, 'OpenCV SFace v2', 'AES-256-GCM',
                           'Futronic Fingerprint Scanner 2.0', {actor_sql}, 'completed',
                           '{created_at.strftime('%Y-%m-%d %H:%M:%S')}'
                    FROM students WHERE student_index = '{self._escape_sql(student_id)}';
                    INSERT INTO audit_logs (user_id, action, entity_type, entity_id, description, device_information)
                    SELECT {actor_sql}, 'STUDENT_ENROLLED', 'student', student_id,
                           CONCAT('Student enrolled: ', student_index), 'BioAccess Desktop App'
                    FROM students WHERE student_index = '{self._escape_sql(student_id)}';
                """)
                rows = self._run_mysql(f"SELECT student_id FROM students WHERE student_index = '{self._escape_sql(student_id)}' LIMIT 1;", True, ["student_id"])
                return int(rows[0]["student_id"])
            embedding_sql = (
                f"UNHEX('{encrypted_embedding.hex()}')" if encrypted_embedding is not None else "NULL"
            )
            template_sql = (
                f"UNHEX('{encrypted_template.hex()}')" if encrypted_template is not None else "NULL"
            )
            self._run_mysql(
                f"""
                INSERT INTO users (
                    full_name,
                    student_id,
                    department,
                    level,
                    gender,
                    phone,
                    email,
                    face_embedding,
                    fingerprint_template,
                    created_at
                )
                VALUES (
                    '{self._escape_sql(full_name)}',
                    '{self._escape_sql(student_id)}',
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    {embedding_sql},
                    {template_sql},
                    '{created_at.strftime("%Y-%m-%d %H:%M:%S")}'
                );
                """
            )
            rows = self._run_mysql(
                "SELECT LAST_INSERT_ID() AS new_id;",
                capture_output=True,
                headers=["new_id"],
            )
            return int(rows[0]["new_id"])

        with self._connect_sqlite() as connection:
            try:
                cursor = connection.execute(
                    """
                    INSERT INTO users (
                        full_name,
                        student_id,
                        programme,
                        department,
                        level,
                        email,
                        phone,
                        face_embedding,
                        fingerprint_template,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        full_name,
                        student_id,
                        programme,
                        department,
                        level,
                        email,
                        phone,
                        encrypted_embedding,
                        encrypted_template,
                        created_at.isoformat(),
                    ),
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                if "UNIQUE constraint failed" in str(exc):
                    raise ValueError(
                        f"Student ID '{student_id}' is already registered. Please use a different ID."
                    )
                raise
        return int(cursor.lastrowid)

    def update_user_fingerprint(self, user_id: int, fingerprint_template: bytes) -> None:
        self.require_permissions(ENROL_BIOMETRICS)
        if fingerprint_template is None:
            raise ValueError("Fingerprint template cannot be empty.")

        encrypted_template = self.encryption_service.encrypt_bytes(fingerprint_template)
        fingerprint_quality_sql = "NULL"
        fingerprint_algorithm_sql = "NULL"
        try:
            fingerprint_metadata = json.loads(fingerprint_template.decode("utf-8"))
            quality_value = float(fingerprint_metadata.get("quality_score", 0))
            quality_percent = (
                quality_value * 10
                if int(fingerprint_metadata.get("version", 0)) >= 4
                else quality_value * 100
            )
            fingerprint_quality_sql = str(round(quality_percent, 2))
            algorithm_name = fingerprint_metadata.get(
                "algorithm",
                "Futronic FTRAPI minutiae",
            )
            algorithm_version = fingerprint_metadata.get("version", 4)
            fingerprint_algorithm_sql = (
                f"'{self._escape_sql(str(algorithm_name) + ' v' + str(algorithm_version))}'"
            )
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            pass

        if self.backend == "mysql":
            if self.database.lower() == "mydatabase":
                actor_sql = "NULL" if self.current_account_id is None else str(self.current_account_id)
                self._run_mysql(f"""
                    UPDATE biometric_data
                    SET fingerprint_template = UNHEX('{encrypted_template.hex()}'),
                        fingerprint_quality = {fingerprint_quality_sql},
                        fingerprint_algorithm = {fingerprint_algorithm_sql},
                        enrollment_status = 'completed',
                        updated_by = {actor_sql}
                    WHERE student_id = {int(user_id)};
                    INSERT INTO audit_logs (user_id, action, entity_type, entity_id, description, device_information)
                    VALUES ({actor_sql}, 'FINGERPRINT_REENROLLED', 'student', {int(user_id)},
                            'Fingerprint template re-enrolled using official Futronic FTRAPI minutiae matching.', 'BioAccess Desktop App');
                """)
                return
            self._run_mysql(
                f"""
                UPDATE users
                SET fingerprint_template = UNHEX('{encrypted_template.hex()}')
                WHERE user_id = {int(user_id)};
                """
            )
            return

        with self._connect_sqlite() as connection:
            cursor = connection.execute(
                "UPDATE users SET fingerprint_template = ? WHERE id = ?",
                (encrypted_template, user_id),
            )
            if cursor.rowcount == 0:
                raise ValueError("The selected user could not be found.")
            connection.commit()

    def update_user_face(self, user_id: int, face_embedding: dict | list[float]) -> None:
        self.require_permissions(ENROL_BIOMETRICS)
        if not face_embedding:
            raise ValueError("Face template cannot be empty.")

        encrypted_embedding = self.encryption_service.encrypt_json(face_embedding)

        if self.backend == "mysql":
            if self.database.lower() == "mydatabase":
                actor_sql = "NULL" if self.current_account_id is None else str(self.current_account_id)
                self._run_mysql(f"""
                    UPDATE biometric_data
                    SET face_embedding = UNHEX('{encrypted_embedding.hex()}'),
                        face_algorithm = 'OpenCV SFace v2',
                        enrollment_status = CASE
                            WHEN fingerprint_template IS NULL THEN enrollment_status
                            ELSE 'completed'
                        END,
                        updated_by = {actor_sql}
                    WHERE student_id = {int(user_id)};
                    INSERT INTO audit_logs (user_id, action, entity_type, entity_id, description, device_information)
                    VALUES ({actor_sql}, 'FACE_REENROLLED', 'student', {int(user_id)},
                            'Face template re-enrolled using webcam capture.', 'BioAccess Desktop App');
                """)
                return
            self._run_mysql(
                f"""
                UPDATE users
                SET face_embedding = UNHEX('{encrypted_embedding.hex()}')
                WHERE user_id = {int(user_id)};
                """
            )
            return

        with self._connect_sqlite() as connection:
            cursor = connection.execute(
                "UPDATE users SET face_embedding = ? WHERE id = ?",
                (encrypted_embedding, user_id),
            )
            if cursor.rowcount == 0:
                raise ValueError("The selected user could not be found.")
            connection.commit()

    def _student_id_exists(self, student_id: str) -> bool:
        if self.backend == "mysql":
            table = "students" if self.database.lower() == "mydatabase" else "users"
            column = "student_index" if self.database.lower() == "mydatabase" else "student_id"
            rows = self._run_mysql(
                f"""
                SELECT COUNT(*) AS total
                FROM {table}
                WHERE {column} = '{self._escape_sql(student_id)}';
                """,
                capture_output=True,
                headers=["total"],
            )
            return int(rows[0]["total"]) > 0 if rows else False

        with self._connect_sqlite() as connection:
            row = connection.execute(
                "SELECT COUNT(*) as count FROM users WHERE student_id = ?",
                (student_id,),
            ).fetchone()
            return row["count"] > 0 if row else False

    def get_users(self) -> list[UserRecord]:
        if self.backend == "mysql":
            if self.database.lower() == "mydatabase":
                rows = self._run_mysql(
                    "SELECT student_id, CONCAT(first_name, ' ', last_name), student_index, created_at FROM students WHERE account_status = 'active' ORDER BY first_name, last_name;",
                    True,
                    ["record_id", "full_name", "student_id", "created_at"],
                )
                return [UserRecord(id=int(row["record_id"]), full_name=row["full_name"], student_id=row["student_id"], created_at=self._parse_mysql_datetime(row["created_at"])) for row in rows]
            rows = self._run_mysql(
                """
                SELECT user_id AS record_id, full_name, student_id, created_at
                FROM users
                ORDER BY full_name ASC;
                """,
                capture_output=True,
                headers=["record_id", "full_name", "student_id", "created_at"],
            )
            return [
                UserRecord(
                    id=int(row["record_id"]),
                    full_name=row["full_name"],
                    student_id=row["student_id"],
                    created_at=self._parse_mysql_datetime(row["created_at"]),
                )
                for row in rows
            ]

        with self._connect_sqlite() as connection:
            rows = connection.execute(
                """
                SELECT id, full_name, student_id, created_at
                FROM users
                ORDER BY full_name ASC
                """
            ).fetchall()

        return [
            UserRecord(
                id=row["id"],
                full_name=row["full_name"],
                student_id=row["student_id"],
                created_at=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]

    def get_verification_log_count(self) -> int:
        if self.backend == "mysql":
            rows = self._run_mysql(
                "SELECT COUNT(*) AS total FROM verification_logs;",
                capture_output=True,
                headers=["total"],
            )
            return int(rows[0]["total"]) if rows else 0

        with self._connect_sqlite() as connection:
            row = connection.execute("SELECT COUNT(*) AS total FROM verification_logs").fetchone()
        return int(row["total"]) if row else 0

    def get_inside_count(self) -> int:
        if self.backend == "mysql":
            try:
                rows = self._run_mysql(
                    """
                    SELECT COUNT(*) AS total
                    FROM access_events latest
                    INNER JOIN (
                        SELECT student_id, MAX(event_id) AS latest_event_id
                        FROM access_events
                        WHERE access_status = 'SUCCESS'
                          AND student_id IS NOT NULL
                        GROUP BY student_id
                    ) grouped ON grouped.latest_event_id = latest.event_id
                    WHERE latest.access_type = 'ENTRY';
                    """,
                    capture_output=True,
                    headers=["total"],
                )
            except RuntimeError:
                return 0
            return int(rows[0]["total"]) if rows else 0

        with self._connect_sqlite() as connection:
            self._ensure_sqlite_access_event_storage(connection)
            row = connection.execute(
                """
                SELECT COUNT(*) AS total
                FROM access_events latest
                INNER JOIN (
                    SELECT student_id, MAX(event_id) AS latest_event_id
                    FROM access_events
                    WHERE access_status = 'SUCCESS'
                      AND student_id IS NOT NULL
                    GROUP BY student_id
                ) grouped ON grouped.latest_event_id = latest.event_id
                WHERE latest.access_type = 'ENTRY'
                """
            ).fetchone()
        return int(row["total"]) if row else 0

    def get_user_biometrics(
        self,
        require_face: bool = True,
        require_fingerprint: bool = True,
    ) -> list[dict]:
        self.require_permissions(VERIFY_STUDENTS)
        if self.backend == "mysql":
            if self.database.lower() == "mydatabase":
                biometric_filters = ["s.account_status = 'active'", "b.enrollment_status = 'completed'"]
                if require_face:
                    biometric_filters.append("b.face_embedding IS NOT NULL")
                if require_fingerprint:
                    biometric_filters.append("b.fingerprint_template IS NOT NULL")
                where_clause = "\n                      AND ".join(biometric_filters)
                rows = self._run_mysql(f"""
                    SELECT s.student_id, CONCAT(s.first_name, ' ', s.last_name), s.student_index,
                           HEX(b.face_embedding), HEX(b.fingerprint_template)
                    FROM students s
                    INNER JOIN biometric_data b ON b.student_id = s.student_id
                    WHERE {where_clause};
                """, True, ["record_id", "full_name", "student_id", "face_embedding_hex", "fingerprint_template_hex"])
                biometrics = []
                for row in rows:
                    face_embedding = self._safe_decrypt_json(
                        self._decode_mysql_hex_blob(row["face_embedding_hex"])
                    )
                    fingerprint_template = self._safe_decrypt_bytes(
                        self._decode_mysql_hex_blob(row["fingerprint_template_hex"])
                    )
                    if require_face and not face_embedding:
                        continue
                    if require_fingerprint and not fingerprint_template:
                        continue
                    biometrics.append(
                        {
                            "id": int(row["record_id"]),
                            "full_name": row["full_name"],
                            "student_id": row["student_id"],
                            "face_embedding": face_embedding,
                            "fingerprint_template": fingerprint_template,
                        }
                    )
                return biometrics
            rows = self._run_mysql(
                """
                SELECT
                    user_id AS record_id,
                    full_name,
                    student_id,
                    HEX(face_embedding) AS face_embedding_hex,
                    HEX(fingerprint_template) AS fingerprint_template_hex
                FROM users;
                """,
                capture_output=True,
                headers=[
                    "record_id",
                    "full_name",
                    "student_id",
                    "face_embedding_hex",
                    "fingerprint_template_hex",
                ],
            )
            biometrics = []
            for row in rows:
                face_bytes = self._decode_mysql_hex_blob(row["face_embedding_hex"])
                fingerprint_bytes = self._decode_mysql_hex_blob(row["fingerprint_template_hex"])
                biometrics.append(
                    {
                        "id": int(row["record_id"]),
                        "full_name": row["full_name"],
                        "student_id": row["student_id"],
                        "face_embedding": self._safe_decrypt_json(face_bytes),
                        "fingerprint_template": self._safe_decrypt_bytes(fingerprint_bytes),
                    }
                )
            return biometrics

        with self._connect_sqlite() as connection:
            rows = connection.execute(
                """
                SELECT id, full_name, student_id, face_embedding, fingerprint_template
                FROM users
                """
            ).fetchall()

        biometrics = []
        for row in rows:
            biometrics.append(
                {
                    "id": row["id"],
                    "full_name": row["full_name"],
                    "student_id": row["student_id"],
                    "face_embedding": self.encryption_service.decrypt_json(row["face_embedding"])
                    if row["face_embedding"]
                    else None,
                    "fingerprint_template": self.encryption_service.decrypt_bytes(
                        row["fingerprint_template"]
                    )
                    if row["fingerprint_template"]
                    else None,
                }
            )
        return biometrics

    def delete_user(self, user_id: int) -> None:
        self.require_permissions(MANAGE_STUDENTS)
        user_snapshot = self._get_user_identity(user_id)
        if user_snapshot is None:
            raise ValueError("The selected user could not be found.")

        if self.backend == "mysql":
            if self.database.lower() == "mydatabase":
                actor_sql = "NULL" if self.current_account_id is None else str(self.current_account_id)
                self._run_mysql(f"""
                    UPDATE students SET account_status = 'inactive' WHERE student_id = {int(user_id)};
                    UPDATE biometric_data
                    SET fingerprint_template = NULL,
                        face_embedding = NULL,
                        fingerprint_quality = NULL,
                        enrollment_status = 'deactivated',
                        updated_by = {actor_sql}
                    WHERE student_id = {int(user_id)};
                    INSERT INTO audit_logs (user_id, action, entity_type, entity_id, description, device_information)
                    VALUES ({actor_sql}, 'STUDENT_DEACTIVATED', 'student', {int(user_id)},
                            'Student record deactivated; active biometric templates removed. Historical verification, access, and audit records retained.', 'BioAccess Desktop App');
                """)
                return
            self._run_mysql(
                f"""
                UPDATE verification_logs
                SET
                    subject_name = COALESCE(subject_name, '{self._escape_sql(user_snapshot["full_name"])}'),
                    subject_student_id = COALESCE(subject_student_id, '{self._escape_sql(user_snapshot["student_id"])}')
                WHERE user_id = {int(user_id)};

                INSERT INTO verification_logs (
                    user_id,
                    subject_name,
                    subject_student_id,
                    event_type,
                    verification_mode,
                    fingerprint_status,
                    face_status,
                    final_status,
                    device_name,
                    location,
                    remarks,
                    verification_time
                )
                VALUES (
                    {int(user_id)},
                    '{self._escape_sql(user_snapshot["full_name"])}',
                    '{self._escape_sql(user_snapshot["student_id"])}',
                    'USER_DELETED',
                    'ADMIN',
                    'NOT_USED',
                    'NOT_USED',
                    'SUCCESS',
                    'Biometric Desktop App',
                    'Admin Console',
                    'User record deleted by administrator. Historical logs preserved.',
                    '{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")}'
                );

                DELETE FROM users
                WHERE user_id = {int(user_id)};
                """
            )
            return

        with self._connect_sqlite() as connection:
            connection.execute(
                """
                UPDATE verification_logs
                SET
                    subject_name = COALESCE(subject_name, ?),
                    subject_student_id = COALESCE(subject_student_id, ?)
                WHERE user_id = ?
                """,
                (user_snapshot["full_name"], user_snapshot["student_id"], user_id),
            )
            connection.execute(
                """
                INSERT INTO verification_logs (
                    user_id, subject_name, subject_student_id, event_type, method, status, details, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    user_snapshot["full_name"],
                    user_snapshot["student_id"],
                    "USER_DELETED",
                    "ADMIN",
                    "SUCCESS",
                    "User record deleted by administrator. Historical logs preserved.",
                    datetime.utcnow().isoformat(),
                ),
            )
            connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
            connection.commit()

    @staticmethod
    def _decode_mysql_hex_blob(value: str | None) -> bytes | None:
        if value is None:
            return None

        normalized = value.strip()
        if not normalized or normalized.upper() == "NULL":
            return None

        try:
            return bytes.fromhex(normalized)
        except ValueError:
            return None

    def _safe_decrypt_json(self, payload: bytes | None) -> list[float] | None:
        if not payload:
            return None

        try:
            return self.encryption_service.decrypt_json(payload)
        except Exception:
            return None

    def _safe_decrypt_bytes(self, payload: bytes | None) -> bytes | None:
        if not payload:
            return None

        try:
            return self.encryption_service.decrypt_bytes(payload)
        except Exception:
            return None

    def _ensure_access_event_storage(self) -> None:
        if self.backend != "mysql":
            return

        rows = self._run_mysql(
            f"""
            SELECT COUNT(*) AS total
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = '{self._escape_sql(self.database)}'
              AND TABLE_NAME = 'access_events';
            """,
            capture_output=True,
            headers=["total"],
        )
        if not rows or int(rows[0]["total"]) == 0:
            raise RuntimeError(
                "The access_events table is missing. Run sql/setup_access_events.sql once using the MySQL root/admin account."
            )

    def _ensure_sqlite_access_event_storage(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS access_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NULL,
                subject_name TEXT NULL,
                subject_student_id TEXT NULL,
                access_type TEXT NOT NULL,
                biometric_status TEXT NOT NULL,
                access_status TEXT NOT NULL,
                remarks TEXT NULL,
                device_name TEXT NULL,
                location TEXT NULL,
                verified_by INTEGER NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.commit()

    def record_access_event(
        self,
        access_type: str,
        biometric_success: bool,
        matched_user_id: int | None,
        details: str,
    ) -> tuple[bool, str]:
        self.require_permissions(VERIFY_STUDENTS)
        access_type = access_type.upper().strip()
        if access_type not in {"ENTRY", "EXIT"}:
            raise ValueError("Access type must be ENTRY or EXIT.")

        if self.backend == "mysql":
            try:
                self._ensure_access_event_storage()
            except RuntimeError as exc:
                return False, f"Entry/Exit logging is not ready: {exc}"

        identity = self._get_user_identity(matched_user_id) if matched_user_id is not None else None
        subject_name = identity["full_name"] if identity else None
        subject_student_id = identity["student_id"] if identity else None
        user_id = int(identity["user_id"]) if identity else None

        access_success = False
        if not biometric_success or user_id is None:
            message = "Access denied because biometric verification did not confirm a registered identity."
        else:
            current_state = self._get_current_access_state(user_id)
            if access_type == "ENTRY" and current_state == "INSIDE":
                message = f"Entry denied for {subject_name}; this student is already marked inside."
            elif access_type == "EXIT" and current_state != "INSIDE":
                message = f"Exit denied for {subject_name}; no successful entry is currently open."
            else:
                access_success = True
                message = (
                    f"Entry recorded for {subject_name}."
                    if access_type == "ENTRY"
                    else f"Exit recorded for {subject_name}."
                )

        self._insert_access_event(
            user_id=user_id,
            subject_name=subject_name,
            subject_student_id=subject_student_id,
            access_type=access_type,
            biometric_status="SUCCESS" if biometric_success else "FAILED",
            access_status="SUCCESS" if access_success else "FAILED",
            remarks=f"{message} {details}".strip(),
        )
        return access_success, message

    def _get_current_access_state(self, user_id: int) -> str:
        if self.backend == "mysql":
            rows = self._run_mysql(
                f"""
                SELECT access_type
                FROM access_events
                WHERE student_id = {int(user_id)}
                  AND access_status = 'SUCCESS'
                ORDER BY created_at DESC, event_id DESC
                LIMIT 1;
                """,
                capture_output=True,
                headers=["access_type"],
            )
            if not rows:
                return "OUTSIDE"
            return "INSIDE" if rows[0]["access_type"].upper() == "ENTRY" else "OUTSIDE"

        with self._connect_sqlite() as connection:
            row = connection.execute(
                """
                SELECT access_type
                FROM access_events
                WHERE student_id = ?
                  AND access_status = 'SUCCESS'
                ORDER BY created_at DESC, event_id DESC
                LIMIT 1
                """,
                (int(user_id),),
            ).fetchone()
        if row is None:
            return "OUTSIDE"
        return "INSIDE" if str(row["access_type"]).upper() == "ENTRY" else "OUTSIDE"

    def _insert_access_event(
        self,
        user_id: int | None,
        subject_name: str | None,
        subject_student_id: str | None,
        access_type: str,
        biometric_status: str,
        access_status: str,
        remarks: str,
    ) -> None:
        created_at = datetime.utcnow()
        user_id_sql = "NULL" if user_id is None else str(int(user_id))
        subject_name_sql = "NULL" if subject_name is None else f"'{self._escape_sql(subject_name)}'"
        subject_student_id_sql = (
            "NULL" if subject_student_id is None else f"'{self._escape_sql(subject_student_id)}'"
        )
        verified_by_sql = "NULL" if self.current_account_id is None else str(int(self.current_account_id))

        if self.backend == "mysql":
            self._run_mysql(
                f"""
                INSERT INTO access_events (
                    student_id,
                    subject_name,
                    subject_student_id,
                    access_type,
                    biometric_status,
                    access_status,
                    remarks,
                    device_name,
                    location,
                    verified_by,
                    created_at
                )
                VALUES (
                    {user_id_sql},
                    {subject_name_sql},
                    {subject_student_id_sql},
                    '{self._escape_sql(access_type)}',
                    '{self._escape_sql(biometric_status)}',
                    '{self._escape_sql(access_status)}',
                    '{self._escape_sql(remarks)}',
                    'BioAccess Desktop App',
                    'Access Point',
                    {verified_by_sql},
                    '{created_at.strftime("%Y-%m-%d %H:%M:%S")}'
                );
                """
            )
            return

        with self._connect_sqlite() as connection:
            self._ensure_sqlite_access_event_storage(connection)
            connection.execute(
                """
                INSERT INTO access_events (
                    student_id, subject_name, subject_student_id, access_type,
                    biometric_status, access_status, remarks, device_name,
                    location, verified_by, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    subject_name,
                    subject_student_id,
                    access_type,
                    biometric_status,
                    access_status,
                    remarks,
                    "BioAccess Desktop App",
                    "Access Point",
                    self.current_account_id,
                    created_at.isoformat(),
                ),
            )
            connection.commit()

    def log_verification(
        self,
        method: str,
        status: str,
        details: str,
        user_id: int | None = None,
    ) -> None:
        created_at = datetime.utcnow()
        subject_name = None
        subject_student_id = None
        if user_id is not None:
            identity = self._get_user_identity(user_id)
            if identity:
                subject_name = identity["full_name"]
                subject_student_id = identity["student_id"]

        if self.backend == "mysql":
            if self.database.lower() == "mydatabase":
                actor_sql = "NULL" if self.current_account_id is None else str(self.current_account_id)
                entity_sql = "NULL" if user_id is None else str(user_id)
                self._run_mysql(f"""
                    INSERT INTO audit_logs (user_id, action, entity_type, entity_id, description, device_information)
                    VALUES ({actor_sql}, 'BIOMETRIC_VERIFICATION_{self._escape_sql(status)}', 'student', {entity_sql},
                            '{self._escape_sql(method + ': ' + details)}', 'BioAccess Desktop App');
                """)
                return
            verification_mode = "MULTIMODAL" if method == "FACE" else "FINGERPRINT_ONLY"
            face_status = status if method == "FACE" else "NOT_USED"
            fingerprint_status = status if method == "FINGERPRINT" else "NOT_USED"
            user_id_sql = "NULL" if user_id is None else str(user_id)
            subject_name_sql = (
                "NULL" if subject_name is None else f"'{self._escape_sql(subject_name)}'"
            )
            subject_student_id_sql = (
                "NULL" if subject_student_id is None else f"'{self._escape_sql(subject_student_id)}'"
            )
            self._run_mysql(
                f"""
                INSERT INTO verification_logs (
                    user_id,
                    subject_name,
                    subject_student_id,
                    event_type,
                    verification_mode,
                    fingerprint_status,
                    face_status,
                    final_status,
                    device_name,
                    location,
                    remarks,
                    verification_time
                )
                VALUES (
                    {user_id_sql},
                    {subject_name_sql},
                    {subject_student_id_sql},
                    'VERIFICATION',
                    '{self._escape_sql(verification_mode)}',
                    '{self._escape_sql(fingerprint_status)}',
                    '{self._escape_sql(face_status)}',
                    '{self._escape_sql(status)}',
                    'Futronic Fingerprint Scanner 2.0',
                    'Exam Hall',
                    '{self._escape_sql(details)}',
                    '{created_at.strftime("%Y-%m-%d %H:%M:%S")}'
                );
                """
            )
            return

        with self._connect_sqlite() as connection:
            connection.execute(
                """
                INSERT INTO verification_logs (
                    user_id, subject_name, subject_student_id, event_type, method, status, details, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    subject_name,
                    subject_student_id,
                    "VERIFICATION",
                    method,
                    status,
                    details,
                    created_at.isoformat(),
                ),
            )
            connection.commit()

    def record_result(self, method: str, result: VerificationResult) -> None:
        self.require_permissions(VERIFY_STUDENTS)
        self.log_verification(
            method=method,
            status="SUCCESS" if result.success else "FAILED",
            details=result.message,
            user_id=result.matched_user_id,
        )

    def _connect_sqlite(self) -> sqlite3.Connection:
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.sqlite_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_sqlite(self, connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                student_id TEXT NOT NULL UNIQUE,
                programme TEXT NOT NULL DEFAULT 'Not specified',
                department TEXT,
                level TEXT,
                email TEXT UNIQUE,
                phone TEXT,
                face_embedding BLOB,
                fingerprint_template BLOB,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS verification_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                subject_name TEXT,
                subject_student_id TEXT,
                event_type TEXT NOT NULL DEFAULT 'VERIFICATION',
                method TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                display_name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            );
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER,
                username_attempted TEXT NOT NULL,
                status TEXT NOT NULL,
                login_time TEXT NOT NULL
            );
            """
        )

        connection.execute(
            "ALTER TABLE verification_logs ADD COLUMN subject_name TEXT"
        ) if "subject_name" not in self._sqlite_columns(connection, "verification_logs") else None
        connection.execute(
            "ALTER TABLE verification_logs ADD COLUMN subject_student_id TEXT"
        ) if "subject_student_id" not in self._sqlite_columns(connection, "verification_logs") else None
        connection.execute(
            "ALTER TABLE verification_logs ADD COLUMN event_type TEXT NOT NULL DEFAULT 'VERIFICATION'"
        ) if "event_type" not in self._sqlite_columns(connection, "verification_logs") else None
        user_columns = self._sqlite_columns(connection, "users")
        for column_name, definition in (
            ("programme", "TEXT NOT NULL DEFAULT 'Not specified'"),
            ("department", "TEXT"),
            ("level", "TEXT"),
            ("email", "TEXT"),
            ("phone", "TEXT"),
        ):
            if column_name not in user_columns:
                connection.execute(f"ALTER TABLE users ADD COLUMN {column_name} {definition}")
        connection.commit()

    def _get_user_identity(self, user_id: int) -> dict | None:
        if self.backend == "mysql":
            if self.database.lower() == "mydatabase":
                rows = self._run_mysql(f"SELECT student_id, CONCAT(first_name, ' ', last_name), student_index FROM students WHERE student_id = {int(user_id)} LIMIT 1;", True, ["user_id", "full_name", "student_id"])
                if not rows:
                    return None
                return {"user_id": int(rows[0]["user_id"]), "full_name": rows[0]["full_name"], "student_id": rows[0]["student_id"]}
            rows = self._run_mysql(
                f"""
                SELECT user_id, full_name, student_id
                FROM users
                WHERE user_id = {int(user_id)}
                LIMIT 1;
                """,
                capture_output=True,
                headers=["user_id", "full_name", "student_id"],
            )
            if not rows:
                return None
            row = rows[0]
            return {
                "user_id": int(row["user_id"]),
                "full_name": row["full_name"],
                "student_id": row["student_id"],
            }

        with self._connect_sqlite() as connection:
            row = connection.execute(
                "SELECT id, full_name, student_id FROM users WHERE id = ? LIMIT 1",
                (user_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "user_id": int(row["id"]),
            "full_name": row["full_name"],
            "student_id": row["student_id"],
        }

    @staticmethod
    def _sqlite_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
        rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {row["name"] for row in rows}

    def _run_mysql(
        self,
        sql: str,
        capture_output: bool = False,
        headers: list[str] | None = None,
    ) -> list[dict] | None:
        if not Path(self.mysql_executable).exists():
            raise RuntimeError(f"MySQL executable not found at {self.mysql_executable}.")

        args = [
            self.mysql_executable,
            f"-h{self.host}",
            f"-P{self.port}",
            f"-u{self.user}",
        ]
        args.append(f"--ssl-mode={self.mysql_ssl_mode}")
        if self.mysql_ssl_mode in {"VERIFY_CA", "VERIFY_IDENTITY"}:
            if not self.mysql_ssl_ca.exists():
                raise RuntimeError(f"MySQL CA certificate not found at {self.mysql_ssl_ca}.")
            args.append(f"--ssl-ca={self.mysql_ssl_ca}")
        args.extend([
            "--batch",
            "--raw",
        ])
        if capture_output:
            args.append("--skip-column-names")
        args.extend(["-D", self.database])

        mysql_environment = self._mysql_environment()
        mysql_environment["MYSQL_PWD"] = self.password or ""
        try:
            result = subprocess.run(
                args,
                input=sql,
                capture_output=True,
                text=True,
                timeout=30,
                env=mysql_environment,
                cwd=str(Path(self.mysql_executable).parent),
            )
        except OSError as exc:
            message = (
                "MySQL could not start. Windows rejected the database launch request. "
                "Restart BioAccess and try again."
                if getattr(exc, "winerror", None) == 206
                else f"MySQL could not start: {exc}"
            )
            raise RuntimeError(message) from exc
        if result.returncode != 0:
            stderr = result.stderr.strip()
            filtered = "\n".join(
                line for line in stderr.splitlines() if "Using a password on the command line interface can be insecure" not in line
            ).strip()
            raise RuntimeError(filtered or result.stdout.strip() or "MySQL command failed.")

        if not capture_output:
            return None

        lines = [line for line in result.stdout.splitlines() if line.strip()]
        if not lines:
            return []

        if headers is None:
            first_select_line = next(
                (line.strip() for line in sql.splitlines() if line.strip().upper().startswith("SELECT")),
                "",
            )
            select_body = first_select_line[6:].strip().rstrip(";")
            headers = []
            for segment in select_body.split(","):
                segment = segment.strip()
                upper_segment = segment.upper()
                if " AS " in upper_segment:
                    headers.append(segment.rsplit(" AS ", 1)[-1].strip())
                else:
                    headers.append(segment.split(".")[-1].strip())

        rows = []
        for line in lines:
            values = line.split("\t")
            if len(headers) != len(values):
                rows.append({str(index): value for index, value in enumerate(values)})
            else:
                rows.append(dict(zip(headers, values, strict=False)))
        return rows

    def _mysql_environment(self) -> dict[str, str]:
        essential_keys = (
            "SystemRoot",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
            "PROCESSOR_ARCHITECTURE",
            "PROCESSOR_ARCHITEW6432",
        )
        mysql_environment = {
            key: value
            for key in essential_keys
            if (value := os.environ.get(key))
        }

        path_entries = [str(Path(self.mysql_executable).parent)]
        system_root = mysql_environment.get("SystemRoot") or mysql_environment.get("WINDIR")
        if system_root:
            path_entries.extend(
                [
                    str(Path(system_root) / "System32"),
                    str(Path(system_root)),
                    str(Path(system_root) / "System32" / "Wbem"),
                ]
            )
        mysql_environment["PATH"] = os.pathsep.join(path_entries)
        return mysql_environment

    @staticmethod
    def _escape_sql(value: str) -> str:
        return value.replace("\\", "\\\\").replace("'", "\\'")

    @staticmethod
    def _parse_mysql_datetime(value: str) -> datetime:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        raise ValueError(f"Unsupported MySQL datetime format: {value}")
