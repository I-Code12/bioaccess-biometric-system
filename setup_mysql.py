#!/usr/bin/env python3
"""
MySQL Database Setup Script for Biometric App
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from biometric_app.config import MYSQL_EXECUTABLE


def setup_mysql_database() -> None:
    host = os.getenv("MYSQL_HOST", "localhost")
    port = int(os.getenv("MYSQL_PORT", "3306"))
    user = os.getenv("MYSQL_USER", "root")
    password = os.getenv("MYSQL_PASSWORD", "")
    database = os.getenv("MYSQL_DATABASE", "fingerprint_system")

    print("MySQL Database Setup for Biometric App")
    print("=" * 40)
    print(f"Host: {host}")
    print(f"Port: {port}")
    print(f"User: {user}")
    print(f"Database: {database}")
    print()

    try:
        create_database = subprocess.run(
            [
                MYSQL_EXECUTABLE,
                f"-h{host}",
                f"-P{port}",
                f"-u{user}",
                f"-p{password}",
                "-e",
                f"CREATE DATABASE IF NOT EXISTS {database};",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if create_database.returncode != 0:
            raise RuntimeError(create_database.stderr.strip() or create_database.stdout.strip())

        print(f"Database '{database}' created or already exists")

        create_tables = subprocess.run(
            [
                MYSQL_EXECUTABLE,
                f"-h{host}",
                f"-P{port}",
                f"-u{user}",
                f"-p{password}",
                "-D",
                database,
                "-e",
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    full_name VARCHAR(255) NOT NULL,
                    student_id VARCHAR(50) NOT NULL UNIQUE,
                    face_embedding LONGBLOB,
                    fingerprint_template LONGBLOB,
                    created_at DATETIME NOT NULL
                );
                CREATE TABLE IF NOT EXISTS verification_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    method VARCHAR(50) NOT NULL,
                    status VARCHAR(20) NOT NULL,
                    details TEXT NOT NULL,
                    created_at DATETIME NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );
                """,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if create_tables.returncode != 0:
            raise RuntimeError(create_tables.stderr.strip() or create_tables.stdout.strip())
        print("Database tables created successfully")
        print()
        print("Setup completed successfully.")
        print("You can now run the biometric application.")
    except Exception as exc:
        print(f"Error setting up database: {exc}")
        print()
        print("Troubleshooting:")
        print("1. Make sure MySQL server is running")
        print("2. Check your MySQL credentials")
        print("3. Confirm mysql.exe exists at the configured MYSQL_EXECUTABLE path")
        print("4. Set environment variables if needed:")
        print("   - MYSQL_HOST")
        print("   - MYSQL_PORT")
        print("   - MYSQL_USER")
        print("   - MYSQL_PASSWORD")
        print("   - MYSQL_DATABASE")
        print("   - MYSQL_EXECUTABLE")
        sys.exit(1)


if __name__ == "__main__":
    setup_mysql_database()
