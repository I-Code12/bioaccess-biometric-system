from __future__ import annotations

import os
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication, QInputDialog, QMessageBox
from biometric_app.env_loader import load_env_file
from biometric_app.ui.login_page import LoginWindow


load_env_file(Path(__file__).resolve().parents[1])


def create_app() -> QApplication:
    app = QApplication(sys.argv)
    app.setApplicationName("Biometric Desktop App")
    return app


def ensure_mysql_password() -> bool:
    if os.environ.get("MYSQL_PASSWORD"):
        return True

    password, accepted = QInputDialog.getText(
        None,
        "BioAccess Database Login",
        "Enter the MySQL bioaccess_app password:",
        text="",
    )
    if not accepted or not password:
        QMessageBox.warning(
            None,
            "BioAccess",
            "BioAccess cannot open without the database password.",
        )
        return False

    os.environ["MYSQL_PASSWORD"] = password
    return True


def run() -> int:
    qt_app = create_app()
    if not ensure_mysql_password():
        return 1

    from biometric_app.services.db_service import DatabaseService
    from biometric_app.services.encryption_service import EncryptionService

    encryption_service = EncryptionService()
    db_service = DatabaseService(
        password=os.environ.get("MYSQL_PASSWORD", ""),
        encryption_service=encryption_service,
    )
    try:
        db_service.initialize()
    except Exception as exc:
        QMessageBox.critical(
            None,
            "BioAccess Database Error",
            f"BioAccess could not connect to the database.\n\n{exc}",
        )
        return 1

    windows = {}

    def open_main_window(account) -> None:
        from biometric_app.services.face_service import FaceRecognitionService
        from biometric_app.services.fingerprint_service import FingerprintService
        from biometric_app.ui.main_window import MainWindow

        face_service = FaceRecognitionService()
        fingerprint_service = FingerprintService()
        db_service.set_current_account(account)
        window = MainWindow(db_service=db_service, face_service=face_service, fingerprint_service=fingerprint_service, account=account)
        window.setWindowTitle(f"Biometric Desktop App | {account.display_name}")
        windows["main"] = window
        window.show()
        windows["login"].close()

    login_window = LoginWindow(db_service)
    windows["login"] = login_window
    login_window.authenticated.connect(open_main_window)
    login_window.show()

    return qt_app.exec()
