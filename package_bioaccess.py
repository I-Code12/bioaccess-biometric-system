from __future__ import annotations

import os
import sys
from pathlib import Path


def _app_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


ROOT = _app_root()
VENDORLIBS = ROOT / "vendorlibs"
if VENDORLIBS.exists():
    sys.path.insert(0, str(VENDORLIBS))

from biometric_app.env_loader import load_env_file  # noqa: E402

load_env_file(ROOT)

os.environ.setdefault("MYSQL_HOST", "localhost")
os.environ.setdefault("MYSQL_PORT", "3306")
os.environ.setdefault("MYSQL_USER", "bioaccess_app")
os.environ.setdefault("MYSQL_DATABASE", "mydatabase")
os.environ.setdefault("MYSQL_SSL_MODE", "REQUIRED")
os.environ.setdefault("ALLOW_SQLITE_FALLBACK", "0")
os.environ.setdefault("DOTNET_ROOT_X86", str(ROOT / "tools" / "dotnet-x86"))
os.environ.setdefault("DOTNET_ROOT", str(ROOT / "tools" / "dotnet-x86"))

from PySide6.QtWidgets import QApplication, QInputDialog, QMessageBox  # noqa: E402


def _ensure_mysql_password() -> bool:
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


def main() -> int:
    qt_app = QApplication(sys.argv)
    qt_app.setApplicationName("Biometric Desktop App")

    if not _ensure_mysql_password():
        return 1

    from biometric_app.services.db_service import DatabaseService
    from biometric_app.services.encryption_service import EncryptionService
    from biometric_app.ui.login_page import LoginWindow

    encryption_service = EncryptionService()
    db_service = DatabaseService(encryption_service=encryption_service)
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
        window = MainWindow(
            db_service=db_service,
            face_service=face_service,
            fingerprint_service=fingerprint_service,
            account=account,
        )
        window.setWindowTitle(f"Biometric Desktop App | {account.display_name}")
        windows["main"] = window
        window.show()
        windows["login"].close()

    login_window = LoginWindow(db_service)
    windows["login"] = login_window
    login_window.authenticated.connect(open_main_window)
    login_window.show()

    return qt_app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
