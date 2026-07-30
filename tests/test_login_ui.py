from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QFrame, QLineEdit

from biometric_app.ui.login_page import LoginWindow


class _DatabaseStub:
    database = "mydatabase"

    def authenticate(self, username: str, password: str):
        return None


class LoginInterfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_professional_shell_fits_without_clipped_branding(self) -> None:
        window = LoginWindow(_DatabaseStub())
        window.show()
        self.app.processEvents()
        shell = window.findChild(QFrame, "authShell")
        self.assertIsNotNone(shell)
        self.assertLessEqual(shell.width(), window.width())
        self.assertLessEqual(shell.height(), window.height())
        self.assertGreaterEqual(
            window.brand_title.width(),
            window.brand_title.sizeHint().width(),
        )
        window.close()

    def test_password_visibility_toggle(self) -> None:
        window = LoginWindow(_DatabaseStub())
        self.assertEqual(window.login_password.echoMode(), QLineEdit.Password)
        window.password_toggle.setChecked(True)
        self.assertEqual(window.login_password.echoMode(), QLineEdit.Normal)
        self.assertEqual(window.password_toggle.text(), "Hide")
        window.close()


if __name__ == "__main__":
    unittest.main()
