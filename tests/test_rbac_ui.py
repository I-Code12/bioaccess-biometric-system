from __future__ import annotations

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from biometric_app.models import AccountRecord
from biometric_app.ui.main_window import MainWindow


class _DatabaseStub:
    def get_users(self) -> list:
        return []

    def get_verification_log_count(self) -> int:
        return 0

    def get_inside_count(self) -> int:
        return 0

    def get_available_roles(self) -> list[dict]:
        return [{"name": "invigilator", "label": "Invigilator"}]

    def get_operator_accounts(self) -> list[dict]:
        return []


class _FingerprintStub:
    def is_sdk_available(self) -> bool:
        return True


class _FaceStub:
    pass


class RoleBasedAccessInterfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.app = QApplication.instance() or QApplication([])

    def test_invigilator_only_receives_verification_navigation(self) -> None:
        account = AccountRecord(
            1,
            "Invigilator",
            "invigilator",
            ("invigilator",),
            frozenset({"verify_students"}),
        )
        window = MainWindow(
            _DatabaseStub(), _FaceStub(), _FingerprintStub(), account
        )
        self.assertTrue(window.sidebar.item(1).isHidden())
        self.assertFalse(window.sidebar.item(2).isHidden())
        self.assertTrue(window.sidebar.item(3).isHidden())
        self.assertTrue(window.dashboard_page.user_table.isHidden())
        window.close()

    def test_administrator_receives_all_navigation(self) -> None:
        account = AccountRecord(
            2,
            "Administrator",
            "admin",
            ("admin",),
            frozenset({"*"}),
        )
        window = MainWindow(
            _DatabaseStub(), _FaceStub(), _FingerprintStub(), account
        )
        for index in (1, 2, 3):
            self.assertFalse(window.sidebar.item(index).isHidden())
        self.assertFalse(window.dashboard_page.user_table.isHidden())
        window.close()


if __name__ == "__main__":
    unittest.main()
