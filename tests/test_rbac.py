from __future__ import annotations

import unittest
from unittest.mock import patch

from biometric_app.models import AccountRecord
from biometric_app.rbac import (
    ENROL_BIOMETRICS,
    MANAGE_ACCOUNTS,
    REGISTER_STUDENTS,
    VERIFY_STUDENTS,
    VIEW_STUDENTS,
    has_all_permissions,
    has_permission,
    role_summary,
)
from biometric_app.services.db_service import DatabaseService


class RoleBasedAccessControlTests(unittest.TestCase):
    def _account(self, role: str, *permissions: str) -> AccountRecord:
        return AccountRecord(
            id=1,
            display_name="Test Operator",
            username="operator",
            roles=(role,),
            permissions=frozenset(permissions),
        )

    def test_administrator_wildcard_allows_every_permission(self) -> None:
        account = self._account("admin", "*")
        for permission in (
            VIEW_STUDENTS,
            VERIFY_STUDENTS,
            REGISTER_STUDENTS,
            ENROL_BIOMETRICS,
            MANAGE_ACCOUNTS,
        ):
            self.assertTrue(has_permission(account, permission))

    def test_invigilator_can_verify_but_cannot_browse_or_enroll(self) -> None:
        account = self._account("invigilator", VERIFY_STUDENTS)
        self.assertTrue(has_permission(account, VERIFY_STUDENTS))
        self.assertFalse(has_permission(account, VIEW_STUDENTS))
        self.assertFalse(has_permission(account, ENROL_BIOMETRICS))
        self.assertFalse(has_permission(account, MANAGE_ACCOUNTS))

    def test_registrar_requires_registration_and_enrollment_permissions(self) -> None:
        account = self._account(
            "registrar",
            VIEW_STUDENTS,
            REGISTER_STUDENTS,
            ENROL_BIOMETRICS,
        )
        self.assertTrue(
            has_all_permissions(
                account, (REGISTER_STUDENTS, ENROL_BIOMETRICS)
            )
        )
        self.assertFalse(has_permission(account, VERIFY_STUDENTS))

    def test_role_summary_uses_user_facing_label(self) -> None:
        account = self._account("biometric_officer", VERIFY_STUDENTS)
        self.assertEqual(role_summary(account), "Biometric Officer")

    def test_managed_session_uses_authenticated_permissions_for_actions(self) -> None:
        account = self._account("system_developer", "*")
        service = DatabaseService(database="mydatabase")
        service.backend = "mysql"
        service.set_current_account(account)
        with patch.object(
            service,
            "_run_mysql",
            return_value=[{"account_status": "active"}],
        ) as mysql_query:
            self.assertTrue(service.has_permission(MANAGE_ACCOUNTS))
        mysql_query.assert_called_once()


if __name__ == "__main__":
    unittest.main()
