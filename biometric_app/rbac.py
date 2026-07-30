from __future__ import annotations

from collections.abc import Iterable

from biometric_app.models import AccountRecord


FULL_ACCESS = "*"
VIEW_STUDENTS = "view_students"
VERIFY_STUDENTS = "verify_students"
REGISTER_STUDENTS = "register_students"
ENROL_BIOMETRICS = "enrol_biometrics"
MANAGE_STUDENTS = "manage_users"
MANAGE_ACCOUNTS = "manage_accounts"
GENERATE_REPORTS = "generate_reports"
MANAGE_EXAMS = "manage_exams"


ROLE_LABELS = {
    "admin": "Administrator",
    "administrator": "Administrator",
    "registrar": "Registrar",
    "biometric_officer": "Biometric Officer",
    "invigilator": "Invigilator",
    "system_developer": "System Developer",
    "local_admin": "Local Administrator",
}


def has_permission(account: AccountRecord, permission: str) -> bool:
    return FULL_ACCESS in account.permissions or permission in account.permissions


def has_all_permissions(account: AccountRecord, permissions: Iterable[str]) -> bool:
    return all(has_permission(account, permission) for permission in permissions)


def has_any_permission(account: AccountRecord, permissions: Iterable[str]) -> bool:
    return any(has_permission(account, permission) for permission in permissions)


def role_summary(account: AccountRecord) -> str:
    labels: list[str] = []
    for role in account.roles:
        label = ROLE_LABELS.get(role, role.replace("_", " ").title())
        if label not in labels:
            labels.append(label)
    return ", ".join(labels) if labels else "No assigned role"
