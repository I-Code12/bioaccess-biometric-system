from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class UserRecord:
    id: int | None
    full_name: str
    student_id: str
    created_at: datetime | None = None


@dataclass(slots=True)
class VerificationResult:
    success: bool
    message: str
    matched_user_id: int | None = None
    candidate_user_ids: tuple[int, ...] = ()


@dataclass(slots=True)
class AccountRecord:
    id: int
    display_name: str
    username: str
    roles: tuple[str, ...] = ()
    permissions: frozenset[str] = frozenset()
