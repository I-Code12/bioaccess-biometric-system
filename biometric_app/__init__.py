"""Biometric desktop app package."""

from __future__ import annotations

import site
import sys


try:
    user_site = site.getusersitepackages()
except Exception:
    user_site = None

if user_site and user_site not in sys.path:
    sys.path.append(user_site)
