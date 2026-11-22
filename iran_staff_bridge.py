
"""Iran Change: phased manager authentication bridge.

Accept a valid staff Bearer session or the temporary legacy admin key.
This module does not modify bot authentication.
"""

import hmac
import os

from flask import request

from iran_staff_routes import authenticated_manager, login_enabled


def admin_authorized():
    """Authorize a manager using MFA-backed session or legacy key."""

    authorization = request.headers.get("Authorization", "")

    if authorization:
        if not login_enabled():
            return False
        if not authorization.startswith("Bearer "):
            return False
        account, token = authenticated_manager()
        return bool(account and token)

    secret = os.environ.get("IRAN_CHANGE_ADMIN_KEY", "")
    supplied = request.headers.get("X-Admin-Key", "")

    return bool(secret) and hmac.compare_digest(supplied, secret)
