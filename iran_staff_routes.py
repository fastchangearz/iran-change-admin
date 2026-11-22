# ==========================================
# IRAN CHANGE - Staff Authentication
# Manager Bootstrap: ICA1000
# ==========================================

import os
import hmac
import requests

from datetime import datetime, timedelta, timezone
from flask import Blueprint, jsonify, request, current_app

from iran_staff_auth import (
    valid_new_password,
    hash_password,
    new_totp_secret,
    encrypt_mfa_secret,
    decrypt_mfa_secret,
    verify_totp,
)


staff_bp = Blueprint(
    "iran_staff",
    __name__,
    url_prefix="/staff"
)

_db = None
MANAGER_CODE = "ICA1000"


# ==========================================
# Database Connection
# ==========================================

def db():
    if _db is None:
        raise RuntimeError(
            "Staff database unavailable"
        )
    return _db


# ==========================================
# Bootstrap Authorization
# ==========================================

def bootstrap_ok():
    expected = os.environ.get(
        "IRAN_STAFF_BOOTSTRAP_KEY", ""
    )

    supplied = request.headers.get(
        "X-Staff-Bootstrap-Key", ""
    )

    return (
        bool(expected)
        and hmac.compare_digest(
            supplied,
            expected
        )
    )


# ==========================================
# Manager Account
# ==========================================

def manager():
    rows = db()(
        "GET",
        "iran_staff_accounts",
        {
            "select": "*",
            "staff_code": "eq." + MANAGER_CODE,
            "limit": 1,
        }
    )

    return rows[0] if rows else None


def error(message, status):
    return jsonify({
        "error": message
    }), status


# ==========================================
# Safe Error Logging
# ==========================================

def log_staff_error(stage, exc):
    http_status = "unknown"

    if isinstance(exc, requests.HTTPError):
        response = exc.response

        if response is not None:
            http_status = str(
                response.status_code
            )

    current_app.logger.error(
        "STAFF_BOOTSTRAP_%s_FAILED: %s HTTP_STATUS=%s",
        stage,
        type(exc).__name__,
        http_status
    )


# ==========================================
# Staff Status
# ==========================================

@staff_bp.route(
    "/status",
    methods=["GET"]
)
def staff_status():
    return jsonify({
        "service": "Iran Change Staff Authentication",
        "status": "installed",
        "login_enabled": False,
        "manager_code": MANAGER_CODE,
        "version": "stage-2-debug-http"
    })


# ==========================================
# Manager Bootstrap - Start
# ==========================================

@staff_bp.route(
    "/bootstrap/start",
    methods=["POST"]
)
def bootstrap_start():

    if not bootstrap_ok():
        return error("Unauthorized", 401)

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error("Invalid JSON", 400)

    password = data.get("password")

    if not valid_new_password(password):
        return error(
            "Password must contain 12-128 characters, "
            "including letters and numbers",
            400
        )

    stage = "READ_MANAGER"

    try:
        account = manager()

        if not account:
            return error(
                "Manager not found",
                404
            )

        if (
            account.get("is_active")
            or account.get("mfa_enabled")
        ):
            return error(
                "Manager already activated",
                409
            )

        stage = "GENERATE_MFA"

        secret = new_totp_secret()

        stage = "ENCRYPT_MFA"

        encrypted = encrypt_mfa_secret(secret)

        expires = (
            datetime.now(timezone.utc)
            + timedelta(minutes=10)
        ).isoformat()

        stage = "HASH_PASSWORD"

        password_hash = hash_password(password)

        stage = "SAVE_MANAGER"

        updated = db()(
            "PATCH",
            "iran_staff_accounts",
            {
                "staff_code": "eq." + MANAGER_CODE,
                "is_active": "eq.false",
                "mfa_enabled": "eq.false",
            },
            {
                "password_hash": password_hash,
                "mfa_secret_encrypted": encrypted,
                "setup_attempts": 0,
                "setup_expires_at": expires,
            },
            "return=representation"
        )

        if not updated:
            return error(
                "Manager state changed",
                409
            )

        return jsonify({
            "status": "pending_mfa",
            "staff_code": MANAGER_CODE,
            "authenticator_secret": secret,
            "expires_in_seconds": 600,
            "message": (
                "Add the secret to an authenticator "
                "and confirm its six-digit code."
            )
        })

    except (
        requests.RequestException,
        RuntimeError,
        ValueError,
        TypeError
    ) as exc:

        log_staff_error(stage, exc)

        return error(
            "Setup unavailable",
            503
        )


# ==========================================
# Manager Bootstrap - Confirm
# ==========================================

@staff_bp.route(
    "/bootstrap/confirm",
    methods=["POST"]
)
def bootstrap_confirm():

    if not bootstrap_ok():
        return error("Unauthorized", 401)

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error("Invalid JSON", 400)

    code = data.get("code")

    if (
        not isinstance(code, str)
        or len(code) != 6
        or not code.isascii()
        or not code.isdecimal()
    ):
        return error(
            "Invalid code",
            400
        )

    stage = "READ_MANAGER"

    try:
        account = manager()

        if not account:
            return error(
                "Manager not found",
                404
            )

        if (
            account.get("is_active")
            or account.get("mfa_enabled")
        ):
            return error(
                "Manager already activated",
                409
            )

        expires = account.get(
            "setup_expires_at"
        )

        encrypted = account.get(
            "mfa_secret_encrypted"
        )

        attempts = int(
            account.get("setup_attempts") or 0
        )

        if not expires or not encrypted:
            return error(
                "Setup not started",
                409
            )

        stage = "CHECK_EXPIRY"

        expiry = datetime.fromisoformat(
            expires.replace("Z", "+00:00")
        )

        if datetime.now(timezone.utc) >= expiry:
            return error(
                "Setup expired",
                410
            )

        if attempts >= 5:
            return error(
                "Too many attempts",
                429
            )

        stage = "RESERVE_ATTEMPT"

        reserved = db()(
            "PATCH",
            "iran_staff_accounts",
            {
                "staff_code": "eq." + MANAGER_CODE,
                "is_active": "eq.false",
                "mfa_enabled": "eq.false",
                "setup_attempts": "eq." + str(attempts),
                "mfa_secret_encrypted": "eq." + encrypted,
            },
            {
                "setup_attempts": attempts + 1
            },
            "return=representation"
        )

        if not reserved:
            return error(
                "Please retry verification",
                409
            )

        stage = "DECRYPT_MFA"

        secret = decrypt_mfa_secret(
            encrypted
        )

        stage = "VERIFY_MFA"

        if not verify_totp(secret, code):
            return error(
                "Incorrect code",
                401
            )

        stage = "ACTIVATE_MANAGER"

        activated = db()(
            "PATCH",
            "iran_staff_accounts",
            {
                "staff_code": "eq." + MANAGER_CODE,
                "is_active": "eq.false",
                "mfa_enabled": "eq.false",
                "setup_attempts": "eq." + str(
                    attempts + 1
                ),
                "mfa_secret_encrypted": "eq." + encrypted,
            },
            {
                "is_active": True,
                "mfa_enabled": True,
                "setup_expires_at": None,
            },
            "return=representation"
        )

        if not activated:
            return error(
                "Activation conflict",
                409
            )

        return jsonify({
            "status": "activated",
            "staff_code": MANAGER_CODE,
            "mfa_enabled": True,
            "message": "Manager activated"
        })

    except (
        requests.RequestException,
        RuntimeError,
        ValueError,
        TypeError
    ) as exc:

        log_staff_error(stage, exc)

        return error(
            "Verification unavailable",
            503
        )


# ==========================================
# Login - Not Enabled Yet
# ==========================================

@staff_bp.route(
    "/login",
    methods=["POST"]
)
def staff_login():
    return error(
        "Login not enabled yet",
        503
    )


@staff_bp.route(
    "/mfa/verify",
    methods=["POST"]
)
def staff_mfa_verify():
    return error(
        "Login not enabled yet",
        503
    )


@staff_bp.route(
    "/logout",
    methods=["POST"]
)
def staff_logout():
    return error(
        "Login not enabled yet",
        503
    )


@staff_bp.route(
    "/me",
    methods=["GET"]
)
def staff_profile():
    return error(
        "Login not enabled yet",
        503
    )


# ==========================================
# Admin Management - Not Enabled Yet
# ==========================================

@staff_bp.route(
    "/admins",
    methods=["GET", "POST"]
)
def staff_admins():
    return error(
        "Admin management not enabled",
        503
    )


@staff_bp.route(
    "/admins/<staff_code>/permissions",
    methods=["PUT"]
)
def update_staff_permissions(staff_code):
    return error(
        "Not enabled",
        503
    )


@staff_bp.route(
    "/admins/<staff_code>/disable",
    methods=["POST"]
)
def disable_staff_admin(staff_code):
    return error(
        "Not enabled",
        503
    )


# ==========================================
# Install Staff Routes
# ==========================================

def install_staff_routes(app, db_request):
    global _db

    _db = db_request

    if "iran_staff" not in app.blueprints:
        app.register_blueprint(staff_bp)
