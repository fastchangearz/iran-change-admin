"""Iran Change manager authentication: password, TOTP and protected recovery."""
import hashlib
import hmac
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

import requests
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from flask import Blueprint, current_app, jsonify, request, send_from_directory

from iran_staff_auth import decrypt_mfa_secret, verify_totp

staff_bp = Blueprint("iran_staff", __name__, url_prefix="/staff")
_db = None
MANAGER_CODE = "ICA1000"
PASSWORD_HASHER = PasswordHasher()
SESSION_TABLE = "iran_staff_auth_sessions"
ATTEMPT_TABLE = "iran_staff_auth_attempts"
# The attempts table only permits 'password' and 'mfa'. A distinct identifier
# keeps recovery attempts separate without changing the existing SQL schema.
RECOVERY_ATTEMPT_CODE = "ICA1000:recovery"


def db():
    if _db is None:
        raise RuntimeError("Staff database unavailable")
    return _db


def now():
    return datetime.now(timezone.utc)


def iso(value):
    return value.isoformat()


def parse_time(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def fail(message, status):
    return jsonify({"error": message}), status


def log_error(stage, exc):
    status = getattr(getattr(exc, "response", None), "status_code", "unknown")
    current_app.logger.error("STAFF_%s_FAILED: %s HTTP_STATUS=%s", stage, type(exc).__name__, status)


def account_by_code(staff_code):
    rows = db()("GET", "iran_staff_accounts", {
        "select": "*", "staff_code": "eq." + staff_code, "limit": 1
    })
    return rows[0] if rows else None


def token_digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def make_session(staff_code, kind, minutes):
    token = secrets.token_urlsafe(48)
    db()("POST", SESSION_TABLE, payload={
        "token_hash": token_digest(token),
        "staff_code": staff_code,
        "kind": kind,
        "expires_at": iso(now() + timedelta(minutes=minutes)),
    }, prefer="return=representation")
    return token


def get_session(token, kind):
    if not isinstance(token, str) or not 40 <= len(token) <= 256:
        return None
    rows = db()("GET", SESSION_TABLE, {
        "select": "*", "token_hash": "eq." + token_digest(token),
        "kind": "eq." + kind, "revoked_at": "is.null", "limit": 1,
    })
    if not rows:
        return None
    expiry = parse_time(rows[0].get("expires_at"))
    return rows[0] if expiry and expiry > now() else None


def revoke_session(token):
    db()("PATCH", SESSION_TABLE, {
        "token_hash": "eq." + token_digest(token), "revoked_at": "is.null"
    }, {"revoked_at": iso(now())}, "return=minimal")


def bearer_token():
    header = request.headers.get("Authorization", "")
    return header[7:].strip() if header.startswith("Bearer ") else None


def authenticated_manager():
    token = bearer_token()
    if not token:
        return None, None
    session = get_session(token, "access")
    if not session or session.get("staff_code") != MANAGER_CODE:
        return None, None
    account = account_by_code(MANAGER_CODE)
    if not account or not account.get("is_active") or not account.get("mfa_enabled"):
        return None, None
    return account, token


def valid_code(code):
    return isinstance(code, str) and bool(re.fullmatch(r"[0-9]{6}", code))


def valid_new_password(password):
    return (
        isinstance(password, str)
        and 12 <= len(password) <= 128
        and not password.isspace()
        and password == password.strip()
        and any(c.isalpha() for c in password)
        and any(c.isdigit() for c in password)
    )


def rate_limit(staff_code, stage, max_attempts, window_minutes):
    cutoff = iso(now() - timedelta(minutes=window_minutes))
    rows = db()("GET", ATTEMPT_TABLE, {
        "select": "id", "staff_code": "eq." + staff_code,
        "stage": "eq." + stage, "created_at": "gte." + cutoff,
        "order": "created_at.desc", "limit": max_attempts,
    })
    return len(rows) >= max_attempts


def record_attempt(staff_code, stage):
    db()("POST", ATTEMPT_TABLE, payload={
        "staff_code": staff_code, "stage": stage,
    }, prefer="return=minimal")


def login_enabled():
    return os.environ.get("IRAN_STAFF_LOGIN_ENABLED", "false").lower() == "true"


@staff_bp.route("/status", methods=["GET"])
def staff_status():
    return jsonify({
        "service": "Iran Change Staff Authentication",
        "status": "installed", "login_enabled": login_enabled(),
        "manager_code": MANAGER_CODE, "version": "stage-4-recovery",
    })


@staff_bp.route("/login", methods=["POST"])
def staff_login():
    if not login_enabled():
        return fail("Login not enabled", 503)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return fail("Invalid JSON", 400)
    staff_code = data.get("staff_code", "")
    password = data.get("password")
    if staff_code != MANAGER_CODE or not isinstance(password, str) or len(password) > 256:
        return fail("Invalid credentials", 401)
    try:
        if rate_limit(MANAGER_CODE, "password", 8, 15):
            return fail("Too many attempts. Try again later", 429)
        account = account_by_code(MANAGER_CODE)
        if not account or not account.get("is_active") or not account.get("mfa_enabled") or not account.get("password_hash"):
            record_attempt(MANAGER_CODE, "password")
            return fail("Invalid credentials", 401)
        try:
            PASSWORD_HASHER.verify(account["password_hash"], password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            record_attempt(MANAGER_CODE, "password")
            return fail("Invalid credentials", 401)
        challenge = make_session(MANAGER_CODE, "challenge", 5)
        return jsonify({"status": "mfa_required", "challenge_token": challenge, "expires_in_seconds": 300})
    except (requests.RequestException, RuntimeError, ValueError, TypeError) as exc:
        log_error("LOGIN", exc)
        return fail("Login unavailable", 503)


@staff_bp.route("/mfa/verify", methods=["POST"])
def staff_mfa_verify():
    if not login_enabled():
        return fail("Login not enabled", 503)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return fail("Invalid JSON", 400)
    code = data.get("code")
    challenge_token = data.get("challenge_token")
    if not valid_code(code) or not isinstance(challenge_token, str):
        return fail("Invalid request", 400)
    try:
        if rate_limit(MANAGER_CODE, "mfa", 8, 15):
            return fail("Too many attempts. Try again later", 429)
        challenge = get_session(challenge_token, "challenge")
        if not challenge or challenge.get("staff_code") != MANAGER_CODE:
            return fail("Challenge expired or invalid", 401)
        account = account_by_code(MANAGER_CODE)
        if not account or not account.get("is_active") or not account.get("mfa_enabled") or not account.get("mfa_secret_encrypted"):
            return fail("Account unavailable", 403)
        secret = decrypt_mfa_secret(account["mfa_secret_encrypted"])
        if not verify_totp(secret, code):
            record_attempt(MANAGER_CODE, "mfa")
            return fail("Incorrect code", 401)
        claimed = db()("PATCH", SESSION_TABLE, {
            "token_hash": "eq." + token_digest(challenge_token),
            "kind": "eq.challenge", "revoked_at": "is.null",
            "expires_at": "gt." + iso(now()),
        }, {"revoked_at": iso(now())}, "return=representation")
        if not claimed:
            return fail("Challenge already used", 409)
        access_token = make_session(MANAGER_CODE, "access", 480)
        db()("PATCH", "iran_staff_accounts", {
            "staff_code": "eq." + MANAGER_CODE,
        }, {"last_login_at": iso(now())}, "return=minimal")
        return jsonify({
            "status": "authenticated", "staff_code": MANAGER_CODE,
            "access_token": access_token, "token_type": "Bearer", "expires_in_seconds": 28800,
        })
    except (requests.RequestException, RuntimeError, ValueError, TypeError) as exc:
        log_error("MFA", exc)
        return fail("Verification unavailable", 503)


@staff_bp.route("/password/recover", methods=["POST"])
def recover_manager_password():
    """Require independent Render recovery key AND current TOTP to reset password."""
    if not login_enabled():
        return fail("Login not enabled", 503)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return fail("Invalid request", 400)
    recovery_key = data.get("recovery_key")
    otp = data.get("code")
    new_password = data.get("new_password")
    if (not isinstance(recovery_key, str) or len(recovery_key) > 256
            or not valid_code(otp) or not valid_new_password(new_password)):
        return fail("Invalid recovery information", 400)
    try:
        if rate_limit(RECOVERY_ATTEMPT_CODE, "password", 5, 15):
            return fail("Too many attempts. Try again later", 429)
        # The existing attempts schema permits the 'password' stage; the
        # separate staff_code prevents recovery failures locking normal login.
        record_attempt(RECOVERY_ATTEMPT_CODE, "password")
        expected = os.environ.get("IRAN_STAFF_RECOVERY_KEY", "")
        if len(expected) < 40 or not hmac.compare_digest(recovery_key, expected):
            return fail("Recovery verification failed", 401)
        account = account_by_code(MANAGER_CODE)
        if not account or not account.get("is_active") or not account.get("mfa_enabled") or not account.get("mfa_secret_encrypted"):
            return fail("Account unavailable", 403)
        secret = decrypt_mfa_secret(account["mfa_secret_encrypted"])
        if not verify_totp(secret, otp):
            return fail("Recovery verification failed", 401)
        updated = db()("PATCH", "iran_staff_accounts", {
            "staff_code": "eq." + MANAGER_CODE, "is_active": "eq.true",
        }, {"password_hash": PASSWORD_HASHER.hash(new_password), "updated_at": iso(now())},
            "return=representation")
        if not updated:
            return fail("Password update failed", 503)
        # Revoke both access tokens and pending challenges.
        db()("PATCH", SESSION_TABLE, {
            "staff_code": "eq." + MANAGER_CODE, "revoked_at": "is.null",
        }, {"revoked_at": iso(now())}, "return=minimal")
        return jsonify({"status": "password_reset", "message": "Password changed successfully"})
    except (requests.RequestException, RuntimeError, ValueError, TypeError) as exc:
        log_error("RECOVERY", exc)
        return fail("Recovery unavailable", 503)


@staff_bp.route("/me", methods=["GET"])
def staff_profile():
    if not login_enabled():
        return fail("Login not enabled", 503)
    try:
        account, _ = authenticated_manager()
        if not account:
            return fail("Unauthorized", 401)
        return jsonify({
            "staff_code": account["staff_code"],
            "full_name": account.get("full_name"),
            "role": account.get("role"),
            "mfa_enabled": account.get("mfa_enabled"),
            "last_login_at": account.get("last_login_at"),
        })
    except (requests.RequestException, RuntimeError, ValueError, TypeError) as exc:
        log_error("PROFILE", exc)
        return fail("Profile unavailable", 503)


@staff_bp.route("/logout", methods=["POST"])
def staff_logout():
    if not login_enabled():
        return fail("Login not enabled", 503)
    try:
        account, token = authenticated_manager()
        if not account:
            return fail("Unauthorized", 401)
        revoke_session(token)
        return jsonify({"status": "logged_out"})
    except (requests.RequestException, RuntimeError, ValueError, TypeError) as exc:
        log_error("LOGOUT", exc)
        return fail("Logout unavailable", 503)


@staff_bp.route("/admins", methods=["GET", "POST"])
def staff_admins():
    return fail("Admin management not enabled", 503)


@staff_bp.route("/admins/<staff_code>/permissions", methods=["PUT"])
def update_staff_permissions(staff_code):
    return fail("Admin management not enabled", 503)


@staff_bp.route("/admins/<staff_code>/disable", methods=["POST"])
def disable_staff_admin(staff_code):
    return fail("Admin management not enabled", 503)


@staff_bp.route("/portal", methods=["GET"])
def staff_portal():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "iran_staff_login.html")


def install_staff_routes(app, db_request):
    global _db
    _db = db_request
    if "iran_staff" not in app.blueprints:
        app.register_blueprint(staff_bp)
