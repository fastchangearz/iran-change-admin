
"""
IRAN CHANGE - Staff Routes
Safe initial installation.

Staff login is disabled until secure provisioning,
MFA encryption and rate limiting are completed.
"""

import os
from flask import Blueprint, jsonify, request


staff_bp = Blueprint(
    "iran_staff",
    __name__,
    url_prefix="/staff"
)


def staff_login_enabled():
    return (
        os.environ.get(
            "IRAN_STAFF_LOGIN_ENABLED", "false"
        ).lower() == "true"
    )


def disabled_response():
    return jsonify({
        "status": "not_ready",
        "message": (
            "Staff authentication is not yet enabled."
        )
    }), 503


@staff_bp.route("/status", methods=["GET"])
def staff_status():
    return jsonify({
        "service": "Iran Change Staff Authentication",
        "status": "installed",
        "login_enabled": False,
        "manager_code": "ICA1000",
        "version": "stage-1"
    })


@staff_bp.route("/login", methods=["POST"])
def staff_login():
    # Fail closed: do not accept credentials yet.
    return disabled_response()


@staff_bp.route("/mfa/verify", methods=["POST"])
def staff_mfa_verify():
    return disabled_response()


@staff_bp.route("/logout", methods=["POST"])
def staff_logout():
    return disabled_response()


@staff_bp.route("/me", methods=["GET"])
def staff_profile():
    return disabled_response()


@staff_bp.route("/admins", methods=["POST"])
def create_staff_admin():
    return disabled_response()


@staff_bp.route("/admins", methods=["GET"])
def list_staff_admins():
    return disabled_response()


@staff_bp.route(
    "/admins/<staff_code>/permissions",
    methods=["PUT"]
)
def update_staff_permissions(staff_code):
    return disabled_response()


@staff_bp.route(
    "/admins/<staff_code>/disable",
    methods=["POST"]
)
def disable_staff_admin(staff_code):
    return disabled_response()


def install_staff_routes(app):
    if "iran_staff" not in app.blueprints:
        app.register_blueprint(staff_bp)
