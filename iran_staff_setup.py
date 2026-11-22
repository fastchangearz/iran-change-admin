
# iran_staff_setup.py
# Iran Change - Secure Manager Provisioning

import os
import secrets
from datetime import datetime, timezone

from iran_staff_auth import (
    valid_new_password,
    hash_password,
    new_totp_secret,
    encrypt_mfa_secret,
    decrypt_mfa_secret,
    verify_totp,
)


MANAGER_CODE = "ICA1000"


def bootstrap_authorized(submitted_token):
    expected = os.environ.get("IRAN_STAFF_BOOTSTRAP_KEY", "")

    if not expected or not isinstance(submitted_token, str):
        return False

    return secrets.compare_digest(submitted_token, expected)


def prepare_manager(password):
    if not valid_new_password(password):
        raise ValueError(
            "Password must be 12-128 characters and include letters and numbers"
        )

    password_hash = hash_password(password)
    totp_secret = new_totp_secret()
    encrypted_secret = encrypt_mfa_secret(totp_secret)

    return {
        "staff_code": MANAGER_CODE,
        "password_hash": password_hash,
        "mfa_secret_encrypted": encrypted_secret,
        "is_active": False,
        "mfa_enabled": False,
        "totp_secret": totp_secret,
    }


def confirm_manager_totp(encrypted_secret, code):
    secret = decrypt_mfa_secret(encrypted_secret)
    return verify_totp(secret, code)
