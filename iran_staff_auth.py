
"""Iran Change - Staff Authentication Core.

No routes or database changes are activated by this file.
"""

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time

from argon2 import PasswordHasher
from argon2 import exceptions as argon_errors


PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2
)

STAFF_CODE_PATTERN = re.compile(r"ICA[0-9]{4,}\Z")


def valid_staff_code(value):
    return (
        isinstance(value, str)
        and STAFF_CODE_PATTERN.fullmatch(value) is not None
    )


def valid_new_password(value):
    return (
        isinstance(value, str)
        and 12 <= len(value) <= 128
        and any(c.isalpha() for c in value)
        and any(c.isdigit() for c in value)
    )


def hash_password(password):
    if not valid_new_password(password):
        raise ValueError(
            "Password must contain 12-128 characters, "
            "including letters and digits"
        )

    return PASSWORD_HASHER.hash(password)


def verify_password(stored_hash, password):
    if not isinstance(stored_hash, str):
        return False

    if not isinstance(password, str):
        return False

    try:
        return bool(
            PASSWORD_HASHER.verify(stored_hash, password)
        )
    except (
        argon_errors.VerificationError,
        ValueError,
        TypeError
    ):
        return False


def new_session_token():
    return secrets.token_urlsafe(48)


def session_token_hash(token):
    if not isinstance(token, str) or not token:
        raise ValueError("Invalid session token")

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def new_totp_secret():
    return base64.b32encode(
        secrets.token_bytes(20)
    ).decode("ascii").rstrip("=")


def verify_totp(secret, submitted_code, now=None):
    if not isinstance(submitted_code, str):
        return False

    if not re.fullmatch(r"[0-9]{6}", submitted_code):
        return False

    if not isinstance(secret, str):
        return False

    try:
        padded = secret.upper() + "=" * (-len(secret) % 8)
        key = base64.b32decode(padded, casefold=True)

        if len(key) < 16:
            return False

    except (ValueError, TypeError, base64.binascii.Error):
        return False

    moment = time.time() if now is None else float(now)
    counter = int(moment // 30)

    for offset in (-1, 0, 1):
        moving = counter + offset

        if moving < 0:
            continue

        digest = hmac.new(
            key,
            struct.pack(">Q", moving),
            hashlib.sha1
        ).digest()

        index = digest[-1] & 15

        number = (
            struct.unpack(
                ">I",
                digest[index:index + 4]
            )[0] & 0x7fffffff
        ) % 1000000

        expected = f"{number:06d}"

        if hmac.compare_digest(expected, submitted_code):
            return True

    return False


# ==========================================
# Encrypted MFA Secret Storage
# ==========================================

import os
from cryptography.fernet import Fernet, InvalidToken


def _mfa_cipher():
    key = os.environ.get("IRAN_STAFF_FERNET_KEY", "")

    if not key:
        raise RuntimeError("MFA encryption key is missing")

    return Fernet(key.encode("ascii"))


def encrypt_mfa_secret(secret):
    if not isinstance(secret, str) or not secret:
        raise ValueError("Invalid MFA secret")

    return _mfa_cipher().encrypt(
        secret.encode("utf-8")
    ).decode("ascii")


def decrypt_mfa_secret(encrypted_secret):
    if not isinstance(encrypted_secret, str):
        raise ValueError("Invalid encrypted MFA secret")

    try:
        return _mfa_cipher().decrypt(
            encrypted_secret.encode("ascii")
        ).decode("utf-8")
    except InvalidToken:
        raise ValueError("MFA decryption failed") from None
