"""Auth primitives (SR6): Argon2 passwords, TOTP MFA, JWT tokens."""
from __future__ import annotations

import datetime as dt

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_ph = PasswordHasher()
_JWT_ALGO = "HS256"


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except VerifyMismatchError:
        return False


def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code (±1 window for clock skew)."""
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def create_token(secret: str, *, sub: str, role: str, scope: str | None,
                 kind: str, ttl_seconds: int) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "sub": sub, "role": role, "scope": scope, "kind": kind,
        "iat": now, "exp": now + dt.timedelta(seconds=ttl_seconds),
    }
    return jwt.encode(payload, secret, algorithm=_JWT_ALGO)


def decode_token(secret: str, token: str) -> dict:
    """Decode/verify a JWT. Raises jwt.PyJWTError on failure."""
    return jwt.decode(token, secret, algorithms=[_JWT_ALGO])
