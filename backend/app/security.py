import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

ALGORITHM = "HS256"
MIN_SECRET_LENGTH = 32

_hasher = PasswordHasher()
DUMMY_HASH = _hasher.hash("dummy-pass")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerificationError, InvalidHashError:
        return False


def secret_is_usable(secret: str) -> bool:
    return len(secret) >= MIN_SECRET_LENGTH


def create_access_token(
    user_id: int, role: str, secret: str, expires_in: timedelta, now: datetime | None = None
) -> str:
    issued = now or datetime.now(UTC)
    claims = {"sub": str(user_id), "role": role, "iat": issued, "exp": issued + expires_in}
    return jwt.encode(claims, secret, algorithm=ALGORITHM)


def decode_access_token(token: str, secret: str) -> int:
    claims = jwt.decode(
        token,
        secret,
        algorithms=[ALGORITHM],
        options={"require": ["sub", "exp", "iat"]},
    )
    try:
        return int(claims["sub"])
    except ValueError:
        raise jwt.InvalidTokenError("bad subject") from None


def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
