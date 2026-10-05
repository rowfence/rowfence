"""Accounts and sessions. The backend is trusted: it checks the password or the session
cookie, then tells the database who is asking (authz.user_id)."""

import hashlib
import hmac
import secrets

from fastapi import Cookie, HTTPException
from psycopg.rows import DictRow

from . import db

COOKIE = "fm_session"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


def password_ok(password: str, stored: str) -> bool:
    try:
        _, salt, digest = stored.split("$")
    except ValueError:
        return False
    got = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1)
    return hmac.compare_digest(got.hex(), digest)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_session(tx: db.Tx, user_id: object, days: int) -> str:
    token = secrets.token_urlsafe(32)
    tx.run(
        "INSERT INTO fm.sessions VALUES (%s, %s, now() + make_interval(days => %s))", (token_hash(token), user_id, days)
    )
    return token


def current_user(fm_session: str | None = Cookie(default=None)) -> DictRow:
    """The signed-in user (FastAPI dependency); 401 without a valid session."""
    if not fm_session:
        raise HTTPException(401, "sign in first")
    with db.as_user(None) as tx:
        user = tx.row(
            "SELECT u.id, u.email, u.name, u.is_support FROM fm.sessions s JOIN fm.users u ON u.id = s.user_id "
            "WHERE s.token_hash = %s AND s.expires_at > now()",
            (token_hash(fm_session),),
        )
    if user is None:
        raise HTTPException(401, "your session has ended; sign in again")
    return user
