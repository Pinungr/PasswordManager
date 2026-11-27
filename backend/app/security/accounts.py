import hashlib
import hmac
import json
import secrets
from contextlib import contextmanager
from threading import BoundedSemaphore
from time import time
from uuid import uuid4

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.core.config import ACCOUNT_PASSWORD_MIN_LENGTH

COOKIE = "__Host-securevault"
HTTP_COOKIE = "securevault-http-test"
PASSWORDS = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)
KDF_SLOTS = BoundedSemaphore(4)


def run(connection, sql, **params):
    return connection.execute(text(sql), params)


@contextmanager
def write(engine):
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
    except OperationalError as error:
        code = getattr(error.orig, "sqlite_errorcode", 0) or 0
        if code & 0xFF in (5, 6):
            raise HTTPException(503, "Storage is busy. Try again.", {"Retry-After": "1"}) from None
        raise


def now():
    return int(time())


def new_password(value, minimum=ACCOUNT_PASSWORD_MIN_LENGTH):
    if len(value) < minimum or len(value.encode("utf-8")) > 512 or not value.strip():
        raise HTTPException(422, f"Use at least {minimum} characters and at most 512 UTF-8 bytes.")
    if not KDF_SLOTS.acquire(blocking=False):
        raise HTTPException(503, "Authentication is busy. Try again.", {"Retry-After": "1"})
    try:
        return PASSWORDS.hash(value)
    finally:
        KDF_SLOTS.release()


def matches(password_hash, value):
    if not KDF_SLOTS.acquire(blocking=False):
        raise HTTPException(503, "Authentication is busy. Try again.", {"Retry-After": "1"})
    try:
        return PASSWORDS.verify(password_hash, value)
    except VerifyMismatchError:
        return False
    finally:
        KDF_SLOTS.release()


def token_hash(token, *, secure=True):
    prefix = b"session\0" if secure else b"http-test-session\0"
    return hashlib.sha256(prefix + token.encode("ascii")).hexdigest()


def csrf_token(token):
    return hashlib.sha256(b"csrf\0" + token.encode("ascii")).hexdigest()


def add_session(connection, user_id, expires, *, secure=True):
    token = secrets.token_urlsafe(32)
    run(
        connection,
        "INSERT INTO user_sessions (token_hash,user_id,expires_at) VALUES (:digest,:user,:expires)",
        digest=token_hash(token, secure=secure),
        user=user_id,
        expires=expires,
    )
    return token


def audit(connection, key, action, actor=None, target=None, result="success", source=None):
    previous = run(connection, "SELECT mac FROM audit_logs ORDER BY id DESC LIMIT 1").scalar()
    event = json.dumps([now(), action, actor, target, result, source], separators=(",", ":"))
    message = bytes.fromhex(previous or "00" * 32) + event.encode()
    mac = hmac.digest(key, message, "sha256").hex()
    run(connection, "INSERT INTO audit_logs (event,mac) VALUES (:event,:mac)", event=event, mac=mac)


def create_user(connection, key, capacity, data, password_hash, actor=None, *, self_registered=False):
    if run(connection, "SELECT count(*) FROM users").scalar_one() >= capacity:
        raise HTTPException(409, "Registered user capacity reached.")
    if run(connection, "SELECT id FROM users WHERE username=:name", name=data.username).scalar():
        raise HTTPException(409, "Username already in use.")
    user_id = str(uuid4())
    run(
        connection,
        """INSERT INTO users (id,username,full_name,email,password_hash,role,active,must_change,
           created_at,self_registered)
           VALUES (:id,:username,:full_name,:email,:hash,:role,:active,:must_change,:created,:private)""",
        id=user_id,
        username=data.username,
        full_name=data.full_name,
        email=data.email,
        hash=password_hash,
        role=data.role,
        active=data.active,
        must_change=not self_registered,
        created=now(),
        private=self_registered,
    )
    audit(connection, key, "account.create", actor, user_id)
    return user_id
