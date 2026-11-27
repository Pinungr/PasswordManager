import hashlib
import re
import secrets

from fastapi import APIRouter, HTTPException, Request, Response

from app.api.contracts import ChangePassword, Login, NewUser, Signup
from app.security.accounts import (
    COOKIE,
    PASSWORDS,
    add_session,
    audit,
    create_user,
    csrf_token,
    matches,
    new_password,
    now,
    run,
    token_hash,
    write,
)

router = APIRouter(prefix="/api/v1/auth")


def same_origin(request):
    if request.headers.getlist("origin") != [request.app.state.settings.origin]:
        raise HTTPException(403, "Request origin denied.")


def authenticate(request, connection, *, allow_temporary=False, admin=False):
    token = request.cookies.get(COOKIE, "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        raise HTTPException(401, "Sign in required.")
    row = (
        run(
            connection,
            """SELECT u.*, s.expires_at FROM user_sessions s JOIN users u ON u.id=s.user_id
           WHERE s.token_hash=:digest AND s.expires_at>:now AND u.active=1""",
            digest=token_hash(token),
            now=now(),
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(401, "Session expired. Sign in again.")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        same_origin(request)
        claim = request.headers.get("x-csrf-token", "")
        if not re.fullmatch(r"[a-f0-9]{64}", claim) or not secrets.compare_digest(
            claim, csrf_token(token)
        ):
            raise HTTPException(403, "CSRF verification failed.")
    if row.must_change and not allow_temporary:
        raise HTTPException(403, "Change your temporary password first.")
    if admin and row.role != "ADMIN":
        raise HTTPException(403, "Administrator access required.")
    return row, token


def public_session(row, token, expires_at):
    return {
        "id": row.id,
        "username": row.username,
        "full_name": row.full_name,
        "role": row.role,
        "must_change": bool(row.must_change),
        "csrf": csrf_token(token),
        "expires_at": expires_at,
    }


def cookie(response, token, ttl):
    response.set_cookie(COOKIE, token, secure=True, httponly=True, samesite="strict", max_age=ttl)


def scope(label, value):
    return hashlib.sha256(f"{label}:{value}".encode()).hexdigest()


def throttled(connection, scopes, moment):
    return any(
        (
            run(
                connection,
                "SELECT attempts FROM login_limits WHERE scope=:id AND expires_at>:now",
                id=key,
                now=moment,
            ).scalar()
            or 0
        )
        >= threshold
        for key, threshold in scopes
    )


def read_login(connection, username):
    return (
        run(connection, "SELECT * FROM users WHERE username=:name", name=username)
        .mappings()
        .one_or_none()
    )


def record_attempt(connection, key, threshold, moment, window):
    run(
        connection,
        """INSERT INTO login_limits (scope,attempts,expires_at) VALUES (:id,1,:until)
           ON CONFLICT(scope) DO UPDATE SET attempts=attempts+1,
           expires_at=CASE WHEN attempts+1 >= :threshold
                THEN excluded.expires_at ELSE expires_at END""",
        id=key,
        until=moment + window,
        threshold=threshold,
    )


@router.post("/signup", status_code=201)
def signup(data: Signup, request: Request, response: Response):
    same_origin(request)
    state = request.app.state
    settings = state.settings
    source = request.client.host if request.client else "unknown"
    key = scope("signup", source)
    threshold = settings.max_login_attempts
    window = settings.login_lockout_minutes * 60
    with write(state.engine) as connection:
        if not run(connection, "SELECT 1 FROM users WHERE role='ADMIN' AND active=1 LIMIT 1").scalar():
            raise HTTPException(503, "Account sign-up is unavailable until administrator setup.")
        moment = now()
        if throttled(connection, ((key, threshold),), moment):
            raise HTTPException(429, "Too many sign-up attempts. Try again later.")
        run(connection, "DELETE FROM login_limits WHERE expires_at<=:now", now=moment)
        record_attempt(connection, key, threshold, moment, window)

    password_hash = new_password(data.password, settings.account_password_min_length)
    user = NewUser(**data.model_dump())
    ttl = settings.session_timeout_minutes * 60
    with write(state.engine) as connection:
        user_id = create_user(
            connection, state.audit_key, settings.max_registered_users, user, password_hash,
            self_registered=True,
        )
        moment = now()
        run(connection, "UPDATE users SET last_login=:now WHERE id=:id", now=moment, id=user_id)
        row = read_login(connection, user.username)
        token = add_session(connection, user_id, moment + ttl)
        audit(connection, state.audit_key, "auth.login", user_id, source=source)
    cookie(response, token, ttl)
    return public_session(row, token, moment + ttl)


@router.post("/login")
def login(data: Login, request: Request, response: Response):
    same_origin(request)
    state = request.app.state
    settings = state.settings
    source = request.client.host if request.client else "unknown"
    user_scope = scope("username", data.username)
    scopes = (
        (user_scope, settings.max_login_attempts),
        (scope("source", source), max(30, settings.max_login_attempts * 6)),
    )
    denied = HTTPException(401, "Sign-in failed. Check your credentials or try again later.")
    with state.engine.connect() as connection:
        if throttled(connection, scopes, now()):
            raise denied
        user = read_login(connection, data.username)
    candidate = user.password_hash if user is not None else state.dummy_hash
    verified = matches(candidate, data.password) and user is not None
    token = None
    ttl = settings.session_timeout_minutes * 60
    with write(state.engine) as connection:
        moment = now()
        if throttled(connection, scopes, moment):
            raise denied
        fresh = read_login(connection, data.username)
        if verified and fresh and fresh.active and fresh.password_hash == candidate:
            run(connection, "DELETE FROM login_limits WHERE scope=:id", id=user_scope)
            run(connection, "DELETE FROM user_sessions WHERE expires_at<=:now", now=moment)
            run(
                connection, "UPDATE users SET last_login=:now WHERE id=:id", now=moment, id=fresh.id
            )
            token = add_session(connection, fresh.id, moment + ttl)
            audit(connection, state.audit_key, "auth.login", fresh.id, source=source)
        else:
            run(connection, "DELETE FROM login_limits WHERE expires_at<=:now", now=moment)
            for key, threshold in scopes:
                record_attempt(connection, key, threshold, moment, settings.login_lockout_minutes * 60)
            audit(
                connection,
                state.audit_key,
                "auth.login",
                target=fresh.id if fresh else None,
                result="failure",
                source=source,
            )
    if token is None:
        raise denied
    cookie(response, token, ttl)
    return public_session(fresh, token, moment + ttl)


@router.get("/session")
def session(request: Request):
    with request.app.state.engine.connect() as connection:
        row, token = authenticate(request, connection, allow_temporary=True)
        return public_session(row, token, row.expires_at)


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response):
    state = request.app.state
    with write(state.engine) as connection:
        row, token = authenticate(request, connection, allow_temporary=True)
        run(connection, "DELETE FROM user_sessions WHERE token_hash=:id", id=token_hash(token))
        audit(connection, state.audit_key, "auth.logout", row.id)
    response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="strict")


@router.post("/password")
def change_password(data: ChangePassword, request: Request, response: Response):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection, allow_temporary=True)
    if not matches(user.password_hash, data.current_password):
        raise HTTPException(403, "Incorrect current password.")
    if data.current_password == data.password:
        raise HTTPException(422, "Choose a different account password.")
    password_hash = new_password(data.password, state.settings.account_password_min_length)
    ttl = state.settings.session_timeout_minutes * 60
    with write(state.engine) as connection:
        fresh, _ = authenticate(request, connection, allow_temporary=True)
        if fresh.password_hash != user.password_hash:
            raise HTTPException(409, "Account changed. Sign in again.")
        run(
            connection,
            "UPDATE users SET password_hash=:hash,must_change=0 WHERE id=:user",
            hash=password_hash,
            user=fresh.id,
        )
        run(connection, "DELETE FROM user_sessions WHERE user_id=:id", id=fresh.id)
        expires = now() + ttl
        token = add_session(connection, fresh.id, expires)
        audit(connection, state.audit_key, "account.password_change", fresh.id)
        row = read_login(connection, fresh.username)
    cookie(response, token, ttl)
    return public_session(row, token, expires)


def dummy_password_hash():
    return PASSWORDS.hash(secrets.token_urlsafe(32))
