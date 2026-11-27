import csv
import io
import json
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import Field, ValidationError

from app.api.auth import authenticate
from app.api.contracts import DisplayName, Email, Payload
from app.core.config import ACCOUNT_PASSWORD_MIN_LENGTH, Settings
from app.security.accounts import audit, now, run, write

router = APIRouter(prefix="/api/v1")
Positive = Annotated[int, Field(ge=1)]


class Policy(Payload):
    max_registered_users: Positive
    session_timeout_minutes: Positive
    vault_auto_lock_minutes: Positive
    secret_reveal_timeout_seconds: Positive
    clipboard_clear_seconds: Positive
    account_password_min_length: Annotated[int, Field(ge=ACCOUNT_PASSWORD_MIN_LENGTH, le=512)] = (
        ACCOUNT_PASSWORD_MIN_LENGTH
    )
    max_login_attempts: Positive
    login_lockout_minutes: Positive
    password_history_limit: Positive
    recycle_bin_retention_days: Positive
    backup_retention_days: Positive
    backup_schedule: Annotated[str, Field(pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")]


class Profile(Payload):
    full_name: DisplayName
    email: Email | None = None


def load_policy(engine, defaults):
    with engine.connect() as connection:
        value = run(connection, "SELECT policy FROM app_settings WHERE id=1").scalar()
    return (
        defaults
        if not value
        else Settings.model_validate(
            defaults.model_dump() | Policy.model_validate_json(value).model_dump()
        )
    )


@router.get("/settings")
def settings(request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        profile = {
            "username": user.username,
            "full_name": user.full_name,
            "email": user.email,
            "role": user.role,
        }
        policy = (
            state.settings.model_dump(include=set(Policy.model_fields))
            if user.role == "ADMIN"
            else None
        )
    return {"profile": profile, "policy": policy}


@router.put("/settings/policy")
def set_policy(policy: Policy, request: Request):
    state = request.app.state
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection, admin=True)
        if run(connection, "SELECT count(*) FROM users").scalar_one() > policy.max_registered_users:
            raise HTTPException(409, "Capacity must cover existing accounts.")
        try:
            updated = Settings.model_validate(state.settings.model_dump() | policy.model_dump())
        except ValidationError:
            raise HTTPException(422, "Invalid application policy.") from None
        run(
            connection,
            """INSERT INTO app_settings VALUES (1,:policy)
            ON CONFLICT(id) DO UPDATE SET policy=excluded.policy""",
            policy=policy.model_dump_json(),
        )
        run(
            connection,
            "UPDATE user_sessions SET expires_at=MIN(expires_at,:expiry)",
            expiry=now() + updated.session_timeout_minutes * 60,
        )
        audit(connection, state.audit_key, "configuration.policy", user.id)
    # Serialize application state updates using the latest committed policy.
    state.settings = load_policy(state.engine, state.settings)
    return state.settings.model_dump(include=set(Policy.model_fields))


@router.put("/settings/profile", status_code=204)
def update_profile(profile: Profile, request: Request):
    state = request.app.state
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection)
        run(
            connection,
            "UPDATE users SET full_name=:full_name,email=:email WHERE id=:id",
            id=user.id,
            **profile.model_dump(),
        )
        audit(connection, state.audit_key, "account.profile", user.id)


def activity(request, *, cursor, action, since, until, result, username, event_type, limit):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        rows = run(
            connection,
            """SELECT a.id,a.event,u.username FROM audit_logs a
            LEFT JOIN users u ON u.id=json_extract(a.event,'$[2]')
            WHERE (:cursor=0 OR a.id<:cursor)
            AND NOT EXISTS (
                SELECT 1 FROM users private WHERE private.self_registered=1 AND private.id<>:user
                AND private.id IN (u.id, json_extract(a.event,'$[3]'), json_extract(a.event,'$[3][1]'))
            )
            AND (:action='' OR json_extract(a.event,'$[1]')=:action)
            AND (:username='' OR u.username=:username)
            AND (:since=0 OR json_extract(a.event,'$[0]')>=:since)
            AND (:until=0 OR json_extract(a.event,'$[0]')<:until)
            AND (:result='' OR json_extract(a.event,'$[4]')=:result)
            AND (:event_type='' OR (
                 :event_type='client' AND instr(json_extract(a.event,'$[1]'),'.client_')>0)
                 OR (:event_type='server' AND instr(json_extract(a.event,'$[1]'),'.client_')=0))
            AND (:admin OR json_extract(a.event,'$[2]')=:user OR json_extract(a.event,'$[3]')=:user
                OR (:lead AND (EXISTS(
                   SELECT 1 FROM teams t WHERE t.lead_id=:user AND t.active=1
                   AND (t.id=json_extract(a.event,'$[3]') OR t.id=json_extract(a.event,'$[3][0]'))
                ) OR EXISTS(
                   SELECT 1 FROM shared_vaults v JOIN teams t ON t.id=v.team_id
                   JOIN shared_access s ON s.vault_id=v.id AND s.user_id=:user
                   WHERE t.lead_id=:user AND t.active=1 AND
                   (v.id=json_extract(a.event,'$[3]') OR v.id=json_extract(a.event,'$[3][0]'))
                ))))
            ORDER BY a.id DESC LIMIT :limit""",
            action=action,
            since=since,
            until=until,
            result=result,
            event_type=event_type,
            username=username,
            cursor=cursor,
            limit=limit + 1,
            user=user.id,
            admin=user.role == "ADMIN",
            lead=user.role == "TEAM_LEAD",
        ).all()
    items = []
    for event_id, event, name in rows[:limit]:
        timestamp, action, _actor, target, result, source = json.loads(event)
        items.append(
            {
                "id": event_id,
                "timestamp": timestamp,
                "action": action,
                "user": name,
                "target": target,
                "result": result,
                "source": source,
                "type": "client-reported" if ".client_" in action else "server",
            }
        )
    return {"items": items, "cursor": rows[limit - 1][0] if len(rows) > limit else None}


@router.get("/audit")
def audit_rows(
    request: Request,
    cursor: Annotated[int, Query(ge=0)] = 0,
    action: Annotated[str, Query(max_length=80)] = "",
    username: Annotated[str, Query(max_length=64)] = "",
    since: int = 0,
    until: int = 0,
    result: Annotated[str, Query(max_length=20)] = "",
    export: bool = False,
    event_type: Annotated[str, Query(alias="type", max_length=10)] = "",
):
    data = activity(
        request,
        cursor=cursor,
        action=action,
        since=since,
        until=until,
        result=result,
        username=username,
        event_type=event_type,
        limit=5000 if export else 50,
    )
    if not export:
        return data
    file = io.StringIO()
    fields = ["timestamp", "user", "action", "target", "result", "source", "type"]
    writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in data["items"]:
        writer.writerow(
            {
                key: (
                    "'" + value
                    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@"))
                    else value
                )
                for key, value in row.items()
            }
        )
    return Response(
        file.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="securevault-audit.csv"',
            "Cache-Control": "no-store",
        },
    )


@router.get("/summary")
def summary(request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        cutoff = now()
        shared = run(
            connection,
            """SELECT count(*) FROM shared_records r
            JOIN shared_vaults v ON v.id=r.vault_id JOIN teams t ON t.id=v.team_id
            JOIN team_members m ON m.team_id=t.id AND m.user_id=:user
            JOIN shared_access a ON a.vault_id=v.id AND a.user_id=:user
            WHERE r.deleted_at IS NULL AND t.active=1""",
            user=user.id,
        ).scalar_one()
        totals = None
        if user.role == "ADMIN":
            totals = {
                "users": run(connection, "SELECT count(*) FROM users WHERE self_registered=0").scalar_one(),
                "teams": run(connection, "SELECT count(*) FROM teams").scalar_one(),
                "capacity": state.settings.max_registered_users,
            }
    return {"shared_credentials": shared, "admin": totals, "timestamp": cutoff}
