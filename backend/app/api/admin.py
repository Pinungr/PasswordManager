from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Request

from app.api.auth import authenticate
from app.api.contracts import (
    Assignments, NewPassword, NewUser, Payload, PrivatePasswordReset, Team, UpdateUser, Username,
)
from app.api.shared import DELETE, MANAGE, remove_member_grants, remove_user_grants
from app.security.accounts import audit, create_user, new_password, run, write

router = APIRouter(prefix="/api/v1")
USER_COLUMNS = "id, username, full_name, email, role, active, must_change, created_at, last_login"


def user_by_id(connection, user_id):
    user = (
        run(
            connection, f"SELECT {USER_COLUMNS} FROM users WHERE id=:id AND self_registered=0",
            id=str(user_id),
        )
        .mappings()
        .one_or_none()
    )
    if user is None:
        raise HTTPException(404, "User not found.")
    return user


@router.get("/users")
def users(request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        authenticate(request, connection, admin=True)
        rows = (
            run(
                connection, f"SELECT {USER_COLUMNS} FROM users WHERE self_registered=0 ORDER BY username",
            ).mappings().all()
        )
        memberships = run(connection, "SELECT user_id,team_id FROM team_members").all()
    teams = {}
    for user_id, team_id in memberships:
        teams.setdefault(user_id, []).append(team_id)
    return {
        "items": [dict(row, teams=teams.get(row.id, [])) for row in rows],
        "capacity": state.settings.max_registered_users,
    }


@router.post("/users", status_code=201)
def add_user(data: NewUser, request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        authenticate(request, connection, admin=True)
    password_hash = new_password(data.password, state.settings.account_password_min_length)
    with write(state.engine) as connection:
        actor, _ = authenticate(request, connection, admin=True)
        user_id = create_user(
            connection,
            state.audit_key,
            state.settings.max_registered_users,
            data,
            password_hash,
            actor.id,
        )
        change_assignments(connection, state.audit_key, actor.id, user_id, data.team_ids)
        return dict(user_by_id(connection, user_id))


@router.put("/users/{user_id}")
def update_user(user_id: UUID, data: UpdateUser, request: Request):
    state = request.app.state
    with write(state.engine) as connection:
        actor, _ = authenticate(request, connection, admin=True)
        user = user_by_id(connection, user_id)
        if user.id == actor.id and (not data.active or data.role != actor.role):
            raise HTTPException(409, "Another administrator must change your role or status.")
        run(
            connection,
            "UPDATE users SET full_name=:full_name,email=:email,role=:role,active=:active"
            " WHERE id=:id",
            id=user.id,
            **data.model_dump(),
        )
        if user.role != data.role or bool(user.active) != data.active:
            run(connection, "DELETE FROM user_sessions WHERE user_id=:id", id=user.id)
            if data.role == "MEMBER":
                run(
                    connection,
                    "UPDATE shared_access SET permissions=permissions & :mask WHERE user_id=:id",
                    mask=~(MANAGE | DELETE),
                    id=user.id,
                )
            if not data.active or data.role != "TEAM_LEAD":
                run(connection, "UPDATE teams SET lead_id=NULL WHERE lead_id=:id", id=user.id)
        if bool(user.active) != data.active:
            if not data.active:
                remove_user_grants(connection, user.id)
            action = "account.activate" if data.active else "account.deactivate"
            audit(connection, state.audit_key, action, actor.id, user.id)
        audit(connection, state.audit_key, "account.update", actor.id, user.id)
        return dict(user_by_id(connection, user_id))


@router.post("/users/{user_id}/password-reset", status_code=204)
def reset_password(user_id: UUID, data: NewPassword, request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        authenticate(request, connection, admin=True)
    password_hash = new_password(data.password, state.settings.account_password_min_length)
    with write(state.engine) as connection:
        actor, _ = authenticate(request, connection, admin=True)
        user = user_by_id(connection, user_id)
        if actor.id == user.id:
            raise HTTPException(409, "Use the account password change form.")
        set_temporary_password(connection, state.audit_key, actor.id, user.id, password_hash)


@router.post("/users/private-password-reset", status_code=204)
def reset_private_password(data: PrivatePasswordReset, request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        authenticate(request, connection, admin=True)
    password_hash = new_password(data.password, state.settings.account_password_min_length)
    with write(state.engine) as connection:
        actor, _ = authenticate(request, connection, admin=True)
        user_id = run(
            connection,
            "SELECT id FROM users WHERE username=:username AND self_registered=1",
            username=data.username,
        ).scalar()
        if user_id:
            set_temporary_password(connection, state.audit_key, actor.id, user_id, password_hash)


def set_temporary_password(connection, key, actor_id, user_id, password_hash):
    run(
        connection,
        "UPDATE users SET password_hash=:hash,must_change=1 WHERE id=:id",
        hash=password_hash,
        id=user_id,
    )
    run(connection, "DELETE FROM user_sessions WHERE user_id=:id", id=user_id)
    audit(connection, key, "account.password_reset", actor_id, user_id)


def team_by_id(connection, team_id, actor):
    team = run(connection, "SELECT * FROM teams WHERE id=:id", id=team_id).mappings().one_or_none()
    if team is None or (
        actor.role != "ADMIN"
        and (actor.role != "TEAM_LEAD" or team.lead_id != actor.id or not team.active)
    ):
        raise HTTPException(404, "Team not found.")
    return team


@router.get("/teams")
def teams(request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        actor, _ = authenticate(request, connection)
        rows = run(
            connection,
            """SELECT t.*, (SELECT count(*) FROM team_members m
                   WHERE m.team_id=t.id) AS member_count FROM teams t WHERE :admin
                   OR (:lead AND lead_id=:user AND t.active=1)
                   OR (t.active=1 AND EXISTS(SELECT 1 FROM team_members m
                       WHERE m.team_id=t.id AND m.user_id=:user)) ORDER BY t.name""",
            admin=actor.role == "ADMIN",
            lead=actor.role == "TEAM_LEAD",
            user=actor.id,
        ).mappings()
        return [dict(row) for row in rows]


def validate_team(connection, data, team_id):
    if run(
        connection, "SELECT 1 FROM teams WHERE name=:name AND id<>:id", name=data.name, id=team_id
    ).scalar():
        raise HTTPException(409, "Team name already in use.")
    if data.lead_id:
        lead = user_by_id(connection, data.lead_id)
        if lead.role != "TEAM_LEAD" or not lead.active:
            raise HTTPException(422, "Choose an active team lead.")


def enroll(connection, team_id, user_id):
    run(
        connection,
        """INSERT INTO team_members (team_id,user_id) VALUES (:team,:user)
        ON CONFLICT(team_id,user_id) DO NOTHING""",
        team=team_id,
        user=user_id,
    )


@router.post("/teams", status_code=201)
def add_team(data: Team, request: Request):
    state = request.app.state
    with write(state.engine) as connection:
        actor, _ = authenticate(request, connection, admin=True)
        team_id = str(uuid4())
        validate_team(connection, data, team_id)
        run(
            connection,
            "INSERT INTO teams (id,name,description,lead_id,active)"
            " VALUES (:id,:name,:description,:lead_id,:active)",
            id=team_id,
            **data.model_dump(),
        )
        if data.lead_id:
            enroll(connection, team_id, data.lead_id)
        audit(connection, state.audit_key, "team.create", actor.id, team_id)
        return dict(team_by_id(connection, team_id, actor))


@router.put("/teams/{team_id}")
def update_team(team_id: UUID, data: Team, request: Request):
    state = request.app.state
    team_id = str(team_id)
    with write(state.engine) as connection:
        actor, _ = authenticate(request, connection)
        existing = team_by_id(connection, team_id, actor)
        if actor.role != "ADMIN" and (
            data.lead_id != existing.lead_id or data.active != bool(existing.active)
        ):
            raise HTTPException(403, "Administrator access required.")
        validate_team(connection, data, team_id)
        run(
            connection,
            "UPDATE teams SET name=:name,description=:description,lead_id=:lead_id,"
            "active=:active WHERE id=:id",
            id=team_id,
            **data.model_dump(),
        )
        if data.lead_id:
            enroll(connection, team_id, data.lead_id)
        audit(connection, state.audit_key, "team.update", actor.id, team_id)
        return dict(team_by_id(connection, team_id, actor))


@router.get("/teams/{team_id}/members")
def members_access(team_id: UUID, request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        actor, _ = authenticate(request, connection)
        team_by_id(connection, str(team_id), actor)
        rows = run(
            connection,
            """SELECT u.id,u.username,u.full_name,u.active FROM users u
                   JOIN team_members m ON u.id=m.user_id WHERE m.team_id=:id ORDER BY u.username""",
            id=str(team_id),
        ).mappings()
        return [dict(row) for row in rows]


@router.api_route("/teams/{team_id}/members/{user_id}", methods=["PUT", "DELETE"], status_code=204)
def change_member(team_id: UUID, user_id: UUID, request: Request):
    state = request.app.state
    team_id = str(team_id)
    with write(state.engine) as connection:
        actor, _ = authenticate(request, connection)
        team = team_by_id(connection, team_id, actor)
        user = user_by_id(connection, user_id)
        if request.method == "PUT":
            if not user.active or not team.active:
                raise HTTPException(409, "Both the user and team must be active.")
            enroll(connection, team_id, user.id)
        else:
            if team.lead_id == user.id:
                raise HTTPException(409, "Reassign the team lead before removing their membership.")
            run(
                connection,
                "DELETE FROM team_members WHERE team_id=:team AND user_id=:user",
                team=team_id,
                user=user.id,
            )
            remove_member_grants(connection, team_id, user.id)
        action = "team.member_add" if request.method == "PUT" else "team.member_remove"
        audit(connection, state.audit_key, action, actor.id, [team_id, user.id])


class Membership(Payload):
    username: Username


@router.post("/teams/{team_id}/members", status_code=204)
def add_member_by_username(team_id: UUID, data: Membership, request: Request):
    state = request.app.state
    with write(state.engine) as connection:
        actor, _ = authenticate(request, connection)
        team = team_by_id(connection, str(team_id), actor)
        member_id = run(
            connection,
            "SELECT id FROM users WHERE username=:name AND active=1 AND self_registered=0",
            name=data.username.lower(),
        ).scalar()
        if not member_id or not team.active:
            raise HTTPException(404, "Active user or team not found.")
        enroll(connection, team.id, member_id)
        audit(connection, state.audit_key, "team.member_add", actor.id, [team.id, member_id])


def change_assignments(connection, key, actor, user_id, teams):
    existing = set(
        run(connection, "SELECT team_id FROM team_members WHERE user_id=:id", id=user_id).scalars()
    )
    requested = set(teams)
    for team in requested - existing:
        if not run(connection, "SELECT 1 FROM teams WHERE id=:id AND active=1", id=team).scalar():
            raise HTTPException(422, "Select active teams.")
        enroll(connection, team, user_id)
        audit(connection, key, "team.member_add", actor, [team, user_id])
    for team in existing - requested:
        if run(
            connection, "SELECT 1 FROM teams WHERE id=:id AND lead_id=:user", id=team, user=user_id
        ).scalar():
            raise HTTPException(409, "Reassign the team lead before removing their membership.")
        run(
            connection,
            "DELETE FROM team_members WHERE team_id=:team AND user_id=:user",
            team=team,
            user=user_id,
        )
        remove_member_grants(connection, team, user_id)
        audit(connection, key, "team.member_remove", actor, [team, user_id])


@router.put("/users/{user_id}/teams", status_code=204)
def assign_user_teams(user_id: UUID, data: Assignments, request: Request):
    state = request.app.state
    with write(state.engine) as connection:
        actor, _ = authenticate(request, connection, admin=True)
        user = user_by_id(connection, user_id)
        change_assignments(connection, state.audit_key, actor.id, user.id, data.team_ids)
