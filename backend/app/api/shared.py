import json
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import Field

from app.api.auth import authenticate
from app.api.contracts import DisplayName, Payload
from app.api.personal import ChangeRecord, Envelope, Version, bounded_page, payload_limit, vault_for
from app.security.accounts import audit, now, run, write
from app.security.grants import verify_grant

router = APIRouter(prefix="/api/v1/shared")
VIEW, CREATE, EDIT, DELETE, MANAGE = 1, 2, 4, 8, 16
ALL = VIEW | CREATE | EDIT | DELETE | MANAGE
Coordinate = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]
SignedGrant = Annotated[
    str, Field(max_length=8192, pattern=r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
]


class Jwk(Payload):
    kty: Literal["EC"]
    crv: Literal["P-256"]
    x: Coordinate
    y: Coordinate


class PublicKeys(Payload):
    agreement: Jwk
    signing: Jwk


class Identity(PublicKeys):
    private_envelope: Envelope


class NewSharedVault(Payload):
    id: Annotated[str, Field(pattern=r"^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$")]
    name: DisplayName
    description: Annotated[str, Field(max_length=1000)] = ""
    grant: SignedGrant


class Grant(Payload):
    permissions: Annotated[int, Field(ge=1, le=ALL)]
    grant: SignedGrant
    epoch: Version
    membership_version: Version


class SharedChange(ChangeRecord):
    epoch: Version


def access(connection, vault, user, permission=VIEW, *, writing=False):
    row = (
        run(
            connection,
            """SELECT v.*,a.permissions,a.grant,a.grantor,u.role FROM shared_vaults v
        JOIN shared_access a ON a.vault_id=v.id JOIN teams t ON t.id=v.team_id
        JOIN team_members m ON m.team_id=v.team_id AND m.user_id=a.user_id
        JOIN users u ON u.id=a.user_id
        WHERE v.id=:vault AND a.user_id=:user AND t.active=1""",
            vault=vault,
            user=user,
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(404, "Shared vault not found.")
    if row.permissions & permission != permission or (
        row.role == "MEMBER" and permission & (MANAGE | DELETE)
    ):
        raise HTTPException(403, "Shared vault permission required.")
    if writing and row.rotating:
        raise HTTPException(409, "Key rotation is pending for this vault.")
    return row


def identity(connection, user):
    result = (
        run(connection, "SELECT * FROM shared_identities WHERE user_id=:id", id=user)
        .mappings()
        .one_or_none()
    )
    if result is None:
        raise HTTPException(409, "This user has not set up a shared vault identity.")
    return result


def check_grant(connection, grant, sender, recipient, vault, epoch):
    signing = json.loads(identity(connection, sender).public_keys)["signing"]
    agreement = json.loads(identity(connection, recipient).public_keys)["agreement"]
    verify_grant(grant, sender, recipient, vault, epoch, signing=signing, agreement=agreement)


def verify_member(connection, team, member):
    if not run(
        connection,
        """SELECT 1 FROM team_members m JOIN teams t ON t.id=m.team_id
        JOIN users u ON u.id=m.user_id WHERE m.team_id=:team AND m.user_id=:user
        AND t.active=1 AND u.active=1""",
        team=team,
        user=member,
    ).scalar():
        raise HTTPException(404, "Active team member not found.")


def remove_grant(connection, vault, member):
    run(
        connection,
        "DELETE FROM shared_access WHERE vault_id=:id AND user_id=:member",
        id=vault,
        member=member,
    )
    run(
        connection,
        "UPDATE shared_vaults SET rotating=1,membership_version=membership_version+1,"
        " stage_id=NULL,stage_actor=NULL WHERE id=:id",
        id=vault,
    )


def remove_user_grants(connection, user):
    vaults = (
        run(connection, "SELECT vault_id FROM shared_access WHERE user_id=:user", user=user)
        .scalars()
        .all()
    )
    for vault in vaults:
        remove_grant(connection, vault, user)


def remove_member_grants(connection, team, member):
    vaults = (
        run(
            connection,
            """SELECT v.id FROM shared_vaults v JOIN shared_access a
        ON a.vault_id=v.id WHERE v.team_id=:team AND a.user_id=:member""",
            team=team,
            member=member,
        )
        .scalars()
        .all()
    )
    for vault in vaults:
        remove_grant(connection, vault, member)


@router.get("/identity")
def my_identity(request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        data = (
            run(connection, "SELECT * FROM shared_identities WHERE user_id=:id", id=user.id)
            .mappings()
            .one_or_none()
        )
    return (
        None
        if data is None
        else (
            json.loads(data.public_keys) | {"private_envelope": json.loads(data.private_envelope)}
        )
    )


@router.post("/identity", status_code=201)
def register_identity(data: Identity, request: Request):
    state = request.app.state
    if data.agreement == data.signing:
        raise HTTPException(422, "Use independent signing and agreement keys.")
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection)
        vault_for(connection, user.id)
        if run(
            connection, "SELECT 1 FROM shared_identities WHERE user_id=:id", id=user.id
        ).scalar():
            raise HTTPException(409, "A shared vault identity already exists.")
        run(
            connection,
            "INSERT INTO shared_identities VALUES (:user,:public,:envelope)",
            user=user.id,
            public=data.model_dump_json(exclude={"private_envelope"}),
            envelope=data.private_envelope.model_dump_json(),
        )
        audit(connection, state.audit_key, "identity.create", user.id)


@router.get("/teams/{team_id}/directory")
def directory(team_id: UUID, request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        verify_member(connection, str(team_id), user.id)
        rows = (
            run(
                connection,
                """SELECT u.id,u.username,u.full_name,i.public_keys
            FROM team_members m JOIN users u ON u.id=m.user_id LEFT JOIN shared_identities i
            ON i.user_id=u.id WHERE m.team_id=:id AND u.active=1 ORDER BY u.username""",
                id=str(team_id),
            )
            .mappings()
            .all()
        )
    return [
        dict(row) | {"public_keys": json.loads(row.public_keys) if row.public_keys else None}
        for row in rows
    ]


@router.post("/teams/{team_id}/vaults", status_code=201)
def create_vault(team_id: UUID, data: NewSharedVault, request: Request):
    state = request.app.state
    team_id = str(team_id)
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection)
        if user.role != "ADMIN" and not (
            user.role == "TEAM_LEAD"
            and run(
                connection,
                "SELECT 1 FROM teams WHERE id=:id AND lead_id=:user",
                id=team_id,
                user=user.id,
            ).scalar()
        ):
            raise HTTPException(403, "Team administration permission required.")
        verify_member(connection, team_id, user.id)
        check_grant(connection, data.grant, user.id, user.id, data.id, 1)
        if run(
            connection,
            "SELECT 1 FROM shared_vaults WHERE id=:id OR (team_id=:team AND name=:name)",
            id=data.id,
            team=team_id,
            name=data.name,
        ).scalar():
            raise HTTPException(409, "Shared vault already exists.")
        run(
            connection,
            """INSERT INTO shared_vaults (id,team_id,name,description,epoch,rotating,
            membership_version) VALUES (:id,:team,:name,:description,1,0,1)""",
            id=data.id,
            team=team_id,
            name=data.name,
            description=data.description,
        )
        run(
            connection,
            "INSERT INTO shared_access VALUES (:id,:user,:user,:permissions,:grant)",
            id=data.id,
            user=user.id,
            permissions=ALL,
            grant=data.grant,
        )
        audit(connection, state.audit_key, "shared_vault.create", user.id, data.id)
        return {"id": data.id, "epoch": 1}


@router.get("/vaults")
def vaults(request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        rows = (
            run(
                connection,
                """SELECT v.id,v.team_id,v.name,v.description,v.epoch,v.rotating,
            v.membership_version,t.name AS team_name,a.permissions,a.grant,a.grantor
            FROM shared_vaults v JOIN teams t ON t.id=v.team_id
            JOIN shared_access a ON v.id=a.vault_id
            JOIN team_members m ON m.team_id=v.team_id AND m.user_id=a.user_id
        JOIN users u ON u.id=a.user_id
            WHERE a.user_id=:user AND t.active=1 ORDER BY t.name,v.name""",
                user=user.id,
            )
            .mappings()
            .all()
        )
    return [dict(row) for row in rows]


@router.get("/vaults/{vault_id}/access")
def grants(vault_id: UUID, request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        access(connection, str(vault_id), user.id, MANAGE)
        rows = (
            run(
                connection,
                """SELECT a.user_id,u.username,u.full_name,a.permissions
            FROM shared_access a JOIN users u ON u.id=a.user_id WHERE a.vault_id=:id""",
                id=str(vault_id),
            )
            .mappings()
            .all()
        )
    return [dict(row) for row in rows]


@router.put("/vaults/{vault_id}/access/{member_id}", status_code=204)
def grant(vault_id: UUID, member_id: UUID, data: Grant, request: Request):
    state = request.app.state
    vault_id, member_id = str(vault_id), str(member_id)
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection)
        vault = access(connection, vault_id, user.id, MANAGE, writing=True)
        if data.epoch != vault.epoch or data.membership_version != vault.membership_version:
            raise HTTPException(409, "Vault access changed. Reload and retry.")
        if member_id == user.id or not data.permissions & VIEW:
            raise HTTPException(422, "Choose another member and include View permission.")
        verify_member(connection, vault.team_id, member_id)
        recipient_role = run(
            connection, "SELECT role FROM users WHERE id=:id", id=member_id
        ).scalar()
        if recipient_role == "MEMBER" and data.permissions & (MANAGE | DELETE):
            raise HTTPException(403, "This role cannot manage access or delete shared credentials.")
        check_grant(connection, data.grant, user.id, member_id, vault_id, data.epoch)
        run(
            connection,
            """INSERT INTO shared_access VALUES (:id,:member,:user,:permissions,:grant)
            ON CONFLICT(vault_id,user_id) DO UPDATE SET grantor=excluded.grantor,
            permissions=excluded.permissions,grant=excluded.grant""",
            id=vault_id,
            member=member_id,
            user=user.id,
            permissions=data.permissions,
            grant=data.grant,
        )
        run(
            connection,
            "UPDATE shared_vaults SET membership_version=membership_version+1 WHERE id=:id",
            id=vault_id,
        )
        audit(connection, state.audit_key, "shared_access.grant", user.id, [vault_id, member_id])


@router.delete("/vaults/{vault_id}/access/{member_id}", status_code=204)
def revoke(vault_id: UUID, member_id: UUID, request: Request):
    state = request.app.state
    vault_id, member_id = str(vault_id), str(member_id)
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection)
        access(connection, vault_id, user.id, MANAGE)
        if member_id == user.id:
            raise HTTPException(422, "A different manager must revoke your access.")
        if not run(
            connection,
            "SELECT 1 FROM shared_access WHERE vault_id=:id AND user_id=:member",
            id=vault_id,
            member=member_id,
        ).scalar():
            raise HTTPException(404, "Grant not found.")
        remove_grant(connection, vault_id, member_id)
        audit(connection, state.audit_key, "shared_access.revoke", user.id, [vault_id, member_id])


@router.get("/vaults/{vault_id}/records")
def records(
    vault_id: UUID,
    request: Request,
    cursor: UUID | None = None,
    deleted: bool = False,
    limit: Annotated[int, Query(ge=1, le=1000)] = 25,
):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        vault = access(connection, str(vault_id), user.id)
        cutoff = now() - state.settings.recycle_bin_retention_days * 86400
        rows = run(
            connection,
            """SELECT r.*,p.payload FROM shared_records r JOIN shared_payloads p
            ON p.vault_id=r.vault_id AND p.record_id=r.id AND p.crypto_version=r.crypto_version
            WHERE r.vault_id=:id AND p.epoch=:epoch AND p.generation=:generation AND r.id>:cursor
            AND ((NOT :deleted AND r.deleted_at IS NULL) OR (:deleted AND r.deleted_at>:cutoff))
            ORDER BY r.id LIMIT :limit""",
            id=vault.id,
            epoch=vault.epoch,
            generation=vault.active_generation,
            cursor=str(cursor or ""),
            deleted=deleted,
            cutoff=cutoff,
            limit=limit + 1,
        ).mappings()
        items, cursor = bounded_page(rows, limit)
    return JSONResponse(
        {
            "items": [
                dict(row) | {"payload": json.loads(row.payload), "last_used": None} for row in items
            ],
            "cursor": cursor,
            "epoch": vault.epoch,
        }
    )


@router.put("/vaults/{vault_id}/records/{record_id}")
def save_record(vault_id: UUID, record_id: UUID, data: SharedChange, request: Request):
    state = request.app.state
    record_id = str(record_id)
    if len(data.payload.ciphertext) > payload_limit(state.settings):
        raise HTTPException(413, "Encrypted credential is too large.")
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection)
        vault = access(
            connection, str(vault_id), user.id, CREATE if data.version == 1 else EDIT, writing=True
        )
        if data.epoch != vault.epoch:
            raise HTTPException(409, "Vault key changed. Unlock the current epoch.")
        existing = (
            run(
                connection,
                "SELECT * FROM shared_records WHERE id=:id AND vault_id=:vault",
                id=record_id,
                vault=vault.id,
            )
            .mappings()
            .one_or_none()
        )
        moment = now()
        if data.version == 1:
            if existing:
                raise HTTPException(409, "Credential already exists.")
            run(
                connection,
                """INSERT INTO shared_records
                (vault_id,id,version,crypto_version,created_at,modified_at)
                VALUES (:vault,:id,1,1,:now,:now)""",
                id=record_id,
                vault=vault.id,
                now=moment,
            )
        else:
            if not existing or existing.deleted_at or existing.version + 1 != data.version:
                raise HTTPException(409, "Credential changed. Reload and retry.")
            run(
                connection,
                """UPDATE shared_records SET version=:version,crypto_version=:version,
                modified_at=:now WHERE id=:id AND vault_id=:vault""",
                id=record_id,
                vault=vault.id,
                version=data.version,
                now=moment,
            )
        run(
            connection,
            """INSERT INTO shared_payloads
            VALUES (:vault,:record,:epoch,:generation,:version,:payload,:user,:now)""",
            vault=vault.id,
            record=record_id,
            epoch=vault.epoch,
            generation=vault.active_generation,
            version=data.version,
            payload=data.payload.model_dump_json(),
            user=user.id,
            now=moment,
        )
        run(
            connection,
            """DELETE FROM shared_payloads WHERE vault_id=:vault AND record_id=:record
            AND epoch=:epoch AND generation=:generation AND crypto_version IN (
                SELECT crypto_version FROM shared_payloads WHERE vault_id=:vault
                AND record_id=:record AND epoch=:epoch AND generation=:generation
                ORDER BY crypto_version DESC
                LIMIT -1 OFFSET :keep)""",
            vault=vault.id,
            record=record_id,
            epoch=vault.epoch,
            generation=vault.active_generation,
            keep=state.settings.password_history_limit + 1,
        )
        audit(connection, state.audit_key, "shared_credential.save", user.id, [vault.id, record_id])
        return {
            "id": record_id,
            "version": data.version,
            "crypto_version": data.version,
            "payload": data.payload.model_dump(),
            "modified_at": moment,
            "created_at": existing.created_at if existing else moment,
            "deleted_at": None,
            "last_used": None,
        }


@router.post("/vaults/{vault_id}/records/{record_id}/{action}", status_code=204)
def act(
    vault_id: UUID,
    record_id: UUID,
    action: Literal["delete", "restore", "purge", "copy", "reveal"],
    version: Version,
    epoch: Version,
    request: Request,
):
    state = request.app.state
    mutation = action in {"delete", "restore", "purge"}
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection)
        vault = access(
            connection, str(vault_id), user.id, DELETE if mutation else VIEW, writing=mutation
        )
        if epoch != vault.epoch:
            raise HTTPException(409, "Vault key changed. Unlock the current epoch.")
        record = (
            run(
                connection,
                "SELECT * FROM shared_records WHERE vault_id=:vault AND id=:id",
                vault=vault.id,
                id=str(record_id),
            )
            .mappings()
            .one_or_none()
        )
        if record is None:
            raise HTTPException(404, "Credential not found.")
        if record.version != version or (record.deleted_at is not None) != (
            action in {"restore", "purge"}
        ):
            raise HTTPException(409, "Credential changed. Reload and retry.")
        if action in {"restore", "purge"} and (
            record.deleted_at <= now() - state.settings.recycle_bin_retention_days * 86400
        ):
            raise HTTPException(409, "Credential has expired from the recycle bin.")
        if action in {"delete", "restore"}:
            run(
                connection,
                """UPDATE shared_records SET deleted_at=:time,version=version+1
                WHERE id=:id AND vault_id=:vault""",
                time=now() if action == "delete" else None,
                id=record.id,
                vault=vault.id,
            )
        if action == "purge":
            run(
                connection,
                "DELETE FROM shared_records WHERE id=:id AND vault_id=:vault",
                id=record.id,
                vault=vault.id,
            )
        event = action if mutation else f"client_{action}"
        audit(
            connection,
            state.audit_key,
            f"shared_credential.{event}",
            user.id,
            [vault.id, record.id],
        )


@router.get("/vaults/{vault_id}/records/{record_id}/history")
def history(vault_id: UUID, record_id: UUID, request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        vault = access(connection, str(vault_id), user.id)
        record = (
            run(
                connection,
                "SELECT * FROM shared_records WHERE vault_id=:vault AND id=:id",
                vault=vault.id,
                id=str(record_id),
            )
            .mappings()
            .one_or_none()
        )
        if record is None or record.deleted_at is not None:
            raise HTTPException(404, "Credential not found.")
        rows = (
            run(
                connection,
                """SELECT crypto_version AS version,crypto_version,payload,
            modified_at,modified_by FROM shared_payloads WHERE vault_id=:vault AND record_id=:id
            AND epoch=:epoch AND generation=:gen AND crypto_version<>:current
            ORDER BY crypto_version DESC""",
                vault=vault.id,
                id=record.id,
                epoch=vault.epoch,
                gen=vault.active_generation,
                current=record.crypto_version,
            )
            .mappings()
            .all()
        )
    return [dict(row) | {"payload": json.loads(row.payload)} for row in rows]


@router.get("/vaults/{vault_id}/grantor")
def grantor(vault_id: UUID, request: Request):
    with request.app.state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        vault = access(connection, str(vault_id), user.id)
        keys = identity(connection, vault.grantor)
        return {"id": vault.grantor, "signing": json.loads(keys.public_keys)["signing"]}
