import json
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import Field

from app.api.auth import authenticate
from app.api.contracts import Payload
from app.api.personal import Envelope, Version, payload_limit
from app.api.shared import MANAGE, SignedGrant, access, check_grant, verify_member
from app.security.accounts import audit, run, write

router = APIRouter(prefix="/api/v1/shared/vaults/{vault_id}/rotation")
PHASE = "Shared vault rotation changed. Restart the rotation with a new key."


class StageRecord(Payload):
    id: Annotated[str, Field(pattern=r"^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$")]
    crypto_version: Version
    payload: Envelope


class StageRecords(Payload):
    records: Annotated[list[StageRecord], Field(min_length=1, max_length=25)]


class Finish(Payload):
    grants: dict[str, SignedGrant]


def owned_stage(vault, stage, actor):
    if not vault.rotating or vault.stage_id != str(stage) or vault.stage_actor != actor:
        raise HTTPException(409, PHASE)


@router.post("")
def start(vault_id: UUID, request: Request):
    state = request.app.state
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection)
        vault = access(connection, str(vault_id), user.id, MANAGE)
        if not vault.rotating:
            raise HTTPException(409, "This vault has no pending key rotation.")
        stage = str(uuid4())
        run(
            connection,
            "UPDATE shared_vaults SET stage_id=:stage,stage_actor=:actor WHERE id=:id",
            stage=stage,
            actor=user.id,
            id=vault.id,
        )
        audit(connection, state.audit_key, "shared_rotation.start", user.id, vault.id)
        members = (
            run(connection, "SELECT user_id FROM shared_access WHERE vault_id=:id", id=vault.id)
            .scalars()
            .all()
        )
        return {
            "id": stage,
            "old_epoch": vault.epoch,
            "next_epoch": vault.epoch + 1,
            "members": members,
        }


@router.get("/{stage}/records")
def read_batch(
    vault_id: UUID,
    stage: UUID,
    request: Request,
    after_id: UUID | None = None,
    after_version: Annotated[int, Query(ge=0)] = 0,
):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        vault = access(connection, str(vault_id), user.id, MANAGE)
        owned_stage(vault, stage, user.id)
        rows = (
            run(
                connection,
                """SELECT record_id,crypto_version,payload FROM shared_payloads
            WHERE vault_id=:vault AND epoch=:epoch AND generation=:generation
            AND (record_id,crypto_version)>(:id,:version)
            ORDER BY record_id,crypto_version LIMIT 10""",
                vault=vault.id,
                epoch=vault.epoch,
                generation=vault.active_generation,
                id=str(after_id or ""),
                version=after_version,
            )
            .mappings()
            .all()
        )
    result = []
    total = 0
    for row in rows:
        total += len(row.payload)
        if result and total > payload_limit(state.settings):
            break
        result.append(
            {
                "id": row.record_id,
                "crypto_version": row.crypto_version,
                "payload": json.loads(row.payload),
            }
        )
    more = bool(result) and (len(rows) == 10 or len(result) < len(rows))
    return {"items": result, "more": more}


@router.put("/{stage}/records", status_code=204)
def write_batch(vault_id: UUID, stage: UUID, data: StageRecords, request: Request):
    state = request.app.state
    if any(
        len(record.payload.ciphertext) > payload_limit(state.settings) for record in data.records
    ):
        raise HTTPException(413, "Encrypted credential is too large.")
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection)
        vault = access(connection, str(vault_id), user.id, MANAGE)
        owned_stage(vault, stage, user.id)
        for row in data.records:
            original = (
                run(
                    connection,
                    """SELECT modified_by,modified_at FROM shared_payloads
                WHERE vault_id=:vault AND record_id=:record AND epoch=:epoch AND generation=:gen
                AND crypto_version=:version""",
                    vault=vault.id,
                    record=row.id,
                    epoch=vault.epoch,
                    gen=vault.active_generation,
                    version=row.crypto_version,
                )
                .mappings()
                .one_or_none()
            )
            if original is None:
                raise HTTPException(409, PHASE)
            run(
                connection,
                """INSERT INTO shared_payloads VALUES
                (:vault,:record,:epoch,:gen,:version,:payload,:user,:time)
                ON CONFLICT(vault_id,record_id,epoch,generation,crypto_version)
                DO UPDATE SET payload=excluded.payload""",
                vault=vault.id,
                record=row.id,
                epoch=vault.epoch + 1,
                gen=str(stage),
                version=row.crypto_version,
                payload=row.payload.model_dump_json(),
                user=original.modified_by,
                time=original.modified_at,
            )


@router.post("/{stage}/finish", status_code=204)
def finish(vault_id: UUID, stage: UUID, data: Finish, request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        vault = access(connection, str(vault_id), user.id, MANAGE)
        owned_stage(vault, stage, user.id)
        members = (
            run(connection, "SELECT user_id FROM shared_access WHERE vault_id=:id", id=vault.id)
            .scalars()
            .all()
        )
        if set(members) != set(data.grants):
            raise HTTPException(409, "Provide a grant for every remaining member.")
        for member, grant in data.grants.items():
            verify_member(connection, vault.team_id, member)
            check_grant(connection, grant, user.id, member, vault.id, vault.epoch + 1)

    with write(state.engine) as connection:
        user, _ = authenticate(request, connection)
        vault = access(connection, str(vault_id), user.id, MANAGE)
        owned_stage(vault, stage, user.id)
        for member in members:
            verify_member(connection, vault.team_id, member)
        if run(
            connection,
            """SELECT 1 FROM shared_payloads old WHERE old.vault_id=:vault
            AND old.epoch=:epoch AND old.generation=:old AND NOT EXISTS (
                SELECT 1 FROM shared_payloads new WHERE new.vault_id=old.vault_id
                AND new.record_id=old.record_id AND new.crypto_version=old.crypto_version
                AND new.epoch=:next AND new.generation=:stage) LIMIT 1""",
            vault=vault.id,
            epoch=vault.epoch,
            old=vault.active_generation,
            next=vault.epoch + 1,
            stage=str(stage),
        ).scalar():
            raise HTTPException(409, "Rotation has missing encrypted credential versions.")
        for member, grant in data.grants.items():
            run(
                connection,
                """UPDATE shared_access SET grantor=:user,grant=:grant
                WHERE vault_id=:id AND user_id=:member""",
                id=vault.id,
                member=member,
                user=user.id,
                grant=grant,
            )
        run(
            connection,
            """UPDATE shared_vaults SET rotating=0,epoch=epoch+1,
            active_generation=:stage,stage_id=NULL,stage_actor=NULL WHERE id=:id""",
            stage=str(stage),
            id=vault.id,
        )
        audit(connection, state.audit_key, "shared_rotation.finish", user.id, vault.id)
