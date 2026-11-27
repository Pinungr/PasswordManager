import base64
import binascii
import json
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import Field, field_validator

from app.api.auth import authenticate
from app.api.contracts import Payload
from app.security.accounts import audit, now, run, write

router = APIRouter(prefix="/api/v1/personal")
Version = Annotated[int, Field(ge=1, le=9_007_199_254_740_990)]
Encoded = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")]


def bytes_length(value):
    remainder = len(value) % 4
    if remainder == 1 or (
        remainder and ord(value[-1]) not in (b"AQgw" if remainder == 2 else b"AEIMQUYcgkosw048")
    ):
        raise ValueError("Invalid base64url")
    return len(value) * 3 // 4


class Envelope(Payload):
    version: Literal[1]
    nonce: Annotated[Encoded, Field(min_length=16, max_length=16)]
    ciphertext: Encoded

    @field_validator("ciphertext")
    @classmethod
    def authenticated_length(cls, value):
        if bytes_length(value) < 16:
            raise ValueError("Missing authentication tag")
        return value


class VaultKeys(Payload):
    profile: Literal[1]
    salt: Annotated[Encoded, Field(min_length=22, max_length=22)]
    password: Envelope
    recovery: Envelope

    @field_validator("salt")
    @classmethod
    def salt_encoding(cls, value):
        try:
            raw = base64.b64decode(value + "==", altchars=b"-_", validate=True)
            if base64.urlsafe_b64encode(raw).decode().rstrip("=") == value:
                return value
        except binascii.Error:
            pass
        raise ValueError("Invalid salt")


class Initialize(VaultKeys):
    id: Annotated[str, Field(pattern=r"^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$")]


class Rewrap(VaultKeys):
    revision: Version


class ChangeRecord(Payload):
    version: Version
    payload: Envelope


def vault_for(connection, user_id, *, required=True):
    vault = (
        run(connection, "SELECT * FROM personal_vaults WHERE owner=:user", user=user_id)
        .mappings()
        .one_or_none()
    )
    if required and vault is None:
        raise HTTPException(409, "Set up your personal vault first.")
    return vault


def check_key_length(data):
    if any(bytes_length(key.ciphertext) != 48 for key in (data.password, data.recovery)):
        raise HTTPException(422, "Invalid wrapped vault key.")


@router.get("")
def personal(request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        vault = vault_for(connection, user.id, required=False)
    return {
        "vault": None
        if vault is None
        else {
            "id": vault.id,
            "revision": vault.revision,
            "keys": json.loads(vault["keys"]),
        },
        "limits": {
            "max_fields": state.settings.max_fields_per_credential,
            "max_value_bytes": state.settings.max_field_value_bytes,
            "auto_lock_minutes": state.settings.vault_auto_lock_minutes,
            "reveal_seconds": state.settings.secret_reveal_timeout_seconds,
            "clipboard_seconds": state.settings.clipboard_clear_seconds,
        },
    }


@router.post("", status_code=201)
def initialize(data: Initialize, request: Request):
    state = request.app.state
    check_key_length(data)
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection)
        if (
            vault_for(connection, user.id, required=False)
            or run(connection, "SELECT 1 FROM personal_vaults WHERE id=:id", id=data.id).scalar()
        ):
            raise HTTPException(409, "Vault already exists.")
        run(
            connection,
            "INSERT INTO personal_vaults (id,owner,keys,revision) VALUES (:id,:owner,:keys,1)",
            id=data.id,
            owner=user.id,
            keys=data.model_dump_json(exclude={"id"}),
        )
        audit(connection, state.audit_key, "vault.initialize", user.id, data.id)
    return {"id": data.id, "revision": 1}


@router.put("/keys", status_code=204)
def rewrap(data: Rewrap, request: Request):
    state = request.app.state
    check_key_length(data)
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection)
        vault = vault_for(connection, user.id)
        if data.revision != vault.revision:
            raise HTTPException(409, "Vault keys changed. Reload and unlock again.")
        run(
            connection,
            "UPDATE personal_vaults SET keys=:keys, revision=revision+1 WHERE id=:id",
            id=vault.id,
            keys=data.model_dump_json(exclude={"revision"}),
        )
        audit(connection, state.audit_key, "vault.rewrap", user.id, vault.id)


def record(connection, vault_id, record_id):
    row = (
        run(
            connection,
            "SELECT * FROM credentials WHERE vault_id=:vault AND id=:id",
            id=record_id,
            vault=vault_id,
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise HTTPException(404, "Credential not found.")
    return row


def public(row):
    return dict(row) | {"payload": json.loads(row.payload)}


def payload_limit(settings):
    return (
        settings.max_fields_per_credential * (6 * settings.max_field_value_bytes + 1024) + 131072
    ) * 4 // 3 + 4096


def bounded_page(rows, limit, budget=2 * 1024 * 1024):
    items = []
    size = 0
    for row in rows:
        payload_size = len(row.payload)
        if len(items) == limit or (items and size + payload_size > budget):
            return items, items[-1].id
        items.append(row)
        size += payload_size
    return items, None


@router.get("/records")
def records(
    request: Request,
    cursor: UUID | None = None,
    deleted: bool = False,
    limit: Annotated[int, Query(ge=1, le=1000)] = 25,
):
    state = request.app.state
    cutoff = now() - state.settings.recycle_bin_retention_days * 86400
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        vault = vault_for(connection, user.id)
        rows = run(
            connection,
            """
            SELECT * FROM credentials WHERE vault_id=:vault AND id>:cursor
            AND ((NOT :deleted AND deleted_at IS NULL) OR (:deleted AND deleted_at>:cutoff))
            ORDER BY id LIMIT :limit""",
            vault=vault.id,
            cursor=str(cursor or ""),
            deleted=deleted,
            limit=limit + 1,
            cutoff=cutoff,
        ).mappings()
        items, cursor = bounded_page(rows, limit)
    return JSONResponse({"items": [public(row) for row in items], "cursor": cursor})


@router.put("/records/{record_id}")
def save_record(record_id: UUID, data: ChangeRecord, request: Request):
    state = request.app.state
    record_id = str(record_id)
    if len(data.payload.ciphertext) > payload_limit(state.settings):
        raise HTTPException(413, "Encrypted credential is too large.")
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection)
        vault = vault_for(connection, user.id)
        if data.version == 1:
            if run(connection, "SELECT 1 FROM credentials WHERE id=:id", id=record_id).scalar():
                raise HTTPException(409, "Credential already exists.")
            run(
                connection,
                """INSERT INTO credentials
                (id,vault_id,payload,version,crypto_version,created_at,modified_at)
                VALUES (:id,:vault,:payload,1,1,:now,:now)""",
                id=record_id,
                vault=vault.id,
                payload=data.payload.model_dump_json(),
                now=now(),
            )
            action = "credential.create"
        else:
            previous = record(connection, vault.id, record_id)
            if previous.deleted_at is not None or data.version != previous.version + 1:
                raise HTTPException(409, "Credential changed. Reload and retry.")
            run(
                connection,
                """INSERT INTO credential_history
                (credential_id,version,crypto_version,payload,modified_at)
                VALUES (:id,:version,:crypto_version,:payload,:modified_at)""",
                id=record_id,
                version=previous.version,
                crypto_version=previous.crypto_version,
                payload=previous.payload,
                modified_at=previous.modified_at,
            )
            run(
                connection,
                """UPDATE credentials SET payload=:payload, version=:version,
                crypto_version=:version, modified_at=:now WHERE id=:id""",
                id=record_id,
                payload=data.payload.model_dump_json(),
                version=data.version,
                now=now(),
            )
            run(
                connection,
                """DELETE FROM credential_history WHERE credential_id=:id AND
                version IN (SELECT version FROM credential_history WHERE credential_id=:id
                ORDER BY version DESC LIMIT -1 OFFSET :keep)""",
                id=record_id,
                keep=state.settings.password_history_limit,
            )
            action = "credential.update"
        audit(connection, state.audit_key, action, user.id, record_id)
        return public(record(connection, vault.id, record_id))


@router.get("/records/{record_id}/history")
def history(record_id: UUID, request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection)
        vault = vault_for(connection, user.id)
        current = record(connection, vault.id, str(record_id))
        if current.deleted_at is not None:
            raise HTTPException(409, "Restore the credential to open its history.")
        rows = (
            run(
                connection,
                "SELECT * FROM credential_history WHERE credential_id=:id ORDER BY version DESC",
                id=current.id,
            )
            .mappings()
            .all()
        )
    return [public(row) for row in rows]


@router.post("/records/{record_id}/{action}", status_code=204)
def record_action(
    record_id: UUID,
    action: Literal["delete", "restore", "purge", "copy", "reveal"],
    version: Version,
    request: Request,
):
    state = request.app.state
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection)
        vault = vault_for(connection, user.id)
        row = record(connection, vault.id, str(record_id))
        moment = now()
        cutoff = moment - state.settings.recycle_bin_retention_days * 86400
        if row.version != version:
            raise HTTPException(409, "Credential changed. Reload and retry.")
        if action in {"restore", "purge"}:
            if row.deleted_at is None or row.deleted_at <= cutoff:
                raise HTTPException(409, "Credential is unavailable in the recycle bin.")
            if action == "purge":
                run(connection, "DELETE FROM credentials WHERE id=:id", id=row.id)
            else:
                run(
                    connection,
                    "UPDATE credentials SET deleted_at=NULL,version=version+1 WHERE id=:id",
                    id=row.id,
                )
        else:
            if row.deleted_at is not None:
                raise HTTPException(409, "Credential is in the recycle bin.")
            if action == "delete":
                run(
                    connection,
                    "UPDATE credentials SET deleted_at=:now,version=version+1 WHERE id=:id",
                    now=moment,
                    id=row.id,
                )
            else:
                run(
                    connection,
                    "UPDATE credentials SET last_used=:now WHERE id=:id",
                    now=moment,
                    id=row.id,
                )
        event = (
            f"credential.client_{action}"
            if action in {"reveal", "copy"}
            else f"credential.{action}"
        )
        audit(connection, state.audit_key, event, user.id, row.id)
