import re
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import Field

from app.api.auth import authenticate
from app.api.contracts import Payload
from app.security.accounts import audit, run, write

router = APIRouter(prefix="/api/v1")
Kind = Literal["categories", "environments"]


class Entry(Payload):
    name: Annotated[str, Field(min_length=1, max_length=200, pattern=r"\S")]
    description: Annotated[str, Field(max_length=1000)] = ""
    appearance: Annotated[str, Field(max_length=32)]
    active: bool = True


@router.get("/catalog/{kind}")
def list_entries(kind: Kind, request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        authenticate(request, connection)
        rows = run(
            connection,
            "SELECT id,name,description,appearance,active FROM catalog"
            " WHERE kind=:kind ORDER BY name",
            kind=kind,
        ).mappings()
        return [dict(row) for row in rows]


def save_entry(kind, entry_id, data, request):
    if kind == "environments" and not re.fullmatch(r"#[a-fA-F0-9]{6}", data.appearance):
        raise HTTPException(422, "Enter a six-digit environment color.")
    if kind == "categories" and data.appearance not in {
        "key",
        "globe",
        "database",
        "terminal",
        "file",
    }:
        raise HTTPException(422, "Choose a category icon.")
    state = request.app.state
    with write(state.engine) as connection:
        user, _ = authenticate(request, connection, admin=True)
        identifier = entry_id or str(uuid4())
        if run(
            connection,
            "SELECT 1 FROM catalog WHERE kind=:kind AND name=:name AND id<>:id",
            kind=kind,
            name=data.name,
            id=identifier,
        ).scalar():
            raise HTTPException(409, "Name already in use.")
        if entry_id:
            updated = run(
                connection,
                "UPDATE catalog SET name=:name,description=:description,"
                " appearance=:appearance,active=:active WHERE kind=:kind AND id=:id",
                kind=kind,
                id=identifier,
                **data.model_dump(),
            )
            if not updated.rowcount:
                raise HTTPException(404, "Entry not found.")
        else:
            run(
                connection,
                "INSERT INTO catalog (id,kind,name,description,appearance,active)"
                " VALUES (:id,:kind,:name,:description,:appearance,:active)",
                id=identifier,
                kind=kind,
                **data.model_dump(),
            )
        audit(
            connection,
            state.audit_key,
            kind + (".update" if entry_id else ".create"),
            user.id,
            identifier,
        )
    return {"id": identifier, **data.model_dump()}


@router.post("/catalog/{kind}", status_code=201)
def create_entry(kind: Kind, data: Entry, request: Request):
    return save_entry(kind, None, data, request)


@router.put("/catalog/{kind}/{entry_id}")
def edit_entry(
    kind: Kind, entry_id: Annotated[str, Field(max_length=36)], data: Entry, request: Request
):
    return save_entry(kind, entry_id, data, request)
