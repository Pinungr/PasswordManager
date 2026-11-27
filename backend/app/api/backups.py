from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from sqlcipher3 import dbapi2

from app.api.auth import authenticate
from app.api.contracts import NewPassword
from app.database.backups import verify_database
from app.security.accounts import audit, matches, write

router = APIRouter(prefix="/api/v1/backups")


def storage_for(request):
    storage = request.app.state.backups
    if storage is None:
        raise HTTPException(503, "Backup storage is unavailable.")
    return storage


def info(path):
    status = path.stat()
    return {"name": path.name, "bytes": status.st_size, "timestamp": int(status.st_mtime)}


@router.get("")
def backups(request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        authenticate(request, connection, admin=True)
    storage = storage_for(request)
    with storage.lock:
        return {
            "items": [info(path) for path in storage.listing()[:100]],
            "pending_restore": storage.staging.exists(),
            "schedule": state.settings.backup_schedule,
            "retention_days": state.settings.backup_retention_days,
            "timezone": state.settings.timezone,
        }


@router.post("", status_code=201)
def create(request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection, admin=True)
    storage = storage_for(request)
    if not storage.lock.acquire(blocking=False):
        raise HTTPException(409, "A backup operation is in progress.")
    try:
        path = storage.create()
        with write(state.engine) as connection:
            audit(connection, state.audit_key, "backup.create", user.id, path.name)
        return info(path)
    except (OSError, ValueError, dbapi2.DatabaseError):
        raise HTTPException(503, "Backup could not be created.") from None
    finally:
        storage.lock.release()


@router.get("/{name}/export")
def download(name: str, request: Request):
    with request.app.state.engine.connect() as connection:
        authenticate(request, connection, admin=True)
    try:
        path = storage_for(request).resolve(name)
    except FileNotFoundError:
        raise HTTPException(404, "Backup not found.") from None
    return FileResponse(path, media_type="application/octet-stream", filename=path.name)


@router.post("/{name}/verify")
def verify(name: str, request: Request):
    with request.app.state.engine.connect() as connection:
        authenticate(request, connection, admin=True)
    storage = storage_for(request)
    with storage.lock:
        try:
            verify_database(storage.resolve(name), storage.backup_key)
        except FileNotFoundError:
            raise HTTPException(404, "Backup not found.") from None
        except (OSError, ValueError, dbapi2.DatabaseError):
            raise HTTPException(422, "Backup verification failed.") from None
    return {"verified": True}


class Restore(NewPassword):
    confirmation: Literal["RESTORE"]


@router.post("/{name}/restore", status_code=202)
def restore(name: str, data: Restore, request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection, admin=True)
    if not matches(user.password_hash, data.password):
        raise HTTPException(403, "Administrator reauthentication failed.")
    storage = storage_for(request)
    if not storage.lock.acquire(blocking=False):
        raise HTTPException(409, "A backup operation is in progress.")
    try:
        with state.engine.connect() as connection:
            fresh, _ = authenticate(request, connection, admin=True)
            if fresh.password_hash != user.password_hash:
                raise HTTPException(409, "Account changed. Reauthenticate.")
        if storage.staging.exists():
            raise HTTPException(409, "A database restore is already staged.")
        storage.stage(name, state.revision)
        with write(state.engine) as connection:
            audit(connection, state.audit_key, "backup.restore_stage", user.id, name)
    except FileNotFoundError:
        raise HTTPException(404, "Backup not found.") from None
    except (OSError, ValueError, dbapi2.DatabaseError):
        raise HTTPException(422, "Backup could not be staged safely.") from None
    finally:
        storage.lock.release()
    return {"pending_restart": True}


@router.post("/retention")
def retention(request: Request):
    state = request.app.state
    with state.engine.connect() as connection:
        user, _ = authenticate(request, connection, admin=True)
    storage = storage_for(request)
    with storage.lock:
        count = storage.retention(state.settings.backup_retention_days)
    if count:
        with write(state.engine) as connection:
            audit(connection, state.audit_key, "backup.delete_expired", user.id)
    return {"deleted": count}
