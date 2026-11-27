import asyncio
import logging
from contextlib import suppress
from time import monotonic

from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlcipher3 import dbapi2

from app.security.accounts import audit, now, run, write

log = logging.getLogger(__name__)


def prune(engine, days):
    cutoff = now() - days * 86400
    with write(engine) as connection:
        run(
            connection,
            """DELETE FROM credentials WHERE id IN (
            SELECT id FROM credentials WHERE deleted_at <= :cutoff ORDER BY deleted_at LIMIT 500
        )""",
            cutoff=cutoff,
        )
        run(
            connection,
            """DELETE FROM shared_records WHERE rowid IN (
            SELECT r.rowid FROM shared_records r JOIN shared_vaults v ON v.id=r.vault_id
            WHERE r.deleted_at<=:cutoff AND v.rotating=0 ORDER BY r.deleted_at LIMIT 500
        )""",
            cutoff=cutoff,
        )
        run(
            connection,
            """DELETE FROM shared_payloads WHERE rowid IN (
            SELECT p.rowid FROM shared_payloads p JOIN shared_vaults v ON v.id=p.vault_id
            WHERE NOT (p.epoch=v.epoch AND p.generation=v.active_generation)
            AND (v.stage_id IS NULL OR p.generation<>v.stage_id) LIMIT 500
        )""",
        )


def scheduled_backup(engine, state):
    storage = state.backups
    if storage is None or not storage.lock.acquire(blocking=False):
        return
    try:
        settings = state.settings
        if not storage.staging.exists() and storage.due(settings):
            verified = storage.create()
            with write(engine) as connection:
                audit(connection, state.audit_key, "backup.create", target=verified.name)
            storage.retention(settings.backup_retention_days)
    finally:
        storage.lock.release()


async def maintenance(engine, state, stop):
    next_prune = 0
    while not stop.is_set():
        try:
            if monotonic() >= next_prune:
                if not state.backups or not state.backups.staging.exists():
                    await asyncio.to_thread(
                        prune, engine, state.settings.recycle_bin_retention_days
                    )
                next_prune = monotonic() + 3600
            await asyncio.to_thread(scheduled_backup, engine, state)
        except (SQLAlchemyError, dbapi2.DatabaseError, OSError, ValueError, HTTPException):
            log.warning("Scheduled storage maintenance deferred")
        with suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=60)
