import os
import re
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from time import time
from uuid import uuid4
from zoneinfo import ZoneInfo

from sqlcipher3 import dbapi2

from app.database.connection import connect

BACKUP_NAME = re.compile(r"securevault-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\.db")


def open_snapshot(path: Path, key: str):
    if not path.is_file() or re.fullmatch(r"[a-f0-9]{64}", key) is None:
        raise ValueError("Invalid encrypted database")
    connection = dbapi2.connect(path.as_uri() + "?mode=rw", uri=True, timeout=5)
    try:
        connection.execute(f"""PRAGMA key = "x'{key}'" """)
        if not connection.execute("PRAGMA cipher_version").fetchone():
            raise ValueError("SQLCipher is unavailable")
        return connection
    except BaseException:
        connection.close()
        raise


def verify_database(path: Path, key: str):
    with closing(open_snapshot(path, key)) as connection:
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError("Database integrity failed")
        if connection.execute("PRAGMA cipher_integrity_check").fetchall():
            raise ValueError("Database page authentication failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("Database foreign-key validation failed")
        row = connection.execute("SELECT version_num FROM alembic_version").fetchone()
        if not row:
            raise ValueError("Database schema revision is missing")
        return row[0]


def sync_directory(directory):
    if os.name == "posix":
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def export_encrypted(source: Path, destination: Path, source_key: str, destination_key: str):
    for key in (source_key, destination_key):
        if re.fullmatch(r"[a-f0-9]{64}", key) is None:
            raise ValueError("Invalid SQLCipher key")
    if not source.is_file() or destination.exists():
        raise ValueError("Unexpected SQLCipher source or destination")
    temporary = destination.with_name("." + destination.name + "." + uuid4().hex + ".tmp")
    try:
        with closing(open_snapshot(source, source_key)) as connection:
            connection.execute("PRAGMA busy_timeout=5000")
            # The filename is bound. SQLCipher's raw-key syntax is supplied as validated hex.
            connection.execute(
                f"""ATTACH DATABASE ? AS backup KEY "x'{destination_key}'" """,
                (str(temporary),),
            )
            connection.execute("PRAGMA backup.synchronous=FULL")
            connection.execute("BEGIN")
            connection.execute("SELECT sqlcipher_export('backup')").fetchone()
            connection.commit()
            connection.execute("DETACH DATABASE backup")
        verify_database(temporary, destination_key)
        with temporary.open("r+b") as file:
            os.fsync(file.fileno())
        os.replace(temporary, destination)
        sync_directory(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)


@dataclass
class BackupStorage:
    database: Path
    directory: Path
    database_key: str = field(repr=False)
    backup_key: str = field(repr=False)
    lock: Lock = field(default_factory=Lock, repr=False)

    @property
    def staging(self):
        return self.database.with_name("securevault.restore")

    def resolve(self, name):
        if not BACKUP_NAME.fullmatch(name):
            raise FileNotFoundError("Backup not found")
        path = self.directory / name
        if path.is_symlink() or not path.is_file():
            raise FileNotFoundError("Backup not found")
        return path

    def listing(self):
        return sorted(
            (
                path
                for path in self.directory.iterdir()
                if BACKUP_NAME.fullmatch(path.name) and not path.is_symlink() and path.is_file()
            ),
            reverse=True,
        )

    def create(self):
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        path = self.directory / f"securevault-{stamp}-{uuid4().hex[:12]}.db"
        export_encrypted(self.database, path, self.database_key, self.backup_key)
        return path

    def retention(self, days):
        cutoff = time() - days * 86400
        removed = 0
        for path in self.listing():
            if path.stat().st_mtime < cutoff:
                path.unlink()
                removed += 1
        return removed

    def due(self, settings):
        zone = ZoneInfo(settings.timezone)
        local = datetime.now(zone)
        interval = local.strftime("%H:%M")
        return interval >= settings.backup_schedule and not any(
            datetime.fromtimestamp(path.stat().st_mtime, zone).date() == local.date()
            for path in self.listing()[:1]
        )

    def stage(self, name, revision):
        if self.staging.exists():
            raise ValueError("A restore is already staged")
        source = self.resolve(name)
        if verify_database(source, self.backup_key) not in {revision, "0006_preferences"}:
            raise ValueError("Backup schema is incompatible with the running application")
        candidate = self.staging.with_name(".restore-" + uuid4().hex + ".tmp")
        export_encrypted(source, candidate, self.backup_key, self.database_key)
        # Remove restored sessions before accepting the staged file.
        try:
            with closing(open_snapshot(candidate, self.database_key)) as connection:
                connection.execute("DELETE FROM user_sessions")
                connection.commit()
            verify_database(candidate, self.database_key)
            with candidate.open("r+b") as file:
                os.fsync(file.fileno())
            os.replace(candidate, self.staging)
            sync_directory(self.database.parent)
        finally:
            candidate.unlink(missing_ok=True)

    def apply(self, revision):
        if not self.staging.exists():
            return False
        if verify_database(self.staging, self.database_key) not in {revision, "0006_preferences"}:
            raise ValueError("Staged restore schema is incompatible")
        self.create()
        with closing(connect(self.database, self.database_key)) as connection:
            result = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if not result or result[0] != 0:
                raise RuntimeError("Live database checkpoint is busy")
        # All application connections are closed before this path runs.
        os.replace(self.staging, self.database)
        sync_directory(self.database.parent)
        return True
