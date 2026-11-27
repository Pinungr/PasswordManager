import re
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.pool import QueuePool
from sqlcipher3 import dbapi2

PRAGMAS = {"journal_mode": "wal", "busy_timeout": 5000, "foreign_keys": 1, "synchronous": 2}
ASSIGNMENTS = {
    "journal_mode": "WAL",
    "busy_timeout": "5000",
    "foreign_keys": "ON",
    "synchronous": "FULL",
}


def connect(path: Path, key: str):
    if re.fullmatch(r"[0-9a-f]{64}", key) is None:
        raise ValueError("SQLCipher requires a validated raw key")
    connection = dbapi2.connect(str(path), timeout=5, check_same_thread=False)
    try:
        if not connection.execute("PRAGMA cipher_version").fetchone():
            raise RuntimeError("SQLCipher is unavailable")
        # PRAGMA key cannot bind parameters. Only validated hexadecimal reaches this statement.
        connection.execute(f"""PRAGMA key = "x'{key}'" """)
        connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
        for name, expected in PRAGMAS.items():
            if connection.execute(f"PRAGMA {name}").fetchone() != (expected,):
                connection.execute(f"PRAGMA {name} = {ASSIGNMENTS[name]}")
            if connection.execute(f"PRAGMA {name}").fetchone() != (expected,):
                raise RuntimeError(f"Unable to verify database PRAGMA {name}")
        return connection
    except BaseException:
        connection.close()
        raise


def make_engine(path: Path, key: str) -> Engine:
    return create_engine(
        "sqlite://",
        module=dbapi2,
        creator=lambda: connect(path, key),
        poolclass=QueuePool,
        pool_size=5,
        max_overflow=0,
        pool_timeout=5,
        pool_pre_ping=True,
        hide_parameters=True,
    )
