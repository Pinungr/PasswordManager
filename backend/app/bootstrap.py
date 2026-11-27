import os
import sys
from getpass import getpass
from pathlib import Path

from fastapi import HTTPException
from pydantic import ValidationError

from app.api.contracts import NewUser
from app.core.config import ACCOUNT_PASSWORD_MIN_LENGTH, Settings, load_settings, read_hex_secret
from app.database.connection import make_engine
from app.database.migrate import migrate
from app.security.accounts import create_user, new_password, run, write


def has_accounts(engine) -> bool:
    with engine.connect() as connection:
        return bool(run(connection, "SELECT 1 FROM users LIMIT 1").scalar())


def create_first_administrator(engine, settings: Settings, audit_key: bytes, data, minimum) -> bool:
    password_hash = new_password(data.password, minimum)
    with write(engine) as connection:
        if run(connection, "SELECT 1 FROM users LIMIT 1").scalar():
            return False
        create_user(connection, audit_key, settings.max_registered_users, data, password_hash)
    return True


def bootstrap_from_environment(engine, settings: Settings, audit_key: bytes) -> None:
    password = os.environ.get("SECUREVAULT_BOOTSTRAP_PASSWORD")
    if not password or has_accounts(engine):
        return

    minimum = (
        ACCOUNT_PASSWORD_MIN_LENGTH
        if settings.host_mode == "local"
        else settings.account_password_min_length
    )
    try:
        data = NewUser(
            username=os.environ.get("SECUREVAULT_BOOTSTRAP_USERNAME", "admin"),
            full_name=os.environ.get("SECUREVAULT_BOOTSTRAP_FULL_NAME", "Administrator"),
            password=password,
            role="ADMIN",
        )
        create_first_administrator(engine, settings, audit_key, data, minimum)
    except (HTTPException, ValidationError):
        raise RuntimeError(
            f"Check the bootstrap username and name, and use a temporary password "
            f"of at least {minimum} characters and at most 512 UTF-8 bytes."
        ) from None


def main() -> None:
    if not sys.stdin.isatty():
        raise SystemExit("Run administrator bootstrap in an interactive terminal.")
    settings = load_settings()
    database_key = read_hex_secret("SECUREVAULT_DATABASE_KEY")
    audit_key = read_hex_secret("SECUREVAULT_AUDIT_KEY")
    if audit_key == database_key:
        raise SystemExit("Provision independent database and audit keys.")
    engine = make_engine(Path("/data/database/securevault.db"), database_key)
    try:
        migrate(engine)
        if has_accounts(engine):
            raise SystemExit("Administrator bootstrap has already been completed.")
        username = input("Administrator username: ")
        full_name = input("Full name: ")
        password = getpass("Initial account password: ")
        if password != getpass("Confirm initial account password: "):
            raise SystemExit("Passwords do not match.")
        data = NewUser(username=username, full_name=full_name, password=password, role="ADMIN")
        if not create_first_administrator(
            engine, settings, bytes.fromhex(audit_key), data, settings.account_password_min_length
        ):
            raise SystemExit("Administrator bootstrap has already been completed.")
    except (HTTPException, ValidationError):
        raise SystemExit(
            "Use a valid username and a password of the configured minimum length."
        ) from None
    finally:
        engine.dispose()
    print("Administrator created. Change the initial account password at first sign-in.")


if __name__ == "__main__":
    main()
