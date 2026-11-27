import os
from pathlib import Path

import uvicorn

from app.core.config import load_settings, read_hex_secret
from app.core.tls import tls_paths
from app.database.backups import BackupStorage
from app.main import create_app

ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    settings = load_settings()
    key = read_hex_secret("SECUREVAULT_DATABASE_KEY")
    audit_key = read_hex_secret("SECUREVAULT_AUDIT_KEY")
    backup_key = read_hex_secret("SECUREVAULT_BACKUP_KEY")
    if len({key, audit_key, backup_key}) != 3:
        raise ValueError("Provision independent database, audit and backup keys")
    data = Path(os.environ.get("SECUREVAULT_DATA_DIR", "/data"))
    database = data / "database" / "securevault.db"
    for directory in (database.parent, data / "backups", data / "logs"):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    frontend = ROOT / "frontend" / "dist"
    if not (frontend / "index.html").is_file():
        raise RuntimeError("Build the frontend before starting SecureVault")
    certificate, private_key, _ = tls_paths(data, settings.host_mode, initialize=True)
    uvicorn.run(
        create_app(
            settings,
            database,
            key,
            frontend,
            bytes.fromhex(audit_key),
            BackupStorage(database, data / "backups", key, backup_key),
        ),
        host=os.environ.get("SECUREVAULT_INTERNAL_HOST", "127.0.0.1"),
        port=int(os.environ.get("SECUREVAULT_INTERNAL_PORT", str(settings.https_port))),
        ssl_certfile=str(certificate),
        ssl_keyfile=str(private_key),
        access_log=False,
        log_level=settings.log_level.lower(),
        proxy_headers=False,
        server_header=False,
        timeout_graceful_shutdown=20,
        limit_concurrency=128,
    )


if __name__ == "__main__":
    os.umask(0o077)
    main()
