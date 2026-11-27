# Pinaki SecureVault

## Deploy with Docker Compose

On a fresh Windows installation, open PowerShell 7.4 or later in the project directory with Docker Desktop running in Linux container mode.

```powershell
.\scripts\new-local-tls.ps1 -TrustForCurrentUser
.\scripts\install.ps1 -Build -Bootstrap
```

Approve the SecureVault CA in the Windows trust prompt. The installer creates a private `.env` and prompts you to create the first administrator. Enter `admin` as the username and choose an initial password. Open [SecureVault](https://localhost:18443/) and change that password at first sign-in.

For an existing installation, keep its `.env`, TLS files, and Docker data volume. Build and start the app from the project directory.

```sh
docker compose up -d --build --wait
```

On Linux, place your certificate, private key, and CA trust bundle in `deploy/tls` as `tls-cert.pem`, `tls-key.pem`, and `tls-ca.pem`. Ensure the container user (UID 10001) can read them. Set `SECUREVAULT_DATABASE_KEY`, `SECUREVAULT_AUDIT_KEY`, and `SECUREVAULT_BACKUP_KEY` in a private `.env`. Generate each key separately with `openssl rand -hex 32`. Run the Compose command above, then run `docker compose exec securevault python -m app.bootstrap` to create the administrator. For network access, use a certificate for the configured hostname and set `SECUREVAULT_HOST_MODE=network`, `SECUREVAULT_HOSTNAME`, and `SECUREVAULT_PUBLISH_IP` in `.env`.

You can also set `SECUREVAULT_BOOTSTRAP_PASSWORD` in `.env` to create the default `admin` account automatically on an empty database. After the first sign-in and password change, remove the bootstrap value from `.env`.

## Connect to the database

The app uses SQLCipher at `/data/database/securevault.db` inside the container. The database lives in the Docker data volume. There is no database port. For read-only inspection, start the container's Python shell.

```sh
docker compose exec securevault python -i
```

Paste these lines into the Python shell. The connection uses the configured database key without printing it, and the example lists table names.

```python
from app.core.config import read_hex_secret
from sqlcipher3 import dbapi2

db = dbapi2.connect("file:/data/database/securevault.db?mode=ro", uri=True)
db.execute(f"""PRAGMA key = "x'{read_hex_secret('SECUREVAULT_DATABASE_KEY')}'" """)
print(db.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").fetchall())
db.close()
exit()
```

Use **Backup & restore** in the admin UI for encrypted backups. Keep the private `.env` backed up separately so you can restore the database and its backups.

## Personal accounts

Users can select **Create an account** on the sign-in screen. Self-signup accounts are hidden from the admin directory and audit views. An administrator who knows the username can set a temporary sign-in password under **Users → Reset private account password**. The user must replace it at sign-in. Vault access still requires the separate vault master password or recovery key.
