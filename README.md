# Pinaki SecureVault

## Deploy with Docker Compose

### Linux

Install Docker with the Compose plugin, Git, and OpenSSL. The [`.env_example`](.env_example) template lists the four variables. The commands below clone the repo and create a private `.env` with fresh values.

```sh
git clone https://github.com/Pinungr/PasswordManager.git
cd PasswordManager
(
  set -euC
  umask 077
  database_key=$(openssl rand -hex 32)
  audit_key=$(openssl rand -hex 32)
  backup_key=$(openssl rand -hex 32)
  bootstrap_password=$(openssl rand -hex 16)
  cat > .env <<EOF
SECUREVAULT_DATABASE_KEY=$database_key
SECUREVAULT_AUDIT_KEY=$audit_key
SECUREVAULT_BACKUP_KEY=$backup_key
SECUREVAULT_BOOTSTRAP_PASSWORD=$bootstrap_password
EOF
)
docker compose up -d --wait
```

Compose builds the image on the first run. The app creates the `admin` account and initializes SQLCipher and localhost HTTPS in the Docker data volume. Use the bootstrap password in `.env` to sign in at [https://localhost:18443/](https://localhost:18443/), then change it when prompted. After changing it, remove `SECUREVAULT_BOOTSTRAP_PASSWORD` from `.env`.

Before opening the UI, trust the generated local CA on the machine running your browser. On Debian or Ubuntu, run the following on the Docker host and restart the browser.

```sh
ca_dir=$(mktemp -d)
docker compose cp securevault:/data/tls/tls-ca.pem "$ca_dir/pinaki-securevault-ca.crt"
sudo install -m 0644 "$ca_dir/pinaki-securevault-ca.crt" /usr/local/share/ca-certificates/pinaki-securevault-ca.crt
rm "$ca_dir/pinaki-securevault-ca.crt"
rmdir "$ca_dir"
sudo update-ca-certificates
```

For other Linux distributions or a browser that manages its own certificate store, import the same CA file into the trusted authorities. For network access, set `SECUREVAULT_HOST_MODE=network`, `SECUREVAULT_HOSTNAME`, and `SECUREVAULT_PUBLISH_IP` in `.env`. Place an approved certificate for that hostname, its private key, and its CA bundle in `deploy/tls` as `tls-cert.pem`, `tls-key.pem`, and `tls-ca.pem`. The container user (UID 10001) needs read access to those files.

### Windows

Open PowerShell 7.4 or later in the project directory with Docker Desktop running in Linux container mode.

```powershell
.\scripts\new-local-tls.ps1 -TrustForCurrentUser
.\scripts\install.ps1 -Build -Bootstrap
```

Approve the SecureVault CA in the Windows trust prompt. The installer creates a private `.env` and prompts you to create the first administrator. Enter `admin` as the username and choose an initial password. Open [SecureVault](https://localhost:18443/) and change that password at first sign-in.

For an existing installation, keep its `.env`, TLS files, and Docker data volume. Start or update the app from the project directory.

```sh
docker compose up -d --wait
```

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
