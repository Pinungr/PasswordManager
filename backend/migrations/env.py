from alembic import context

if context.is_offline_mode():
    raise RuntimeError("Migrations require a live SQLCipher connection")

connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("Run migrations through the SecureVault startup command")

context.configure(connection=connection, render_as_batch=True)
with context.begin_transaction():
    context.run_migrations()
