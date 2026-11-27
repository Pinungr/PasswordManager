from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.engine import Engine

ALEMBIC_CONFIG = Path(__file__).resolve().parents[2] / "alembic.ini"


def migrate(engine: Engine) -> str:
    config = Config(str(ALEMBIC_CONFIG))
    head = ScriptDirectory.from_config(config).get_current_head()
    if head is None:
        raise RuntimeError("No database schema revision")
    with engine.connect() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        config.attributes["connection"] = connection
        command.upgrade(config, head)
        connection.commit()
    return head
