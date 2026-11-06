from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.core.config import get_settings
from app.db.base import Base
from app.db.init_db import load_model_metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

load_model_metadata()
target_metadata = Base.metadata


def get_database_url() -> str:
    import os
    if os.getenv("MIGRATION_DATABASE_URL"):
        return os.environ["MIGRATION_DATABASE_URL"]
    return get_settings().sqlalchemy_database_uri


def run_migrations_offline() -> None:
    context.configure(
        url=get_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    # engine_from_config receives the URL directly, bypassing ConfigParser's
    # interpolation of percent-escaped database credentials.
    configuration["sqlalchemy.url"] = get_database_url()

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
