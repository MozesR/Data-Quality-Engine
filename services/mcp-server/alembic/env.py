from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Alembic Config object, providing access to values in alembic.ini.
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def get_database_url() -> str:
    # Prefer runtime env over ini; matches app behavior.
    return os.getenv("DATABASE_URL", "")


def run_migrations_offline() -> None:
    url = get_database_url()
    if not url:
        raise RuntimeError("DATABASE_URL is required for Alembic offline migrations")
    context.configure(url=url, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = get_database_url()
    if not url:
        raise RuntimeError("DATABASE_URL is required for Alembic online migrations")
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = url
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

