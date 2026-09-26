import asyncio
import logging
from logging.config import fileConfig

from sqlalchemy import pool, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

logger = logging.getLogger("alembic.env")

# CYBERGUARD: all models live on the dedicated "cyberguard" schema.
from app.core.config import get_settings
from app.db.base import Base
import app.db.models  # noqa: F401 - populate Base.metadata

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Migrations run with the service/postgres role (MIGRATION_DATABASE_URL) so
# they can create schemas and manage RLS policies, bypassing row-level
# security. Falls back to DATABASE_URL (e.g. SQLite for local checks).
import os

_env_url = os.environ.get("MIGRATION_DATABASE_URL") or os.environ.get("DATABASE_URL")
if _env_url and _env_url.strip():
    _migration_url = _env_url.strip()
else:
    _settings = get_settings()
    _migration_url = (_settings.MIGRATION_DATABASE_URL or _settings.DATABASE_URL).strip()

if _migration_url.startswith("postgres://"):
    _migration_url = _migration_url.replace("postgres://", "postgresql+asyncpg://", 1)
elif _migration_url.startswith("postgresql://") and not _migration_url.startswith("postgresql+asyncpg://"):
    _migration_url = _migration_url.replace("postgresql://", "postgresql+asyncpg://", 1)
config.set_main_option("sqlalchemy.url", _migration_url)

# add your model's MetaData object here
# for 'autogenerate' support
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=True,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    # Self-healing: the cyberguard schema may be missing entirely (fresh
    # database, wiped schema). Create it before any migration runs.
    from app.db.base import SCHEMA

    try:
        connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{SCHEMA}"'))
        connection.commit()
        logger.info("ensured schema '%s' exists", SCHEMA)
    except Exception as exc:  # noqa: BLE001 - degrade with a clear message
        logger.warning("could not ensure schema '%s' (continuing): %s", SCHEMA, exc)

    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_schemas=True,
        compare_type=True,
    )

    # Fresh DB Optimization: If cyberguard has no tables and we are upgrading to 0102_squash_baseline,
    # skip the deprecated historical 0001-0101 migrations and jump straight to 0102 squashed baseline.
    # Mirror on downgrade: 0102's downgrade drops the whole cyberguard schema, so the
    # legacy 0101..0001 downgrade steps after it would run against a dropped schema and
    # fail. Truncate the downgrade path at the squash step — base state is "schema gone".
    mig_ctx = context.get_context()
    orig_migrations_fn = getattr(mig_ctx, "_migrations_fn", None)
    if orig_migrations_fn is not None:
        def wrapped_migrations_fn(heads, mc):
            table_count = connection.execute(
                text("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'cyberguard'")
            ).scalar() or 0
            steps = list(orig_migrations_fn(heads, mc))
            squash_idx = next(
                (
                    i for i, s in enumerate(steps)
                    if getattr(getattr(s, "revision", None), "revision", None) == "0102_squash_baseline"
                ),
                None,
            )
            if squash_idx is not None:
                step = steps[squash_idx]
                if getattr(step, "is_upgrade", False):
                    if table_count <= 10:
                        logger.info("Fresh database detected (tables=%d): applying 0102_squash_baseline directly", table_count)
                        yield step
                        return
                else:
                    logger.info("Squash baseline downgrade: truncating deprecated 0101..0001 chain (schema already dropped by 0102)")
                    for s in steps[:squash_idx + 1]:
                        yield s
                    return
            for step in steps:
                yield step

        mig_ctx._migrations_fn = wrapped_migrations_fn

    with context.begin_transaction():
        context.run_migrations()
    connection.commit()


async def run_async_migrations() -> None:
    """In this scenario we need to create an Engine
    and associate a connection with the context.
    """

    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    try:
        async with connectable.connect() as connection:
            await connection.run_sync(do_run_migrations)
    except Exception:
        logger.exception(
            "Migration failed. Troubleshooting: (1) check MIGRATION_DATABASE_URL / "
            "DATABASE_URL in backend/.env, (2) the role must own the database to "
            "CREATE SCHEMA, (3) if a stale alembic_version table exists in the "
            "public schema, drop it before re-baselining."
        )
        raise
    finally:
        await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""

    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
