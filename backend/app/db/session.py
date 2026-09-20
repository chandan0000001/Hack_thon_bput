"""Database engine, session management, and startup initialization."""

import logging
from contextvars import ContextVar
from typing import AsyncGenerator, Optional

from sqlalchemy import event, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.base import SCHEMA, Base

logger = logging.getLogger("cyberguard.db")

settings = get_settings()

# Per-request identity used to satisfy PostgreSQL row-level security via the
# ``app.user_id`` GUC. Set by app.core.security once the bearer token is
# verified (which happens *after* get_db has yielded its session, hence the
# lazy per-transaction application below instead of a set_config at acquire).
current_user_id: ContextVar[Optional[str]] = ContextVar("current_user_id", default=None)

# Engine creation: supports asyncpg (PostgreSQL) and aiosqlite (SQLite)
connect_args = {}
is_sqlite = "sqlite" in settings.async_database_url
if is_sqlite:
    connect_args["check_same_thread"] = False
    connect_args["timeout"] = 30
else:
    # On PostgreSQL, ensure the app engine operates as the cyberguard_api app role (NOBYPASSRLS)
    # so that Row-Level Security policies are strictly enforced even if DATABASE_URL
    # was configured using a superuser account (e.g. postgres:postgres in local dev).
    connect_args["server_settings"] = {"role": "cyberguard_api"}

engine_options = {}
if is_sqlite:
    engine_options["execution_options"] = {"schema_translate_map": {SCHEMA: None}}

engine = create_async_engine(
    settings.async_database_url,
    echo=False,
    future=True,
    connect_args=connect_args,
    **engine_options,
)

_GUC_SQL = text(
    "select set_config('app.user_id', :uid, false), set_config('request.role', :role, false)"
)
_GUC_RESET_SQL = text(
    "select set_config('app.user_id', '', false), set_config('request.role', '', false)"
)


def _is_postgres(session: Session) -> bool:
    bind = session.bind
    return bind is not None and bind.dialect.name == "postgresql"


@event.listens_for(Session, "after_begin")
def _apply_request_gucs(session: Session, transaction, connection) -> None:
    """Stamp app.user_id / request.role onto every new transaction (PG only)."""
    if not _is_postgres(session):
        return
    uid = current_user_id.get()
    connection.execute(
        _GUC_SQL,
        {"uid": uid or "", "role": "authenticated" if uid else ""},
    )


async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an AsyncSession."""
    async with async_session_maker() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            if _is_postgres(session):
                try:
                    await session.execute(_GUC_RESET_SQL)
                except Exception:  # noqa: S110 - reset is best-effort cleanup
                    pass
            await session.close()


DEFAULT_RESPONSE_CATALOG = [
    {
        "action": "Block suspicious URL",
        "target_type": "url",
        "automation_level": "semi-automatic",
        "requires_approval": True,
        "description": "Add the URL to the blocklist and deny access from managed endpoints.",
    },
    {
        "action": "Quarantine email",
        "target_type": "email",
        "automation_level": "semi-automatic",
        "requires_approval": True,
        "description": "Move the suspicious email out of user inboxes into quarantine.",
    },
    {
        "action": "Warn the user",
        "target_type": "user",
        "automation_level": "automatic",
        "requires_approval": False,
        "description": "Notify the targeted user about the threat and safe handling steps.",
    },
    {
        "action": "Require additional authentication",
        "target_type": "session",
        "automation_level": "automatic",
        "requires_approval": False,
        "description": "Force step-up authentication (e.g. MFA) for the affected account.",
    },
    {
        "action": "Revoke active session",
        "target_type": "session",
        "automation_level": "semi-automatic",
        "requires_approval": True,
        "description": "Terminate the suspicious session and force re-authentication.",
    },
    {
        "action": "Block suspicious IP/device",
        "target_type": "network",
        "automation_level": "semi-automatic",
        "requires_approval": True,
        "description": "Block the flagged IP address or device identifier at the perimeter.",
    },
    {
        "action": "Flag multimedia for manual verification",
        "target_type": "media",
        "automation_level": "manual",
        "requires_approval": False,
        "description": "Mark the media item for human review by an analyst.",
    },
    {
        "action": "Report impersonation",
        "target_type": "external",
        "automation_level": "manual",
        "requires_approval": False,
        "description": "Report the impersonation attempt to the affected brand or platform.",
    },
    {
        "action": "Notify administrator/SOC",
        "target_type": "notification",
        "automation_level": "automatic",
        "requires_approval": False,
        "description": "Send an alert to the administrator or SOC channel for triage.",
    },
    {
        "action": "Escalate the incident for investigation",
        "target_type": "incident",
        "automation_level": "semi-automatic",
        "requires_approval": True,
        "description": "Escalate the incident to senior analysts for deeper investigation.",
    },
]


async def _seed_default_policies() -> None:
    """Create one default "Balanced" enforcement policy per organization if none exists.

    Runs through the service role (admin session maker): startup seeding is a
    system task with no user identity, so owner-scoped RLS on
    enforcement_policies would reject the insert from the app role.
    """
    from app.db.admin import _get_admin_session_maker
    from app.db.models import EnforcementPolicy, Organization

    async with _get_admin_session_maker()() as session:
        result = await session.execute(select(Organization))
        orgs = result.scalars().all()

        seeded = 0
        for org in orgs:
            existing = await session.execute(
                select(EnforcementPolicy).where(
                    EnforcementPolicy.organization_id == org.id,
                    EnforcementPolicy.is_active == True,  # noqa: E712 - SQLAlchemy comparison
                )
            )
            if existing.scalars().first() is not None:
                continue

            session.add(EnforcementPolicy(
                organization_id=org.id,
                name="Balanced (default)",
                description="Auto-block critical/high, require approval for medium.",
                is_active=True,
            ))
            seeded += 1

        if seeded:
            logger.info("Seeded default enforcement policies for %d organization(s)...", seeded)
            await session.commit()


async def _ensure_schema_if_privileged(schema: str) -> None:
    """Best-effort CREATE SCHEMA IF NOT EXISTS on an isolated connection.

    Skipped silently when the connecting role lacks CREATE privilege on the
    database (e.g. the cyberguard_api app role — alembic owns schema creation
    there). Any other failure is logged without breaking startup.
    """
    admin_url = settings.MIGRATION_DATABASE_URL or settings.DATABASE_URL
    if not admin_url or "postgresql" not in admin_url:
        return
    admin_engine = create_async_engine(admin_url)
    try:
        async with admin_engine.connect() as conn:
            has_create = (
                await conn.execute(
                    text("select has_database_privilege(current_user, current_database(), 'CREATE')")
                )
            ).scalar()
            if not has_create:
                logger.info(
                    "role '%s' lacks CREATE privilege — skipping schema bootstrap "
                    "(run 'uv run alembic upgrade head' to (re)create schema + RLS)",
                    (await conn.execute(text("select current_user"))).scalar(),
                )
                return
            await conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
            # Emulate Supabase auth schema and auth.uid() on local/vanilla Postgres for 100% parity
            await conn.execute(text('CREATE SCHEMA IF NOT EXISTS "auth"'))
            await conn.execute(text("""
                CREATE OR REPLACE FUNCTION auth.uid() RETURNS text AS $$
                    SELECT coalesce(
                        nullif(current_setting('request.jwt.claim.sub', true), ''),
                        nullif(current_setting('app.user_id', true), '')
                    );
                $$ LANGUAGE sql STABLE;
            """))
            # Ensure cyberguard_api role exists with NOBYPASSRLS for local PostgreSQL.
            # The password is force-synced right after (bind parameters cannot
            # live inside a DO block) from settings.APP_ROLE_PASSWORD — one
            # source of truth shared with the RLS verification harness.
            await conn.execute(text("""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cyberguard_api') THEN
                        CREATE ROLE cyberguard_api WITH LOGIN NOBYPASSRLS PASSWORD 'cyberguard_api';
                    END IF;
                END $$;
            """))
            # Force-sync the password so an existing role can never drift from
            # config. Utility statements take no bind parameters and a failure
            # must not abort the surrounding bootstrap transaction, hence the
            # inline (quote-escaped) literal inside a savepoint.
            try:
                async with conn.begin_nested():
                    escaped = settings.APP_ROLE_PASSWORD.replace("'", "''")
                    await conn.execute(text(
                        "ALTER ROLE cyberguard_api WITH LOGIN NOBYPASSRLS "
                        f"PASSWORD '{escaped}'"
                    ))
            except Exception as exc:  # noqa: BLE001 - managed roles may forbid ALTER
                logger.info("could not sync cyberguard_api password (managed role?): %s", exc)
            # Grant privileges to cyberguard_api
            await conn.execute(text(f'GRANT USAGE, CREATE ON SCHEMA "{schema}" TO cyberguard_api;'))
            await conn.execute(text(f'GRANT ALL ON ALL TABLES IN SCHEMA "{schema}" TO cyberguard_api;'))
            await conn.execute(text(f'GRANT ALL ON ALL SEQUENCES IN SCHEMA "{schema}" TO cyberguard_api;'))
            await conn.execute(text(f'GRANT ALL ON ALL FUNCTIONS IN SCHEMA "{schema}" TO cyberguard_api;'))
            await conn.execute(text(f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{schema}" GRANT ALL ON TABLES TO cyberguard_api;'))
            await conn.execute(text(f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{schema}" GRANT ALL ON SEQUENCES TO cyberguard_api;'))
            await conn.execute(text(f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{schema}" GRANT ALL ON FUNCTIONS TO cyberguard_api;'))
            await conn.execute(text('GRANT USAGE ON SCHEMA auth TO cyberguard_api, public;'))
            await conn.execute(text('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA auth TO cyberguard_api, public;'))
            # Ensure realtime publication exists and contains org_log_events & alerts
            await conn.execute(text("""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
                        CREATE PUBLICATION supabase_realtime;
                    END IF;
                END $$;
            """))
            for tbl in ("org_log_events", "alerts"):
                await conn.execute(text(f"""
                    DO $$
                    BEGIN
                        ALTER PUBLICATION supabase_realtime ADD TABLE "{schema}".{tbl};
                    EXCEPTION WHEN duplicate_object THEN
                        NULL;
                    END $$;
                """))
            await conn.execute(text(f'ALTER TABLE IF EXISTS "{schema}".organizations ALTER COLUMN status SET DEFAULT \'active\''))
            await conn.commit()
        logger.info("ensured schema '%s' and auth compatibility exist", schema)
    except Exception as exc:  # noqa: BLE001 - never block startup on the bootstrap
        logger.warning("could not ensure schema '%s' (run alembic upgrade head): %s", schema, exc)
    finally:
        await admin_engine.dispose()


async def init_db() -> None:
    """Initialize database tables and seed default records if needed.

    Self-healing (runbook): on PostgreSQL the ``cyberguard`` schema is created
    on demand before create_all, so a wiped/missing schema no longer crashes
    startup — tables are rebuilt from the ORM metadata. The attempt runs on an
    ISOLATED connection and only when the role actually holds CREATE privilege
    (the app role normally does not — schema creation is the migration role's
    job via ``uv run alembic upgrade head``); a failure must never poison the
    main create_all transaction.
    """
    from app.db.models import ResponseCatalog

    logger.info("Initializing database schema on %s...", settings.async_database_url.split("@")[-1])
    if "postgresql" in str(engine.dialect.name):
        from app.db.base import SCHEMA

        await _ensure_schema_if_privileged(SCHEMA)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed response catalog
    async with async_session_maker() as session:
        result = await session.execute(select(ResponseCatalog).limit(1))
        if not result.scalars().first():
            logger.info("Seeding default response catalog actions...")
            for item in DEFAULT_RESPONSE_CATALOG:
                session.add(ResponseCatalog(**item))
            await session.commit()

    # Seed one default enforcement policy per organization (no-op when no orgs exist yet)
    await _seed_default_policies()
