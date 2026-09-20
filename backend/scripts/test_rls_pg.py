"""Row-Level Security verification against a real PostgreSQL database.

Runs everywhere via ``run_rls_tests(runner)`` (wired as Suite 10 in
run_all_tests.py); on SQLite / without PostgreSQL it reports a clean skip.

Standalone usage (exits non-zero on failure):

    MIGRATION_DATABASE_URL=postgresql+asyncpg://postgres:...@host/db \
    APP_DATABASE_URL=postgresql+asyncpg://cyberguard_api:...@host/db \
        uv run python scripts/test_rls_pg.py

Environment:
- MIGRATION_DATABASE_URL: service/postgres role (migrations + bypass checks)
- APP_DATABASE_URL (or DATABASE_URL): the cyberguard_api app role, NOBYPASSRLS
  (its password comes from settings.APP_ROLE_PASSWORD — the same source the
  startup bootstrap syncs the role to; no secrets live in this file)

Checks, per the Phase -1 spec:
  1. user A inserts a row -> A selects it: exactly 1 row
  2. user B selects: 0 rows (cross-user isolation)
  3. unauthenticated session (empty app.user_id GUC) sees 0 rows
  4. service role (bypasses RLS) sees the row
"""

import asyncio
import os
import sys
import uuid

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

SKIP_REASON = (
    "Skipped: no PostgreSQL configured "
    "(set MIGRATION_DATABASE_URL; optionally APP_DATABASE_URL for the app role)"
)


def _to_async(url: str) -> str:
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    if url.startswith("postgresql://") and not url.startswith("postgresql+asyncpg://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return url


def _resolve_urls():
    """Return (service_url, app_url) or (None, None) when not PG-configured."""
    from app.core.config import get_settings

    settings = get_settings()
    service_url = _to_async(settings.MIGRATION_DATABASE_URL or "")
    app_url = _to_async(os.environ.get("APP_DATABASE_URL") or settings.DATABASE_URL)
    if not service_url or "postgresql+asyncpg" not in service_url:
        return None, None
    if "postgresql+asyncpg" not in app_url:
        return None, None
    if "postgres:postgres@" in app_url:
        # Swap the superuser DSN for the NOBYPASSRLS app role. The password is
        # the configured one (settings.APP_ROLE_PASSWORD) — identical to what
        # the startup bootstrap creates/syncs the role with.
        app_url = app_url.replace(
            "postgres:postgres@",
            f"cyberguard_api:{settings.APP_ROLE_PASSWORD}@",
        )
    return service_url, app_url


async def _as_user(app_url: str, user_id: str):
    """Open an app-role connection scoped to one user via the app.user_id GUC."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(app_url)
    conn = await engine.connect()
    # Session-scoped GUC: survives commits inside the connection.
    await conn.execute(
        text(
            "select set_config('app.user_id', :uid, false), "
            "set_config('request.role', 'authenticated', false)"
        ),
        {"uid": user_id},
    )
    return engine, conn


async def _owner_isolation(service_url: str, app_url: str) -> None:
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    from app.db.base import SCHEMA

    user_a = f"rls-user-a-{uuid.uuid4().hex[:8]}"
    user_b = f"rls-user-b-{uuid.uuid4().hex[:8]}"

    # Ensure both accounts exist so the users-table policies don't interfere.
    service_engine = create_async_engine(service_url)
    async with service_engine.begin() as conn:
        for uid in (user_a, user_b):
            await conn.execute(
                text(
                    f"INSERT INTO {SCHEMA}.users (id, account_type, is_single_user, created_at) "
                    f"VALUES (:id, 'user', true, now()) ON CONFLICT (id) DO NOTHING"
                ),
                {"id": uid},
            )
    await service_engine.dispose()

    # User A inserts an event through the app role (RLS enforced).
    engine_a = create_async_engine(app_url)
    async with engine_a.begin() as conn_a:
        await conn_a.execute(
            text("select set_config('app.user_id', :uid, false)"),
            {"uid": user_a},
        )
        await conn_a.execute(
            text(
                f"INSERT INTO {SCHEMA}.events (id, event_type, source, raw_data, owner_user_id, status, created_at) "
                f"VALUES (:id, 'rls_test', 'test', '{{}}'::jsonb, :uid, 'received', now())"
            ),
            {"id": str(uuid.uuid4()), "uid": user_a},
        )
    await engine_a.dispose()

    # User A selects: exactly their 1 row.
    _, conn_a = await _as_user(app_url, user_a)
    count_a = (
        await conn_a.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.events WHERE owner_user_id = :uid"), {"uid": user_a}
        )
    ).scalar()
    total_a = (await conn_a.execute(text(f"SELECT count(*) FROM {SCHEMA}.events"))).scalar()
    await conn_a.close()
    assert count_a == 1 and total_a == 1, f"user A expected exactly 1 own row, saw total={total_a} own={count_a}"

    # User B selects: 0 rows.
    _, conn_b = await _as_user(app_url, user_b)
    total_b = (await conn_b.execute(text(f"SELECT count(*) FROM {SCHEMA}.events"))).scalar()
    await conn_b.close()
    assert total_b == 0, f"user B must see 0 rows, saw {total_b}"

    # Connector isolation (Phase 1-2): user A inserts a connector account via
    # the app role; user B must see none of them.
    engine_a2 = create_async_engine(app_url)
    async with engine_a2.begin() as conn_a2:
        await conn_a2.execute(
            text("select set_config('app.user_id', :uid, false)"),
            {"uid": user_a},
        )
        await conn_a2.execute(
            text(
                f"INSERT INTO {SCHEMA}.email_connector_accounts "
                f"(id, owner_user_id, provider, provider_email, status, scopes, capabilities, created_at, updated_at) "
                f"VALUES (:id, :uid, 'gmail', :email, 'connected', '{{}}'::jsonb, '{{}}'::jsonb, now(), now())"
            ),
            {"id": str(uuid.uuid4()), "uid": user_a, "email": f"{user_a}@gmail.test"},
        )
    await engine_a2.dispose()

    _, conn_a = await _as_user(app_url, user_a)
    count_a_conn = (
        await conn_a.execute(
            text(f"SELECT count(*) FROM {SCHEMA}.email_connector_accounts WHERE owner_user_id = :uid"),
            {"uid": user_a},
        )
    ).scalar()
    await conn_a.close()
    assert count_a_conn == 1, f"user A expected exactly 1 own connector row, saw {count_a_conn}"

    _, conn_b = await _as_user(app_url, user_b)
    count_b_conn = (
        await conn_b.execute(text(f"SELECT count(*) FROM {SCHEMA}.email_connector_accounts"))
    ).scalar()
    await conn_b.close()
    assert count_b_conn == 0, f"user B must see 0 connector rows, saw {count_b_conn}"

    # Unauthenticated (empty GUC): 0 rows.
    engine = create_async_engine(app_url)
    async with engine.connect() as conn_anon:
        rows_anon = (await conn_anon.execute(text(f"SELECT count(*) FROM {SCHEMA}.events"))).scalar()
        assert rows_anon == 0, f"unauthenticated must see 0 rows, saw {rows_anon}"
    await engine.dispose()

    # Service role sees the row.
    engine = create_async_engine(service_url)
    async with engine.connect() as conn_svc:
        total = (
            await conn_svc.execute(
                text(f"SELECT count(*) FROM {SCHEMA}.events WHERE owner_user_id = :uid"),
                {"uid": user_a},
            )
        ).scalar()
        assert total == 1, f"service role expected 1 row, saw {total}"
    await engine.dispose()


async def run_rls_tests(runner) -> None:
    """Suite entry point: self-skips cleanly without PostgreSQL."""
    service_url, app_url = _resolve_urls()
    if service_url is None:
        runner.assert_true(True, "RLS-PG suite skipped without PG", SKIP_REASON)
        print("         " + SKIP_REASON)
        return
    try:
        await _owner_isolation(service_url, app_url)
        runner.assert_true(True, "RLS: events + connectors — A sees own rows, B sees none, anon denied, service role bypasses")
    except AssertionError as exc:
        runner.assert_true(False, "RLS: events + connectors — A sees own rows, B sees none, anon denied, service role bypasses", str(exc))
    except Exception as exc:  # noqa: BLE001
        runner.assert_true(False, "RLS: events + connectors — A sees own rows, B sees none, anon denied, service role bypasses", f"{type(exc).__name__}: {exc}")


async def _standalone() -> int:
    class _Runner:
        def __init__(self):
            self.passed = 0
            self.failed = 0

        def assert_true(self, condition: bool, name: str, details: str = ""):
            if condition:
                self.passed += 1
                print(f"  \033[32m✔ PASS\033[0m: {name}")
            else:
                self.failed += 1
                print(f"  \033[31m✖ FAIL\033[0m: {name} - {details}")

    runner = _Runner()
    print("\n🔒 CYBERGUARD RLS-PG VERIFICATION\n" + "=" * 60)
    await run_rls_tests(runner)
    print("=" * 60)
    print(f"RLS-PG: {runner.passed} passed, {runner.failed} failed")
    return 1 if runner.failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
