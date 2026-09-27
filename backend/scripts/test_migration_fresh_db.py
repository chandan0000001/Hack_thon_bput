"""Suite 48 — Squashed Baseline Migration for Fresh Database Provisioning.

Verifies the 4 critical invariants of MIGRATION-FRESH-DB-FIX:
1. Pure static DDL integrity: 0102_squash_baseline.py contains zero ORM imports
   (no Base.metadata, no app.db.models, no app.db.base).
2. Fresh database provisioning: alembic upgrade head runs against an empty database,
   exits 0, and creates all 32 tables, 6 org_* tables, 0 legacy tables, functions,
   and enables RLS across all tables.
3. Migration idempotency: running alembic upgrade head a second time on an already-provisioned
   database succeeds with exit 0 as a clean no-op.
4. Clean downgrade: alembic downgrade base drops the cyberguard schema cleanly.
"""

import asyncio
import os
from pathlib import Path
import re
import sys
import uuid

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

# Ensure backend root is on sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.config import get_settings


async def run_migration_fresh_db_tests(runner: Any) -> None:
    print("\n--- Running Suite 48: Migration Fresh DB Provisioning ---")

    # -------------------------------------------------------------------------
    # Check 1: Pure Static DDL Integrity
    # -------------------------------------------------------------------------
    migration_file = ROOT / "alembic" / "versions" / "0102_squash_baseline.py"
    runner.assert_true(migration_file.exists(), "0102_squash_baseline.py exists on disk")

    file_content = migration_file.read_text(encoding="utf-8")
    has_base_metadata = "Base.metadata" in file_content
    has_db_models = "app.db.models" in file_content
    has_db_base = "from app.db.base" in file_content or "import app.db.base" in file_content

    runner.assert_true(
        not has_base_metadata and not has_db_models and not has_db_base,
        "Check 1: Pure static DDL integrity (0102 contains no Base.metadata, no app.db.models, no app.db.base)",
        details=f"Base.metadata={has_base_metadata}, models={has_db_models}, base={has_db_base}",
    )

    # -------------------------------------------------------------------------
    # Setup Temporary Database
    # -------------------------------------------------------------------------
    settings = get_settings()
    base_url = (settings.MIGRATION_DATABASE_URL or settings.DATABASE_URL).strip()
    if base_url.startswith("postgres://"):
        base_url = base_url.replace("postgres://", "postgresql+asyncpg://", 1)
    elif base_url.startswith("postgresql://") and not base_url.startswith("postgresql+asyncpg://"):
        base_url = base_url.replace("postgresql://", "postgresql+asyncpg://", 1)

    # Extract maintenance connection URL (connecting to 'postgres' database)
    parsed_base = base_url.rsplit("/", 1)[0]
    maintenance_url = f"{parsed_base}/postgres"

    temp_db_name = f"cg_test_fresh_{uuid.uuid4().hex[:8]}"
    temp_db_url = f"{parsed_base}/{temp_db_name}"

    maint_engine = create_async_engine(maintenance_url, isolation_level="AUTOCOMMIT")

    try:
        async with maint_engine.connect() as conn:
            await conn.execute(text(f'CREATE DATABASE "{temp_db_name}"'))

        # Prepare subprocess environment
        sub_env = os.environ.copy()
        sub_env["MIGRATION_DATABASE_URL"] = temp_db_url
        sub_env["DATABASE_URL"] = temp_db_url
        sub_env["TEST_MIGRATION_DATABASE_URL"] = temp_db_url
        sub_env["TEST_DATABASE_URL"] = temp_db_url

        # ---------------------------------------------------------------------
        # Check 2: Fresh Database Provisioning
        # ---------------------------------------------------------------------
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "alembic", "upgrade", "head",
            cwd=str(ROOT),
            env=sub_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        out_text = (stdout + stderr).decode("utf-8", errors="replace")

        temp_engine = create_async_engine(temp_db_url, isolation_level="AUTOCOMMIT")
        try:
            async with temp_engine.connect() as conn:
                # 1. Total table count in cyberguard schema
                table_count = (await conn.execute(
                    text("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'cyberguard'")
                )).scalar() or 0

                # 2. Rebuilt org_* tables count
                org_tables = (await conn.execute(
                    text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'cyberguard' AND table_name LIKE 'org_%' ORDER BY 1")
                )).scalars().all()

                # 3. Legacy tables count
                legacy_tables = (await conn.execute(
                    text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'cyberguard' AND table_name IN ('organizations', 'organization_members', 'organization_api_keys', 'organization_invites', 'org_invites', 'org_domains', 'org_scans', 'org_policies', 'org_threat_intel', 'org_audit_logs', 'org_log_events', 'org_compliance_reports')")
                )).scalars().all()

                # 4. Functions exist
                functions = (await conn.execute(
                    text("SELECT routine_name FROM information_schema.routines WHERE routine_schema = 'cyberguard' AND routine_name IN ('org_member_role', 'validate_org_api_key')")
                )).scalars().all()

                # 5. RLS enabled on all tables
                disabled_rls = (await conn.execute(
                    text("SELECT tablename FROM pg_tables WHERE schemaname = 'cyberguard' AND rowsecurity = false")
                )).scalars().all()

                # 6. Current alembic version
                version_num = (await conn.execute(
                    text("SELECT version_num FROM alembic_version")
                )).scalar() or ""

            expected_org = [
                "org_api_keys", "org_blocked_indicators", "org_events",
                "org_members", "org_organizations", "org_projects"
            ]

            success_c2 = (
                proc.returncode == 0
                and table_count == 32
                and sorted(org_tables) == expected_org
                and len(legacy_tables) == 0
                and len(functions) == 2
                and len(disabled_rls) == 0
                and "0102_squash_baseline" in version_num
            )

            runner.assert_true(
                success_c2,
                "Check 2: Fresh database provisioning (alembic upgrade head exits 0, 32 tables, 6 org_*, 0 legacy, RLS enabled)",
                details=f"rc={proc.returncode}, tables={table_count}, org={len(org_tables)}, legacy={len(legacy_tables)}, rls_disabled={len(disabled_rls)}, out={out_text[-200:]}",
            )

            # -----------------------------------------------------------------
            # Check 3: Migration Idempotency
            # -----------------------------------------------------------------
            proc_idemp = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "alembic", "upgrade", "head",
                cwd=str(ROOT),
                env=sub_env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_idemp, stderr_idemp = await proc_idemp.communicate()

            async with temp_engine.connect() as conn:
                table_count_idemp = (await conn.execute(
                    text("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'cyberguard'")
                )).scalar() or 0

            runner.assert_true(
                proc_idemp.returncode == 0 and table_count_idemp == 32,
                "Check 3: Migration idempotency (second alembic upgrade head exits 0 as no-op, table count unchanged)",
                details=f"rc={proc_idemp.returncode}, tables={table_count_idemp}",
            )

            # -----------------------------------------------------------------
            # Check 4: Clean Cascade Downgrade
            # -----------------------------------------------------------------
            proc_down = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "alembic", "downgrade", "base",
                cwd=str(ROOT),
                env=sub_env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_down, stderr_down = await proc_down.communicate()

            async with temp_engine.connect() as conn:
                schema_exists = (await conn.execute(
                    text("SELECT count(*) FROM information_schema.schemata WHERE schema_name = 'cyberguard'")
                )).scalar() or 0

            runner.assert_true(
                proc_down.returncode == 0 and schema_exists == 0,
                "Check 4: Clean cascade downgrade (alembic downgrade base exits 0, cyberguard schema cleanly dropped)",
                details=f"rc={proc_down.returncode}, schema_count={schema_exists}",
            )

        finally:
            await temp_engine.dispose()

    finally:
        # Drop temporary database cleanly
        try:
            async with maint_engine.connect() as conn:
                # Terminate any lingering connections to temp_db_name
                await conn.execute(text(f"""
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE datname = '{temp_db_name}' AND pid <> pg_backend_pid()
                """))
                await conn.execute(text(f'DROP DATABASE IF EXISTS "{temp_db_name}"'))
        except Exception as exc:
            print(f"Warning: could not drop temp db {temp_db_name}: {exc}")
        finally:
            await maint_engine.dispose()


if __name__ == "__main__":
    class StandaloneRunner:
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

        def report(self):
            total = self.passed + self.failed
            print("\n" + "=" * 60)
            print(f"TEST RESULTS: {self.passed}/{total} passed")
            return 0 if self.failed == 0 else 1

    r = StandaloneRunner()
    asyncio.run(run_migration_fresh_db_tests(r))
    sys.exit(r.report())
