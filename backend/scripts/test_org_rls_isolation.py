"""ORG-FIX-1 — DB-level RLS tenant isolation test suite (Suite 38).

Proves the permissive ``*_app_all TO cyberguard_api USING (true)`` bypass is
gone (migration 0016) and that the narrow SECURITY DEFINER key-validation
escape keeps the gateway working:

 1. Outsider loop: app role + outsider app.user_id GUC -> 0 rows on ALL 11
    org tables.
 2. Member GUC -> sees own-org rows on all 11.
 3. Gateway e2e with a valid key POST-REVOKE-setup -> 200 (definer-fn path).
 4. Invalid key -> 401 (unchanged).
 5. Admin lists API keys (gated admin SELECT) -> 200 with rows.
 6. Non-admin member lists API keys -> per existing semantics (403 or
    empty), unchanged.
 7. Member INSERT org_log_events own org OK; outsider INSERT rejected
    (WITH CHECK).
 8. organizations: member sees own orgs only; create stamps owner_id from
    the GUC.
 9. Owner-scoped + DLQ suites unaffected (spot-run Suites 11, 23, 30).
10. Migration 0016 contains ZERO auth-schema references; 0017 references
    the auth schema ONLY via the shared 0012 probe expression.

Run via run_all_tests.py (Suite 38) or standalone:
    uv run python scripts/test_org_rls_isolation.py
"""

import asyncio
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.core.security import CurrentUser, get_current_user
from app.db.session import async_session_maker, current_user_id, engine
from app.main import app
from app.services.api_key_service import hash_api_key

MIGRATIONS_DIR = ROOT / "alembic" / "versions"

# The 11 org tables (audit A2.2). Tables keyed by mail_server_id are counted
# through their org_mail_servers parent, exactly like their RLS policies.
ORG_TABLES = (
    "organizations",
    "organization_members",
    "organization_api_keys",
    "organization_settings",
    "org_log_events",
    "org_mail_servers",
    "org_mail_server_settings",
    "org_mail_server_logs",
    "org_notification_emails",
    "org_notification_settings",
    "org_notification_logs",
)

_COUNT_SQL = {
    "organizations": (
        "select count(*) from cyberguard.organizations where id = :org"
    ),
    "org_mail_server_settings": (
        "select count(*) from cyberguard.org_mail_server_settings s "
        "where exists (select 1 from cyberguard.org_mail_servers m "
        "where m.id = s.mail_server_id and m.organization_id = :org)"
    ),
    "org_mail_server_logs": (
        "select count(*) from cyberguard.org_mail_server_logs l "
        "where exists (select 1 from cyberguard.org_mail_servers m "
        "where m.id = l.mail_server_id and m.organization_id = :org)"
    ),
}


class _Identity:
    """Mutable per-suite identity the get_current_user override returns."""

    user: CurrentUser | None = None


async def _mock_get_current_user() -> CurrentUser:
    if _Identity.user is None:
        raise RuntimeError("test identity not set")
    current_user_id.set(_Identity.user.id)  # RLS identity, as in production
    return _Identity.user


async def _count_as(guc_user: str, table: str, org_id: str) -> int:
    """Count an org's rows through the app role (cyberguard_api, NOBYPASSRLS)
    with the given app.user_id GUC — the exact attack surface 0016 closes."""
    sql = _COUNT_SQL.get(
        table,
        f"select count(*) from cyberguard.{table} where organization_id = :org",
    )
    async with engine.connect() as conn:
        await conn.execute(text("select set_config('app.user_id', :uid, false)"), {"uid": guc_user})
        return (await conn.execute(text(sql), {"org": org_id})).scalar()


async def _ensure_user(db, user_id: str, email: str) -> None:
    """Insert a user row under its own RLS identity (owner policy)."""
    from sqlalchemy import select
    from app.db.models import User

    existing = await db.execute(select(User).where(User.id == user_id))
    if existing.scalar_one_or_none() is not None:
        return
    await db.commit()  # close the read transaction (empty GUC)
    current_user_id.set(user_id)
    db.add(User(id=user_id, email=email, full_name=user_id, is_single_user=True))
    await db.commit()
    current_user_id.set(None)


async def _provision_org_rows(admin_db, org_id: str, admin_id: str) -> None:
    """Insert one row in each of the 11 org tables via the service role
    (postgres bypasses RLS — provisioning only, as in the other suites)."""
    from datetime import datetime, timezone

    from app.services.api_key_service import generate_api_key

    now = datetime.now(timezone.utc)
    u = uuid.uuid4().hex
    raw_key = generate_api_key()
    stmts = [
        (
            "insert into cyberguard.organization_api_keys (id, organization_id, name, key_hash, key_prefix, status, created_by, created_at) "
            "values (:id, :org, 'Suite38 Key', :hash, :prefix, 'active', :admin, now())",
            {"hash": hash_api_key(raw_key), "prefix": raw_key[:16]},
        ),
        (
            "insert into cyberguard.organization_settings (id, organization_id, key, value, updated_by, updated_at) "
            "values (:id, :org, 'suite38', '{}'::jsonb, :admin, now())",
            {},
        ),
        (
            "insert into cyberguard.org_log_events (id, organization_id, log_type, raw_data, analysis_result, severity, created_by, created_at) "
            "values (:id, :org, 'app', '{}'::jsonb, '{}'::jsonb, 'safe', :admin, now())",
            {},
        ),
        (
            "insert into cyberguard.org_mail_servers (id, organization_id, name, provider_type, status, created_by, created_at, updated_at) "
            "values (:id, :org, 'Suite38 Server', 'imap_smtp', 'disconnected', :admin, now(), now())",
            {},
        ),
        (
            "insert into cyberguard.org_notification_emails (id, organization_id, email, role, is_enabled, created_by, created_at) "
            "values (:id, :org, 'suite38@example.test', 'analyst', true, :admin, now())",
            {},
        ),
        (
            "insert into cyberguard.org_notification_settings (id, organization_id, event_type, min_role, is_enabled, updated_by, updated_at) "
            "values (:id, :org, 'critical_log', 'analyst', true, :admin, now())",
            {},
        ),
        (
            "insert into cyberguard.org_notification_logs (id, organization_id, event_type, recipients, subject, status, created_at) "
            "values (:id, :org, 'critical_log', '[]'::jsonb, 'Suite38 probe', 'sent', now())",
            {},
        ),
    ]
    for sql, extra in stmts:
        params = {"id": str(uuid.uuid4()), "org": org_id, "admin": admin_id, **extra}
        await admin_db.execute(text(sql), params)
    # Child rows of the mail server (need its id).
    server_id = (
        await admin_db.execute(
            text("select id from cyberguard.org_mail_servers where organization_id = :org limit 1"),
            {"org": org_id},
        )
    ).scalar()
    await admin_db.execute(
        text("insert into cyberguard.org_mail_server_settings (id, mail_server_id, key, value, updated_by, updated_at) "
             "values (:id, :sid, 'scan_interval_seconds', '300'::jsonb, :admin, now())"),
        {"id": str(uuid.uuid4()), "sid": server_id, "admin": admin_id},
    )
    await admin_db.execute(
        text("insert into cyberguard.org_mail_server_logs (id, mail_server_id, log_type, message, created_at) "
             "values (:id, :sid, 'connection', 'Suite38 probe', now())"),
        {"id": str(uuid.uuid4()), "sid": server_id},
    )
    await admin_db.commit()


def _m17_auth_free_lines(source: str) -> list[str]:
    """Lines of migration 0017 that reference the auth schema WITHOUT being
    (a) the shared probe expression, (b) the probe-gated policy bodies
    (``auth.uid()::text`` inside the policy SQL), or (c) documentation
    (module docstring / comments). A non-empty result means executable code
    touches the auth schema outside the two allowed contexts."""
    import ast as _ast

    tree = _ast.parse(source)
    lines = source.splitlines()
    doc_end = (tree.body[0].end_lineno or 0) if _ast.get_docstring(tree) else 0
    offenders = []
    for i, line in enumerate(lines, start=1):
        if "auth." not in line:
            continue
        stripped = line.strip()
        is_doc = i <= doc_end or stripped.startswith("#")
        is_probe = "to_regprocedure('auth.uid()')" in line
        is_policy_body = "auth.uid()::text" in line
        if not (is_doc or is_probe or is_policy_body):
            offenders.append(f"L{i}: {stripped}")
    return offenders


async def run_org_rls_isolation_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("ORG-FIX-1 RLS isolation: no permissive bypass on org tables")
    print("-" * 60)

    if "postgresql" not in str(engine.dialect.name):
        check(True, "ORG-FIX-1 RLS isolation suite skipped without PostgreSQL")
        print("         Skipped: no PostgreSQL configured")
        return

    stamp = uuid.uuid4().hex[:8]
    admin = CurrentUser(id=f"s38-admin-{stamp}", email=f"s38-admin-{stamp}@cyberguard.test", full_name="S38 Admin")
    analyst = CurrentUser(id=f"s38-analyst-{stamp}", email=f"s38-analyst-{stamp}@cyberguard.test", full_name="S38 Analyst")
    outsider = CurrentUser(id=f"s38-outsider-{stamp}", email=f"s38-outsider-{stamp}@cyberguard.test", full_name="S38 Outsider")
    newcomer = CurrentUser(id=f"s38-newcomer-{stamp}", email=f"s38-newcomer-{stamp}@cyberguard.test", full_name="S38 Newcomer")

    async with async_session_maker() as db:
        for u in (admin, analyst, outsider, newcomer):
            await _ensure_user(db, u.id, u.email or "")

    app.dependency_overrides[get_current_user] = _mock_get_current_user
    transport = ASGITransport(app=app)
    org_id = ""
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Provision Org A via the API (owner_id stamped from the GUC).
            _Identity.user = admin
            res = await client.post("/api/v1/orgs", json={"name": f"RLS Iso Org {stamp}"})
            org_id = res.json()["id"]
            res = await client.post(
                f"/api/v1/orgs/{org_id}/members", json={"email": analyst.email, "role": "analyst"}
            )

            # Provision one row per org table via the service role.
            from app.db.admin import _get_admin_session_maker

            async with _get_admin_session_maker()() as admin_db:
                await _provision_org_rows(admin_db, org_id, admin.id)

            # ----------------------------------------------------------
            # 1 + 2. Outsider/member row-visibility loop on all 11 tables.
            # ----------------------------------------------------------
            outsider_seen = {t: await _count_as(outsider.id, t, org_id) for t in ORG_TABLES}
            check(
                all(v == 0 for v in outsider_seen.values()),
                "Outsider GUC sees 0 rows on ALL 11 org tables (no permissive bypass)",
                str(outsider_seen),
            )
            member_seen = {t: await _count_as(admin.id, t, org_id) for t in ORG_TABLES}
            check(
                all(v >= 1 for v in member_seen.values()),
                "Member GUC sees own-org rows on ALL 11 org tables",
                str(member_seen),
            )

            # ----------------------------------------------------------
            # 3 + 4. Gateway e2e: definer-fn validation path.
            # ----------------------------------------------------------
            raw_key = uuid.uuid4().hex
            key_hash = hash_api_key(f"cg_live_{raw_key}")
            async with _get_admin_session_maker()() as admin_db:
                await admin_db.execute(
                    text("insert into cyberguard.organization_api_keys "
                         "(id, organization_id, name, key_hash, key_prefix, status, created_by, created_at) "
                         "values (:id, :org, 'Gateway probe', :hash, :prefix, 'active', :admin, now())"),
                    {"id": str(uuid.uuid4()), "org": org_id, "hash": key_hash,
                     "prefix": f"cg_live_{raw_key[:8]}", "admin": admin.id},
                )
                await admin_db.commit()

            # No user identity on gateway calls — validation must go through
            # cyberguard.validate_org_api_key and writes satisfy gated RLS.
            _Identity.user = None
            res_gw = await client.post(
                f"/api/v1/org/{org_id}/gateway",
                headers={"org_authorization": f"cg_live_{raw_key}"},
                json={"action": "ingest_log", "data": {"message": "suite38 probe"}},
            )
            check(res_gw.status_code == 200, "Gateway e2e with valid key -> 200 (definer-fn path)", res_gw.text[:200])
            res_bad = await client.post(
                f"/api/v1/org/{org_id}/gateway",
                headers={"org_authorization": "cg_live_invalid"},
                json={"action": "ingest_log", "data": {"message": "x"}},
            )
            check(res_bad.status_code == 401, "Gateway with invalid key -> 401 (unchanged)")

            # ----------------------------------------------------------
            # 5 + 6. API-key listing under the gated admin SELECT policy.
            # ----------------------------------------------------------
            _Identity.user = admin
            res_admin_list = await client.get(f"/api/v1/orgs/{org_id}/api-keys")
            rows = res_admin_list.json() if res_admin_list.status_code == 200 else []
            check(
                res_admin_list.status_code == 200 and len(rows) >= 2,
                "Admin lists API keys -> 200 with rows (gated admin SELECT)",
                f"status={res_admin_list.status_code} rows={len(rows)}",
            )
            _Identity.user = analyst
            res_analyst_list = await client.get(f"/api/v1/orgs/{org_id}/api-keys")
            ok_non_admin = res_analyst_list.status_code == 403 or (
                res_analyst_list.status_code == 200 and res_analyst_list.json() == []
            )
            check(ok_non_admin, "Non-admin member lists API keys -> existing semantics (403 or empty), unchanged",
                  f"status={res_analyst_list.status_code}")

            # ----------------------------------------------------------
            # 7. Direct INSERT into org_log_events: member OK, outsider
            #    rejected by the WITH CHECK gate.
            # ----------------------------------------------------------
            from sqlalchemy.exc import DBAPIError

            async with engine.connect() as conn:
                await conn.execute(text("select set_config('app.user_id', :uid, false)"), {"uid": admin.id})
                await conn.execute(text(
                    "insert into cyberguard.org_log_events (id, organization_id, log_type, raw_data, analysis_result, severity, created_by, created_at) "
                    "values (:id, :org, 'app', '{}'::jsonb, '{}'::jsonb, 'safe', :uid, now())"
                ), {"id": str(uuid.uuid4()), "org": org_id, "uid": admin.id})
                member_inserted = True
            async with engine.connect() as conn:
                await conn.execute(text("select set_config('app.user_id', :uid, false)"), {"uid": outsider.id})
                try:
                    await conn.execute(text(
                        "insert into cyberguard.org_log_events (id, organization_id, log_type, raw_data, analysis_result, severity, created_by, created_at) "
                        "values (:id, :org, 'app', '{}'::jsonb, '{}'::jsonb, 'safe', :uid, now())"
                    ), {"id": str(uuid.uuid4()), "org": org_id, "uid": outsider.id})
                    outsider_rejected = False
                except DBAPIError:
                    outsider_rejected = True
                    await conn.rollback()
            check(
                member_inserted and outsider_rejected,
                "org_log_events INSERT: member's own org OK; outsider rejected (WITH CHECK)",
                f"member_inserted={member_inserted} outsider_rejected={outsider_rejected}",
            )

            # ----------------------------------------------------------
            # 8. organizations: member sees own orgs only; owner_id from GUC.
            # ----------------------------------------------------------
            async with engine.connect() as conn:
                await conn.execute(text("select set_config('app.user_id', :uid, false)"), {"uid": admin.id})
                own_orgs = (await conn.execute(
                    text("select count(*) from cyberguard.organizations where id = :org"), {"org": org_id}
                )).scalar()
            async with engine.connect() as conn:
                await conn.execute(text("select set_config('app.user_id', :uid, false)"), {"uid": outsider.id})
                outsider_orgs = (await conn.execute(
                    text("select count(*) from cyberguard.organizations where id = :org"), {"org": org_id}
                )).scalar()
            _Identity.user = newcomer
            res_new = await client.post("/api/v1/orgs", json={"name": f"RLS Iso New {stamp}"})
            new_org = res_new.json() if res_new.status_code == 201 else {}
            from app.db.models import Organization
            from sqlalchemy import select as _select

            async with async_session_maker() as db:
                owner_id = (
                    await db.execute(_select(Organization.owner_id).where(Organization.id == new_org.get("id", "")))
                ).scalar()
            check(
                own_orgs == 1
                and outsider_orgs == 0
                and res_new.status_code == 201
                and owner_id == newcomer.id,
                "organizations: member sees own org only; INSERT stamps owner_id from the GUC",
                f"own={own_orgs} outsider={outsider_orgs} status={res_new.status_code} owner_id={owner_id} expected={newcomer.id}",
            )
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        current_user_id.set(None)

    # --------------------------------------------------------------
    # 9. Spot-run owner-scoped + DLQ suites (no regression).
    # --------------------------------------------------------------
    class _Shim:
        def __init__(self):
            self.passed = 0
            self.failed = 0

        def assert_true(self, condition, name, details=""):
            if condition:
                self.passed += 1
            else:
                self.failed += 1

    from test_dlq_ops import run_dlq_ops_tests
    from test_rls_pg import run_rls_tests
    from test_rt_db_models import run_rt_db_models_tests

    shim = _Shim()
    await run_rls_tests(shim)
    await run_rt_db_models_tests(shim)
    await run_dlq_ops_tests(shim)
    check(
        shim.failed == 0,
        "Spot-run Suites 11 (RLS-PG), 23 (RT-2 models), 30 (DLQ) — all pass",
        f"passed={shim.passed} failed={shim.failed}",
    )

    # --------------------------------------------------------------
    # 10. Migration source audit: no auth-schema references outside the
    #     shared probe.
    # --------------------------------------------------------------
    m16 = (MIGRATIONS_DIR / "0016_drop_app_all_bypass.py").read_text()
    m17 = (MIGRATIONS_DIR / "0017_gated_realtime_reader.py").read_text()
    probe = "to_regprocedure('auth.uid()')"
    m17_without_probe = _m17_auth_free_lines(m17)
    check(
        "auth." not in m16 and not m17_without_probe,
        "Migrations 0016/0017: zero auth-schema references "
        "(0017 only via the shared 0012 probe + probe-gated policy bodies)",
        str(m17_without_probe[:3]),
    )

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

        def report(self):
            print(f"\nORG-FIX-1: {self.passed}/{self.passed + self.failed} passed")
            return 1 if self.failed else 0

    runner = _Runner()
    print("\n🔐 CYBERGUARD ORG-FIX-1 RLS ISOLATION TESTS\n" + "=" * 60)
    await run_org_rls_isolation_tests(runner)
    print("=" * 60)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
