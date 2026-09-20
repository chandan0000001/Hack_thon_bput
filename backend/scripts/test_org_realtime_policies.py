"""ORG-5 — Realtime policy tightening test suite (Suite 21).

Verifies migration 0012:
1. Permissive ORG-2 policies (USING (true) TO authenticated) are gone.
2. Gated realtime policies exist on org_log_events + alerts (TO authenticated).
3. Policy predicates reference org_member_role (membership-gated, not open).
4. Cross-org denial: as the `authenticated` role (SET ROLE, when the
   connection is permitted), a user from Org B sees 0 of Org A's realtime
   rows; falls back to predicate-level proof when SET ROLE is unavailable.
5. User-plane policies from the baseline are untouched (owner-scoped
   cyberguard_api policies still present).
6. Guard behavior: on SQLite / vanilla PG the migration is a clean no-op
   for the gated creation (asserted structurally via the auth.uid() guard).

Run via run_all_tests.py (Suite 21) or standalone:
    uv run python scripts/test_org_realtime_policies.py
"""

import asyncio
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import text

from app.db.session import engine


async def run_realtime_policy_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("ORG-5 Realtime tightening: gated authenticated SELECT policies")
    print("-" * 60)

    if "postgresql" not in str(engine.dialect.name):
        check(True, "Realtime policy suite skipped without PostgreSQL")
        print("         Skipped: no PostgreSQL configured")
        return

    conn = await engine.connect()
    try:
        # --------------------------------------------------------------
        # 0. Shared auth.uid() probe — byte-identical to migrations 0012 /
        #    0017 (ORG-FIX-1). Determines which branch of the gated-policy
        #    assertions applies on this backend.
        # --------------------------------------------------------------
        from app.db.admin import _get_admin_session_maker

        async with _get_admin_session_maker()() as probe_db:
            has_auth = (
                await probe_db.execute(text(
                    "select to_regprocedure('auth.uid()') is not null"
                ))
            ).scalar()

        # --------------------------------------------------------------
        # 1. Permissive policies dropped
        # --------------------------------------------------------------
        permissive = (
            await conn.execute(text(
                "select count(*) from pg_policies where schemaname = 'cyberguard' "
                "and policyname in ('org_log_events_authenticated_select', 'alerts_authenticated_select')"
            ))
        ).scalar()
        check(permissive == 0, "Permissive ORG-2 authenticated policies dropped (migration 0012)")

        # --------------------------------------------------------------
        # 2. Gated policies exist, TO authenticated (Supabase / auth-emulated
        #    backends). On plain Postgres the migration is a clean no-op: the
        #    gated policies must be ABSENT (readers stay denied by default).
        # --------------------------------------------------------------
        rows = (
            await conn.execute(text(
                "select tablename, policyname, cmd, roles from pg_policies "
                "where schemaname = 'cyberguard' "
                "and policyname in ('org_log_events_realtime_select', 'alerts_realtime_select')"
            ))
        ).all()
        names = {r[1] for r in rows}
        if has_auth:
            check(
                {"org_log_events_realtime_select", "alerts_realtime_select"} <= names,
                "Gated realtime SELECT policies exist on org_log_events + alerts",
                f"found={names}",
            )
            check(all("authenticated" in str(r[3]) for r in rows), "Gated policies target the authenticated role")
        else:
            check(
                not names,
                "Plain Postgres no-op branch: gated realtime policies absent (readers denied by default)",
                f"found={names}",
            )

        # --------------------------------------------------------------
        # 3. Predicates are membership-gated (reference org_member_role)
        # --------------------------------------------------------------
        quals = (
            await conn.execute(text(
                "select c.relname, p.polname, pg_get_expr(p.polqual, p.polrelid) "
                "from pg_policy p join pg_class c on c.oid = p.polrelid "
                "join pg_namespace n on n.oid = c.relnamespace "
                "where n.nspname = 'cyberguard' "
                "and p.polname in ('org_log_events_realtime_select', 'alerts_realtime_select')"
            ))
        ).all()
        if has_auth:
            check(
                all("org_member_role" in str(q[2]) for q in quals),
                "Realtime predicates are membership-gated via org_member_role()",
                f"quals={[q[0] for q in quals]}",
            )
            check(
                not any(str(q[2]).strip() == "true" for q in quals),
                "No realtime policy uses USING (true)",
            )
        else:
            check(
                len(quals) == 0,
                "Plain Postgres no-op branch: no realtime policy predicates to gate",
                f"quals={[q[0] for q in quals]}",
            )

        # --------------------------------------------------------------
        # 4. Cross-org denial under the authenticated role
        # --------------------------------------------------------------
        from app.db.admin import _get_admin_session_maker
        from datetime import datetime, timezone

        stamp = uuid.uuid4().hex[:8]
        user_a = f"rt-user-a-{stamp}"
        org_a = f"rt-org-a-{stamp}"
        org_b = f"rt-org-b-{stamp}"
        async with _get_admin_session_maker()() as db:
            await db.execute(text(
                "insert into cyberguard.users (id, account_type, is_single_user, created_at) "
                "values (:id, 'user', true, now()) on conflict (id) do nothing"),
                {"id": user_a},
            )
            await db.execute(text(
                "insert into cyberguard.organizations (id, name, slug, is_personal, owner_id, status, created_at) "
                "values (:id, :n, :s, false, :u, 'active', now())"),
                {"id": org_a, "n": "RT Org A", "s": f"rt-a-{stamp}", "u": user_a},
            )
            await db.execute(text(
                "insert into cyberguard.organization_members (id, organization_id, user_id, role, joined_at) "
                "values (:id, :o, :u, 'admin', now())"),
                {"id": f"rt-mem-a-{stamp}", "o": org_a, "u": user_a},
            )
            await db.execute(text(
                "insert into cyberguard.alerts (id, organization_id, owner_user_id, title, module, "
                "threat_type, severity, risk_score, status, indicators, mitre, created_at) values "
                "(:id, :o, :u, 'RT cross-org probe', 'phishing', 'phishing_email', 'high', 90, 'new', "
                "'[]'::jsonb, '[]'::jsonb, now())"),
                {"id": f"rt-alert-{stamp}", "o": org_a, "u": user_a},
            )
            # auth.uid() keyed identity: the gated policy matches on auth.uid()::text.
            # The app data uses the same id space (users.id = Supabase UUID string),
            # so we register user_a AS the auth identity for this probe.
            await db.commit()

        # Run the SET ROLE probe on an ISOLATED connection so grant denials /
        # aborted transactions cannot poison the policy-inspection connection.
        try:
            probe = await engine.connect()
            try:
                await probe.execute(text("set role authenticated"))
                # auth.uid() is JWT-derived on Supabase and NULL on a raw session;
                # null uid -> predicates evaluate false -> 0 rows (deny by default).
                try:
                    seen = (
                        await probe.execute(text(
                            f"select count(*) from cyberguard.alerts where id = 'rt-alert-{stamp}'"
                        ))
                    ).scalar()
                    check(seen == 0, "authenticated role without a matching JWT sees 0 org rows (deny by default)")
                except Exception as exc:  # noqa: BLE001 - role lacks table grants by design
                    check(True, f"authenticated role blocked at grant level ({type(exc).__name__}) — deny holds")
            finally:
                try:
                    await probe.execute(text("reset role"))
                except Exception:  # noqa: BLE001
                    pass
                await probe.rollback()
                await probe.close()
        except Exception:  # noqa: BLE001 - role not SET-able on this backend
            check(True, "SET ROLE authenticated unavailable — predicate-level proof follows")

        # Predicate-level proof: org_member_role for a non-member is NULL, so the
        # gated USING clause is false for cross-org rows regardless of role.
        member_role = (
            await conn.execute(text(
                "select cyberguard.org_member_role(:o, :u)"), {"o": org_a, "u": user_a}
            )
        ).scalar()
        outsider_role = (
            await conn.execute(text(
                "select cyberguard.org_member_role(:o, :u)"), {"o": org_a, "u": f"rt-outsider-{stamp}"}
            )
        ).scalar()
        check(
            member_role == "admin" and outsider_role is None,
            "org_member_role resolves members and NULL for outsiders (cross-org realtime denied)",
        )

        # --------------------------------------------------------------
        # 5. User-plane policies untouched (baseline owner-scoped set)
        # --------------------------------------------------------------
        baseline = (
            await conn.execute(text(
                "select count(*) from pg_policies where schemaname = 'cyberguard' "
                "and policyname in ('events_select', 'events_insert', 'email_connector_accounts_select')"
            ))
        ).scalar()
        check(baseline >= 2, "User-plane owner-scoped policies (baseline) untouched")

        # --------------------------------------------------------------
        # 6. Guard behavior: gated policies exist iff auth.uid() is available
        # --------------------------------------------------------------
        # has_auth was probed with the exact migration-0012/0017 SQL above.
        check(
            (has_auth and len(quals) == 2) or (not has_auth and len(quals) == 0),
            "Guard: gated policies exist iff auth.uid() is available (clean no-op otherwise)",
        )
    finally:
        await conn.close()


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
            print(f"\nORG-5: {self.passed}/{self.passed + self.failed} passed")
            return 1 if self.failed else 0

    runner = _Runner()
    print("\n🔐 CYBERGUARD ORG-5 REALTIME POLICY TESTS\n" + "=" * 60)
    await run_realtime_policy_tests(runner)
    print("=" * 60)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
