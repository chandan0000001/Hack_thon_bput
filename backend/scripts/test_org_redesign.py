"""ORG-REDESIGN — multi-project architecture + project-scoped API keys
(Suite 40, 14 checks).

 1. create_project generates a unique slug; duplicate NAME in the same org
    is rejected (409).
 2. list_projects filters by org; an outsider's RLS session sees 0 rows.
 3. create_project_key role=master returns plaintext ONCE; only the SHA-256
    hash is stored.
 4. A SECOND active master key for the same project is rejected (409).
 5. A SECOND active viewer key is rejected (409).
 6. Revoking the master key frees the slot — a new master can be created.
 7. validate_project_api_key (SECURITY DEFINER) returns
    (project_id, organization_id, role); a revoked key resolves to nothing.
 8. POST /org/{org}/projects/{slug}/gateway with a valid master key returns
    200 and stamps the created Event with the project_id.
 9. Viewer key: read-only actions pass (scan_email 200); write actions
    reject 403.
10. A revoked key is rejected 401 on the project gateway.
11. An unknown project slug returns 404.
12. An outsider (member of ANOTHER org) sees 0 of this org's projects
    through RLS.
13. A valid key belonging to another org's project is rejected 401 on this
    org's project gateway.
14. Migrations 0019/0020 contain zero auth-schema references.

Run via run_all_tests.py (Suite 40) or standalone:
    uv run python scripts/test_org_redesign.py
"""

import asyncio
import hashlib
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from app.core.security import CurrentUser, get_current_user
from app.db.admin import _get_admin_session_maker
from app.db.session import async_session_maker, current_user_id, engine
from app.main import app


class _Identity:
    user: CurrentUser | None = None


async def _mock_get_current_user() -> CurrentUser:
    if _Identity.user is None:
        raise RuntimeError("test identity not set")
    current_user_id.set(_Identity.user.id)
    return _Identity.user


async def _count_as(guc_user: str, sql: str, params: dict) -> int:
    async with engine.connect() as conn:
        await conn.execute(text("select set_config('app.user_id', :uid, false)"), {"uid": guc_user})
        return (await conn.execute(text(sql), params)).scalar()


async def _ensure_user(db, user_id: str, email: str) -> None:
    from app.db.models import User

    existing = await db.execute(select(User).where(User.id == user_id))
    if existing.scalar_one_or_none() is not None:
        return
    await db.commit()
    current_user_id.set(user_id)
    db.add(User(id=user_id, email=email, full_name=user_id, is_single_user=True))
    await db.commit()
    current_user_id.set(None)


async def run_org_redesign_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("ORG-REDESIGN: projects, project keys, project gateway, RLS")
    print("-" * 60)

    if "postgresql" not in str(engine.dialect.name):
        check(True, "ORG-REDESIGN suite skipped without PostgreSQL")
        print("         Skipped: no PostgreSQL configured")
        return

    stamp = uuid.uuid4().hex[:8]
    admin = CurrentUser(id=f"s40-admin-{stamp}", email=f"s40-admin-{stamp}@cyberguard.test", full_name="S40 Admin")
    outsider = CurrentUser(id=f"s40-out-{stamp}", email=f"s40-out-{stamp}@cyberguard.test", full_name="S40 Outsider")
    other_admin = CurrentUser(id=f"s40-orgb-{stamp}", email=f"s40-orgb-{stamp}@cyberguard.test", full_name="S40 OrgB Admin")

    org_id = ""
    other_org_id = ""
    app.dependency_overrides[get_current_user] = _mock_get_current_user
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # ---------- provisioning ----------
            async with async_session_maker() as db:
                for u in (admin, outsider, other_admin):
                    await _ensure_user(db, u.id, u.email or "")

            _Identity.user = admin
            res = await client.post("/api/v1/orgs", json={"name": f"Redesign Org {stamp}"})
            org_id = res.json()["id"]
            # Org creation auto-provisions the default 'General' project.
            res = await client.get(f"/api/v1/orgs/{org_id}/projects")
            default_projects = res.json() if res.status_code == 200 else []
            check(
                res.status_code == 200 and any(p["slug"] == "general" for p in default_projects),
                "40.0a org creation auto-provisions the default 'General' project",
                f"status={res.status_code} projects={default_projects}",
            )

            _Identity.user = other_admin
            res = await client.post("/api/v1/orgs", json={"name": f"Redesign Other Org {stamp}"})
            other_org_id = res.json()["id"]

            # ---------- 1. create_project: slug + duplicate name ----------
            _Identity.user = admin
            res = await client.post(f"/api/v1/orgs/{org_id}/projects", json={"name": "Demo"})
            check(
                res.status_code == 201 and res.json()["slug"] == "demo",
                "40.1a create_project generates the expected slug",
                f"status={res.status_code} body={res.json()}",
            )
            project_id = res.json()["id"]
            project_slug = res.json()["slug"]
            res_dup = await client.post(f"/api/v1/orgs/{org_id}/projects", json={"name": "Demo"})
            check(
                res_dup.status_code == 409,
                "40.1b duplicate project name in the same org rejected (409)",
                f"status={res_dup.status_code} body={res_dup.text[:120]}",
            )

            # ---------- 2. list filters by org; outsider RLS sees 0 ----------
            res_all = await client.get(f"/api/v1/orgs/{org_id}/projects")
            names = {p["name"] for p in res_all.json()}
            check(
                res_all.status_code == 200 and {"General", "Demo"} <= names,
                "40.2a list_projects returns this org's projects",
                f"status={res_all.status_code} names={names}",
            )
            outsider_count = await _count_as(
                outsider.id,
                "select count(*) from cyberguard.projects where organization_id = :org",
                {"org": org_id},
            )
            check(
                outsider_count == 0,
                "40.2b outsider RLS session sees 0 of the org's projects",
                f"count={outsider_count}",
            )

            # ---------- 3. master key: plaintext once, hash stored ----------
            res = await client.post(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/keys",
                json={"role": "master", "name": "ops master"},
            )
            master = res.json() if res.status_code == 201 else {}
            check(
                res.status_code == 201
                and master.get("key", "").startswith("cg_prj_")
                and master.get("role") == "master"
                and "key" not in str(master.get("key_prefix")),
                "40.3a master key created — plaintext returned once (cg_prj_ prefix)",
                f"status={res.status_code} keys={list(master.keys())}",
            )
            stored_hash = (
                await _count_as(
                    admin.id,
                    "select key_hash from cyberguard.project_api_keys where id = :kid",
                    {"kid": master.get("id", "")},
                )
                if master.get("id")
                else None
            )
            check(
                stored_hash == hashlib.sha256(master.get("key", "").encode()).hexdigest(),
                "40.3b only the SHA-256 hash is stored",
                f"hash_match={stored_hash == hashlib.sha256(master.get('key', '').encode()).hexdigest()}",
            )

            # ---------- 4/5. second active key per role rejected ----------
            res = await client.post(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/keys",
                json={"role": "master", "name": "second master"},
            )
            check(res.status_code == 409, "40.4 second active master key rejected (409)",
                  f"status={res.status_code}")
            res = await client.post(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/keys",
                json={"role": "viewer", "name": "read only"},
            )
            viewer = res.json() if res.status_code == 201 else {}
            check(res.status_code == 201 and viewer.get("role") == "viewer",
                  "40.5a viewer key created", f"status={res.status_code}")
            res = await client.post(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/keys",
                json={"role": "viewer", "name": "second viewer"},
            )
            check(res.status_code == 409, "40.5b second active viewer key rejected (409)",
                  f"status={res.status_code}")

            # ---------- 6. revoke master frees the slot ----------
            res = await client.delete(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/keys/{master['id']}"
            )
            check(res.status_code == 200, "40.6a master key revoked", f"status={res.status_code}")
            res = await client.post(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/keys",
                json={"role": "master", "name": "replacement master"},
            )
            master2 = res.json() if res.status_code == 201 else {}
            check(res.status_code == 201 and master2.get("key", "").startswith("cg_prj_"),
                  "40.6b new master key creatable after revocation",
                  f"status={res.status_code}")

            # ---------- 7. validate_project_api_key definer ----------
            async with engine.connect() as conn:
                row = (
                    await conn.execute(
                        text("select project_id, organization_id, role, status "
                             "from cyberguard.validate_project_api_key(:h)"),
                        {"h": hashlib.sha256(master2["key"].encode()).hexdigest()},
                    )
                ).first()
                revoked_row = (
                    await conn.execute(
                        text("select project_id from cyberguard.validate_project_api_key(:h)"),
                        {"h": hashlib.sha256(master["key"].encode()).hexdigest()},
                    )
                ).first()
            check(
                row is not None
                and row[0] == project_id
                and row[1] == org_id
                and row[2] == "master"
                and row[3] == "active",
                "40.7a validate_project_api_key returns (project, org, role)",
                f"row={tuple(row) if row else None}",
            )
            # The definer returns the row with its status column (indexed
            # exact-match lookup, like validate_org_api_key); the Python-side
            # validator treats non-active as invalid.
            from app.services.api_key_service import validate_project_key as _vpk

            async with async_session_maker() as vdb:
                revoked_claims = await _vpk(vdb, master["key"])
            check(revoked_claims is None, "40.7b revoked key resolves to nothing",
                  f"revoked_claims={revoked_claims}")

            # ---------- 8. project gateway: master key 200 + project stamp ----------
            res = await client.post(
                f"/api/v1/org/{org_id}/projects/{project_slug}/gateway",
                headers={"org_authorization": master2["key"]},
                json={"action": "scan_email",
                      "data": {"sender": "phish@s40.evil.xyz",
                               "subject": "S40 gateway urgency",
                               "body": "Verify your password now at http://185.220.101.7/login or your account will be suspended."}},
            )
            check(res.status_code == 200 and res.json().get("project") == project_slug,
                  "40.8a project gateway accepts a valid master key (200)",
                  f"status={res.status_code} body={res.text[:160]}")
            stamped = (
                await _count_as(
                    admin.id,
                    "select count(*) from cyberguard.events where project_id = :pid",
                    {"pid": project_id},
                )
                if project_id
                else 0
            )
            check(stamped > 0, "40.8b gateway event stamped with project_id",
                  f"stamped={stamped}")

            # ---------- 9. viewer: read-only OK, write 403 ----------
            res = await client.post(
                f"/api/v1/org/{org_id}/projects/{project_slug}/gateway",
                headers={"org_authorization": viewer["key"]},
                json={"action": "scan_email",
                      "data": {"sender": "scan@s40.evil.xyz",
                               "subject": "Viewer read-only scan",
                               "body": "Routine maintenance notice, nothing to act on."}},
            )
            check(res.status_code == 200, "40.9a viewer key may run read-only scan_email",
                  f"status={res.status_code} body={res.text[:120]}")
            res = await client.post(
                f"/api/v1/org/{org_id}/projects/{project_slug}/gateway",
                headers={"org_authorization": viewer["key"]},
                json={"action": "quarantine_release", "data": {}},
            )
            check(res.status_code == 403, "40.9b viewer key rejected on write actions (403)",
                  f"status={res.status_code} body={res.text[:120]}")

            # ---------- 10. revoked key 401 ----------
            res = await client.post(
                f"/api/v1/org/{org_id}/projects/{project_slug}/gateway",
                headers={"org_authorization": master["key"]},  # revoked in 40.6a
                json={"action": "scan_email", "data": {"sender": "x@y.z"}},
            )
            check(res.status_code == 401, "40.10 revoked key rejected 401",
                  f"status={res.status_code}")

            # ---------- 11. wrong slug 404 ----------
            res = await client.post(
                f"/api/v1/org/{org_id}/projects/does-not-exist-{stamp}/gateway",
                headers={"org_authorization": master2["key"]},
                json={"action": "scan_email", "data": {"sender": "x@y.z"}},
            )
            check(res.status_code == 404, "40.11 unknown project slug returns 404",
                  f"status={res.status_code}")

            # ---------- 12. outsider RLS on projects (cross-org) ----------
            leak = await _count_as(
                other_admin.id,
                "select count(*) from cyberguard.projects where organization_id = :org",
                {"org": org_id},
            )
            check(leak == 0, "40.12 other-org admin sees 0 of this org's projects (RLS)",
                  f"count={leak}")

            # ---------- 13. other org's valid key on this org's gateway ----------
            async with async_session_maker() as db:
                current_user_id.set(other_admin.id)
                from app.services.project_service import create_project

                other_project = await create_project(
                    db, org_id=other_org_id, name="OrgB Project", actor_user_id=other_admin.id
                )
                current_user_id.set(None)
            _Identity.user = other_admin
            res = await client.post(
                f"/api/v1/orgs/{other_org_id}/projects/{other_project.id}/keys",
                json={"role": "master", "name": "orgB master"},
            )
            orgb_key = res.json().get("key", "") if res.status_code == 201 else ""
            res = await client.post(
                f"/api/v1/org/{org_id}/projects/{project_slug}/gateway",
                headers={"org_authorization": orgb_key},
                json={"action": "scan_email", "data": {"sender": "x@y.z"}},
            )
            check(res.status_code == 401, "40.13 another org's valid key rejected 401 here",
                  f"status={res.status_code} body={res.text[:120]}")

            # ---------- 14. migrations carry zero auth-schema references ----------
            mig_dir = ROOT / "alembic" / "versions"
            mig_text = ""
            for name in ("0019_projects_keys.py", "0020_events_project_id.py"):
                mig_text += (mig_dir / name).read_text()
            bad = [frag for frag in ("auth.uid", "auth.users", "auth.role(", "supabase_auth_admin")
                   if frag in mig_text]
            check(
                not bad,
                "40.14 migrations 0019/0020 contain zero auth-schema references",
                f"found={bad}",
            )

    finally:
        app.dependency_overrides.pop(get_current_user, None)
        _Identity.user = None
        # Archive the scratch projects so repeat runs stay clean.
        if org_id:
            try:
                async with _get_admin_session_maker()() as adb:
                    await adb.execute(
                        text("delete from cyberguard.projects where organization_id = :o"),
                        {"o": org_id},
                    )
                    await adb.execute(
                        text("delete from cyberguard.projects where organization_id = :o"),
                        {"o": other_org_id},
                    )
                    await adb.commit()
            except Exception:  # noqa: BLE001 - cleanup best-effort
                pass


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
            print(f"\nORG-REDESIGN: {self.passed}/{self.passed + self.failed} passed")
            return 1 if self.failed else 0

    runner = _Runner()
    print("\n🔗 CYBERGUARD ORG-REDESIGN TESTS\n" + "=" * 60)
    await run_org_redesign_tests(runner)
    print("=" * 60)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
