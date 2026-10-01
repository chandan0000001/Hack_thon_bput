"""Suite 49 — ORG-SETTINGS-P1 Project Deletion Automated Test Suite.

Verifies DELETE /orgs/{org_id}/projects/{project_id}:
- analyst delete -> 403
- wrong confirm_name -> 409
- success -> project-scoped rows (org_events / org_api_keys /
  org_blocked_indicators.project_id) gone, org + members + org-scoped
  indicator intact
- users.active_project_id pointing at the deleted project cleared
- deleting the last project allowed; org survives with 0 projects
"""

import uuid

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from app.core.security import CurrentUser, get_current_user
from app.db.models import OrgApiKey, OrgBlockedIndicator, OrgEvent, OrgMember, OrgProject, User
from app.db.session import async_session_maker
from app.main import app


async def run_org_settings_tests(runner) -> None:
    print("\n[Suite 49] ORG-SETTINGS-P1 — Project Deletion")

    from app.core.config import get_settings
    _saved_org_enabled = get_settings().ORG_ENABLED
    get_settings().ORG_ENABLED = True

    try:
        await _run_org_settings_body(runner)
    finally:
        get_settings().ORG_ENABLED = _saved_org_enabled


async def _run_org_settings_body(runner) -> None:
    admin_id = str(uuid.uuid4())
    analyst_id = str(uuid.uuid4())

    admin_user = CurrentUser(
        id=admin_id,
        email=f"settings-admin-{admin_id[:8]}@example.com",
        full_name="Settings Admin",
        username=f"settings_admin_{admin_id[:8]}",
        account_type="user",
    )
    analyst_user = CurrentUser(
        id=analyst_id,
        email=f"settings-analyst-{analyst_id[:8]}@example.com",
        full_name="Settings Analyst",
        username=f"settings_analyst_{analyst_id[:8]}",
        account_type="user",
    )

    from app.db.admin import _get_admin_session_maker
    admin_maker = _get_admin_session_maker()

    # Seed users in DB for FK constraints
    async with admin_maker() as db_session:
        db_session.add(User(
            id=admin_user.id,
            email=admin_user.email,
            full_name=admin_user.full_name,
            username=admin_user.username,
            account_type="user",
        ))
        db_session.add(User(
            id=analyst_user.id,
            email=analyst_user.email,
            full_name=analyst_user.full_name,
            username=analyst_user.username,
            account_type="user",
        ))
        await db_session.commit()

    app.dependency_overrides[get_current_user] = lambda: admin_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        org_id = None
        target_id = None       # "Delete Target" — cascades + pointer clear
        pointer_id = None      # "Pointer Proj" — deleted in last-project check

        try:
            # -----------------------------------------------------------------
            # Setup: org (+ auto 'Default Project'), analyst membership,
            # two extra projects, seeded project-scoped rows + active pointers
            # -----------------------------------------------------------------
            r_org = await client.post("/api/v1/orgs", json={"name": "Settings Test Org"})
            assert r_org.status_code == 201, r_org.text
            org_id = r_org.json()["id"]

            # MEMBER-INVITE-P1: the members POST now issues a token invitation
            # instead of creating the membership — seed the analyst membership
            # directly (service role: RLS blocks cross-user writes).
            from datetime import datetime, timezone

            async with admin_maker() as db:
                db.add(OrgMember(
                    id=str(uuid.uuid4()),
                    organization_id=org_id,
                    user_id=analyst_id,
                    role="analyst",
                    joined_at=datetime.now(timezone.utc),
                ))
                await db.commit()

            r_p1 = await client.post(
                f"/api/v1/orgs/{org_id}/projects",
                json={"name": "Delete Target", "slug": f"del-target-{uuid.uuid4().hex[:6]}"},
            )
            assert r_p1.status_code == 201, r_p1.text
            target_id = r_p1.json()["id"]

            r_p2 = await client.post(
                f"/api/v1/orgs/{org_id}/projects",
                json={"name": "Pointer Proj", "slug": f"pointer-{uuid.uuid4().hex[:6]}"},
            )
            assert r_p2.status_code == 201, r_p2.text
            pointer_id = r_p2.json()["id"]

            # Seed project-scoped rows for the target project (service-role:
            # RLS session would hide cross-user writes) and point both users'
            # active_project_id at it.
            async with admin_maker() as db:
                async with db.begin():
                    db.add_all([
                        OrgEvent(
                            project_id=target_id,
                            organization_id=org_id,
                            event_type="log_event",
                            severity="high",
                            raw_data={"subject": "seed 1"},
                        ),
                        OrgEvent(
                            project_id=target_id,
                            organization_id=org_id,
                            event_type="log_event",
                            severity="critical",
                            raw_data={"subject": "seed 2"},
                        ),
                        OrgApiKey(
                            project_id=target_id,
                            organization_id=org_id,
                            name="Seed Key",
                            role="master",
                            key_hash=f"seed-{uuid.uuid4().hex}",
                            key_prefix="sg_seed",
                        ),
                        OrgBlockedIndicator(
                            organization_id=org_id,
                            project_id=target_id,
                            indicator_type="domain",
                            indicator_value=f"evil-{uuid.uuid4().hex[:8]}.test",
                        ),
                        # Org-scoped indicator (project_id NULL) — must survive
                        OrgBlockedIndicator(
                            organization_id=org_id,
                            project_id=None,
                            indicator_type="ip",
                            indicator_value="203.0.113.77",
                        ),
                    ])
                    from app.db.models import User as UserModel
                    for uid in (admin_id, analyst_id):
                        u = await db.get(UserModel, uid)
                        u.active_project_id = target_id

            default_project_id = r_org.json().get("default_project_id")

            # -----------------------------------------------------------------
            # Check 1: analyst delete -> 403
            # -----------------------------------------------------------------
            try:
                app.dependency_overrides[get_current_user] = lambda: analyst_user
                r_403 = await client.request(
                    "DELETE",
                    f"/api/v1/orgs/{org_id}/projects/{target_id}",
                    json={"confirm_name": "Delete Target"},
                )
                runner.assert_true(
                    r_403.status_code == 403,
                    "1. analyst delete project -> 403",
                    f"Status: {r_403.status_code}, Body: {r_403.text}",
                )
            except Exception as exc:
                runner.assert_true(False, "1. analyst delete project -> 403", str(exc))
            finally:
                app.dependency_overrides[get_current_user] = lambda: admin_user

            # -----------------------------------------------------------------
            # Check 2: wrong confirm_name -> 409
            # -----------------------------------------------------------------
            try:
                r_409 = await client.request(
                    "DELETE",
                    f"/api/v1/orgs/{org_id}/projects/{target_id}",
                    json={"confirm_name": "Wrong Name"},
                )
                runner.assert_true(
                    r_409.status_code == 409,
                    "2. wrong confirm_name -> 409",
                    f"Status: {r_409.status_code}, Body: {r_409.text}",
                )
            except Exception as exc:
                runner.assert_true(False, "2. wrong confirm_name -> 409", str(exc))

            # -----------------------------------------------------------------
            # Check 3: success -> events+keys+scoped indicators gone,
            #          org + members + org-scoped indicator intact
            # -----------------------------------------------------------------
            try:
                r_del = await client.request(
                    "DELETE",
                    f"/api/v1/orgs/{org_id}/projects/{target_id}",
                    json={"confirm_name": "Delete Target"},
                )
                del_body = r_del.json() if r_del.status_code == 200 else {}
                counts_ok = (
                    del_body.get("deleted", {}).get("events") == 2
                    and del_body.get("deleted", {}).get("api_keys") == 1
                    and del_body.get("deleted", {}).get("blocked_indicators") == 1
                    and del_body.get("deleted", {}).get("active_pointers_cleared") == 2
                )
                async with async_session_maker() as db:
                    await db.execute(
                        text("SELECT set_config('app.user_id', :uid, true)"), {"uid": admin_id}
                    )
                    ev_left = await db.scalar(
                        text("SELECT count(*) FROM cyberguard.org_events WHERE project_id = :p"),
                        {"p": target_id},
                    )
                    key_left = await db.scalar(
                        text("SELECT count(*) FROM cyberguard.org_api_keys WHERE project_id = :p"),
                        {"p": target_id},
                    )
                    scoped_ind_left = await db.scalar(
                        text(
                            "SELECT count(*) FROM cyberguard.org_blocked_indicators "
                            "WHERE project_id = :p"
                        ),
                        {"p": target_id},
                    )
                    org_scoped_ind_left = await db.scalar(
                        text(
                            "SELECT count(*) FROM cyberguard.org_blocked_indicators "
                            "WHERE organization_id = :org AND project_id IS NULL"
                        ),
                        {"org": org_id},
                    )
                    proj_gone = await db.get(OrgProject, target_id)
                    r_org_get = await client.get(f"/api/v1/orgs/{org_id}")
                    r_members = await client.get(f"/api/v1/orgs/{org_id}/members")
                    members_intact = (
                        r_members.status_code == 200
                        and len(r_members.json().get("members", [])) == 2
                    )
                    intact = (
                        r_del.status_code == 200
                        and counts_ok
                        and ev_left == 0
                        and key_left == 0
                        and scoped_ind_left == 0
                        and org_scoped_ind_left == 1
                        and proj_gone is None
                        and r_org_get.status_code == 200
                        and members_intact
                    )
                    runner.assert_true(
                        intact,
                        "3. success delete cascades project rows, org+members+org indicator intact",
                        (
                            f"Status: {r_del.status_code}, Body: {del_body}, "
                            f"ev_left: {ev_left}, key_left: {key_left}, "
                            f"scoped_ind_left: {scoped_ind_left}, "
                            f"org_scoped_ind_left: {org_scoped_ind_left}, "
                            f"members: {r_members.text if not members_intact else 'ok'}"
                        ),
                    )
            except Exception as exc:
                runner.assert_true(False, "3. success delete cascade", str(exc))

            # -----------------------------------------------------------------
            # Check 4: users.active_project_id cleared for affected users
            # -----------------------------------------------------------------
            try:
                async with admin_maker() as db:
                    a_ptr = (await db.execute(
                        select(User.active_project_id).where(User.id == admin_id)
                    )).scalar_one_or_none()
                    m_ptr = (await db.execute(
                        select(User.active_project_id).where(User.id == analyst_id)
                    )).scalar_one_or_none()
                cleared = a_ptr is None and m_ptr is None
                runner.assert_true(
                    cleared,
                    "4. active_project_id cleared for affected users",
                    f"admin_ptr: {a_ptr}, analyst_ptr: {m_ptr}",
                )
            except Exception as exc:
                runner.assert_true(False, "4. active_project_id cleared", str(exc))

            # -----------------------------------------------------------------
            # Check 5: last-project delete allowed; org survives with 0 projects
            # -----------------------------------------------------------------
            try:
                r_del2 = await client.request(
                    "DELETE",
                    f"/api/v1/orgs/{org_id}/projects/{pointer_id}",
                    json={"confirm_name": "Pointer Proj"},
                )
                r_del3 = await client.request(
                    "DELETE",
                    f"/api/v1/orgs/{org_id}/projects/{default_project_id}",
                    json={"confirm_name": "Default Project"},
                )
                r_list = await client.get(f"/api/v1/orgs/{org_id}/projects")
                r_org_after = await client.get(f"/api/v1/orgs/{org_id}")
                last_ok = (
                    r_del2.status_code == 200
                    and r_del3.status_code == 200
                    and r_list.status_code == 200
                    and r_list.json().get("projects") == []
                    and r_org_after.status_code == 200
                    and r_org_after.json().get("id") == org_id
                )
                runner.assert_true(
                    last_ok,
                    "5. last-project delete leaves org with 0 projects",
                    (
                        f"del2: {r_del2.status_code}, del3: {r_del3.status_code}, "
                        f"projects: {r_list.text}, org: {r_org_after.status_code}"
                    ),
                )
            except Exception as exc:
                runner.assert_true(False, "5. last-project delete", str(exc))

        except Exception as exc:
            runner.assert_true(False, "Suite 49 setup", str(exc))
        finally:
            # Best-effort teardown of the seeded org (service-role, bypasses RLS)
            if org_id:
                try:
                    async with admin_maker() as db:
                        async with db.begin():
                            await db.execute(
                                text("DELETE FROM cyberguard.org_organizations WHERE id = :o"),
                                {"o": org_id},
                            )
                            from app.db.models import User as UserModel
                            for uid in (admin_id, analyst_id):
                                await db.execute(
                                    text("DELETE FROM cyberguard.users WHERE id = :u"),
                                    {"u": uid},
                                )
                except Exception:
                    pass

    # Clean up overrides
    app.dependency_overrides.pop(get_current_user, None)


async def run_org_member_email_tests(runner) -> None:
    """Suite 50 — ORG-SETTINGS-P6: real member emails for all members.

    Verifies the org_member_emails SECURITY DEFINER fn fixes the RLS-blinded
    users join: admin and analyst alike see every member's email, outsiders
    get rejected, and the definer never returns rows for a foreign org id.
    """
    print("\n[Suite 50] ORG-SETTINGS-P6 — Member Emails via Definer Fn")

    from app.core.config import get_settings
    _saved_org_enabled = get_settings().ORG_ENABLED
    get_settings().ORG_ENABLED = True

    try:
        await _run_member_email_body(runner)
    finally:
        get_settings().ORG_ENABLED = _saved_org_enabled


async def _run_member_email_body(runner) -> None:
    admin_id = str(uuid.uuid4())
    analyst_id = str(uuid.uuid4())
    outsider_id = str(uuid.uuid4())

    admin_user = CurrentUser(
        id=admin_id,
        email=f"mail-admin-{admin_id[:8]}@example.com",
        full_name="Mail Admin",
        username=f"mail_admin_{admin_id[:8]}",
        account_type="user",
    )
    analyst_user = CurrentUser(
        id=analyst_id,
        email=f"mail-analyst-{analyst_id[:8]}@example.com",
        full_name="Mail Analyst",
        username=f"mail_analyst_{analyst_id[:8]}",
        account_type="user",
    )
    outsider_user = CurrentUser(
        id=outsider_id,
        email=f"mail-outsider-{outsider_id[:8]}@example.com",
        full_name="Mail Outsider",
        username=f"mail_outsider_{outsider_id[:8]}",
        account_type="user",
    )

    from app.db.admin import _get_admin_session_maker
    admin_maker = _get_admin_session_maker()

    async with admin_maker() as db_session:
        for u in (admin_user, analyst_user, outsider_user):
            db_session.add(User(
                id=u.id, email=u.email, full_name=u.full_name,
                username=u.username, account_type="user",
            ))
        await db_session.commit()

    app.dependency_overrides[get_current_user] = lambda: admin_user
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r_org = await client.post("/api/v1/orgs", json={"name": "Mail Test Org"})
            assert r_org.status_code == 201, r_org.text
            org_id = r_org.json()["id"]

            # MEMBER-INVITE-P1: members POST now issues invitations — seed the
            # analyst membership directly (service role: RLS blocks cross-user writes).
            from datetime import datetime, timezone

            async with admin_maker() as db:
                db.add(OrgMember(
                    id=str(uuid.uuid4()),
                    organization_id=org_id,
                    user_id=analyst_id,
                    role="analyst",
                    joined_at=datetime.now(timezone.utc),
                ))
                await db.commit()

            # Check 1: admin list shows real emails for self AND others
            try:
                r_admin = await client.get(f"/api/v1/orgs/{org_id}/members")
                rows = r_admin.json().get("members", [])
                by_user = {m["user_id"]: m for m in rows}
                admin_email_ok = by_user.get(admin_id, {}).get("email") == admin_user.email
                analyst_email_ok = by_user.get(analyst_id, {}).get("email") == analyst_user.email
                runner.assert_true(
                    r_admin.status_code == 200 and admin_email_ok and analyst_email_ok,
                    "1. admin members list shows emails for self+others",
                    f"Status: {r_admin.status_code}, rows: {rows}",
                )
            except Exception as exc:
                runner.assert_true(False, "1. admin members list emails", str(exc))

            # Check 2: analyst list likewise sees all emails (RLS would blind them)
            try:
                app.dependency_overrides[get_current_user] = lambda: analyst_user
                r_analyst = await client.get(f"/api/v1/orgs/{org_id}/members")
                rows = r_analyst.json().get("members", [])
                by_user = {m["user_id"]: m for m in rows}
                emails_ok = (
                    by_user.get(admin_id, {}).get("email") == admin_user.email
                    and by_user.get(analyst_id, {}).get("email") == analyst_user.email
                )
                runner.assert_true(
                    r_analyst.status_code == 200 and emails_ok and len(rows) == 2,
                    "2. analyst members list shows emails for self+others",
                    f"Status: {r_analyst.status_code}, rows: {rows}",
                )
            except Exception as exc:
                runner.assert_true(False, "2. analyst members list emails", str(exc))
            finally:
                app.dependency_overrides[get_current_user] = lambda: admin_user

            # Check 3: outsider rejected; definer returns nothing for foreign org ids
            try:
                app.dependency_overrides[get_current_user] = lambda: outsider_user
                r_out = await client.get(f"/api/v1/orgs/{org_id}/members")
                outsider_rejected = r_out.status_code in (403, 404)
                app.dependency_overrides[get_current_user] = lambda: admin_user

                foreign_id = str(uuid.uuid4())
                async with async_session_maker() as db:
                    await db.execute(
                        text("SELECT set_config('app.user_id', :uid, true)"), {"uid": admin_id}
                    )
                    foreign_rows = (
                        await db.execute(
                            text(
                                "SELECT user_id, email FROM cyberguard.org_member_emails(:org)"
                            ),
                            {"org": foreign_id},
                        )
                    ).all()
                runner.assert_true(
                    outsider_rejected and len(foreign_rows) == 0,
                    "3. outsider rejected + definer returns 0 rows for foreign org",
                    f"status: {r_out.status_code}, foreign_rows: {foreign_rows}",
                )
            except Exception as exc:
                runner.assert_true(False, "3. outsider + foreign org definer call", str(exc))

            # Teardown
            async with admin_maker() as db:
                async with db.begin():
                    await db.execute(
                        text("DELETE FROM cyberguard.org_organizations WHERE id = :o"),
                        {"o": org_id},
                    )
                    for uid in (admin_id, analyst_id, outsider_id):
                        await db.execute(
                            text("DELETE FROM cyberguard.users WHERE id = :u"), {"u": uid}
                        )
    finally:
        app.dependency_overrides.pop(get_current_user, None)
