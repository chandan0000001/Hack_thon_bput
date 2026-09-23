"""Suite 46 — Organization Authentication, Membership Hydration, and RLS Fixes.

Verifies the 8 critical invariants of ORG-AUTH-FIX:
1. login -> /auth/me returns 200 with memberships array (empty for org-less user, no crash)
2. create org -> owner row in org_members with role='admin' in same tx, returns role='admin'
3. owner can SELECT own org via app-role GUC; outsider gets 0 rows (RLS isolation)
4. org dashboard returns 200 for owner/analyst; 403/404 for non-member
5. frontend hydration with zero orgs renders personal workspace, no redirect loop
6. gateway master key returns 200 for scan; viewer key gets 403
7. personal login + personal routes unaffected (spot checks pass)
8. revoke member -> their org access is gone immediately (RLS blocks)
"""

import asyncio
import uuid
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.core.config import get_settings
from app.db.session import async_session_maker
from app.main import app


async def run_org_auth_fix_tests(runner) -> None:
    print("\n[Suite 46] ORG-AUTH-FIX — Authentication, Membership Hydration, and RLS Context")

    saved_org_enabled = get_settings().ORG_ENABLED
    get_settings().ORG_ENABLED = True

    try:
        await _run_org_auth_fix_body(runner)
    finally:
        get_settings().ORG_ENABLED = saved_org_enabled


async def _run_org_auth_fix_body(runner) -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        uid1 = uuid.uuid4().hex[:8]
        uid2 = uuid.uuid4().hex[:8]
        uid3 = uuid.uuid4().hex[:8]

        owner_email = f"owner-{uid1}@cyberguard.local"
        analyst_email = f"analyst-{uid2}@cyberguard.local"
        outsider_email = f"outsider-{uid3}@cyberguard.local"

        owner_headers = {"Authorization": f"Bearer test-{owner_email}"}
        analyst_headers = {"Authorization": f"Bearer test-{analyst_email}"}
        outsider_headers = {"Authorization": f"Bearer test-{outsider_email}"}

        # -------------------------------------------------------------------
        # Check 1: login -> /auth/me returns 200 with memberships array (empty for org-less user, no crash)
        # -------------------------------------------------------------------
        r1 = await ac.get("/api/v1/auth/me", headers=owner_headers)
        runner.assert_true(
            r1.status_code == 200,
            f"Check 1.1: /auth/me for fresh user returned 200 (got {r1.status_code})",
        )
        data1 = r1.json()
        runner.assert_true(
            isinstance(data1.get("memberships"), list) and len(data1["memberships"]) == 0,
            "Check 1.2: memberships array present and empty for org-less user",
        )
        runner.assert_true(
            data1.get("active_organization") is None,
            "Check 1.3: active_organization is None for org-less user",
        )
        runner.assert_true(
            data1.get("is_single_user") is True,
            "Check 1.4: is_single_user is True for fresh personal workspace",
        )

        # -------------------------------------------------------------------
        # Check 2: create org -> owner row in org_members with role='admin' in same tx
        # -------------------------------------------------------------------
        org_name = f"AuthFix Corp {uid1}"
        r2 = await ac.post("/api/v1/orgs", headers=owner_headers, json={"name": org_name})
        runner.assert_true(
            r2.status_code == 201,
            f"Check 2.1: POST /orgs created org (got {r2.status_code})",
        )
        org_data = r2.json()
        org_id = org_data.get("id")
        runner.assert_true(
            org_data.get("role") == "admin",
            f"Check 2.2: create org response returns role='admin' (got {org_data.get('role')})",
        )

        # Verify owner row exists in org_members directly in DB
        async with async_session_maker() as db:
            m_res = await db.execute(
                text(
                    "SELECT role FROM cyberguard.org_members "
                    "WHERE organization_id = :oid AND user_id = :uid"
                ),
                {"oid": org_id, "uid": f"user-owner-{uid1}"},
            )
            member_row = m_res.first()
            runner.assert_true(
                member_row is not None and member_row[0] == "admin",
                "Check 2.3: org_members owner row created with role='admin' in same transaction",
            )

        # Re-check /auth/me now reflects the created organization
        r1_updated = await ac.get("/api/v1/auth/me", headers=owner_headers)
        data1_updated = r1_updated.json()
        memberships = data1_updated.get("memberships", [])
        runner.assert_true(
            len(memberships) >= 1 and any(m["id"] == org_id and m["role"] == "admin" for m in memberships),
            "Check 2.4: /auth/me derives memberships array containing newly created org with role='admin'",
        )

        # -------------------------------------------------------------------
        # Check 3: owner can SELECT own org via app-role GUC; outsider gets 0 rows
        # -------------------------------------------------------------------
        async with async_session_maker() as db:
            # Stamped as owner
            await db.execute(
                text("SELECT set_config('app.user_id', :uid, false), set_config('request.role', 'authenticated', false)"),
                {"uid": f"user-owner-{uid1}"},
            )
            r_owner = await db.execute(
                text("SELECT count(*) FROM cyberguard.org_organizations WHERE id = :oid"),
                {"oid": org_id},
            )
            owner_count = r_owner.scalar()

            # Stamped as outsider
            await db.execute(
                text("SELECT set_config('app.user_id', :uid, false), set_config('request.role', 'authenticated', false)"),
                {"uid": f"user-outsider-{uid3}"},
            )
            r_outsider = await db.execute(
                text("SELECT count(*) FROM cyberguard.org_organizations WHERE id = :oid"),
                {"oid": org_id},
            )
            outsider_count = r_outsider.scalar()

            runner.assert_true(
                owner_count == 1 and outsider_count == 0,
                f"Check 3: RLS isolation via GUC - owner sees 1 row ({owner_count}), outsider sees 0 ({outsider_count})",
            )

        # -------------------------------------------------------------------
        # Check 4: org dashboard returns 200 for owner/analyst; 403/404 for non-member
        # -------------------------------------------------------------------
        # Owner dashboard -> 200
        r_dash_owner = await ac.get(f"/api/v1/orgs/{org_id}/dashboard", headers=owner_headers)
        runner.assert_true(
            r_dash_owner.status_code == 200,
            f"Check 4.1: Owner gets 200 on org dashboard (got {r_dash_owner.status_code})",
        )

        # Outsider dashboard -> 403 or 404 (non-member)
        r_dash_outsider = await ac.get(f"/api/v1/orgs/{org_id}/dashboard", headers=outsider_headers)
        runner.assert_true(
            r_dash_outsider.status_code in (403, 404),
            f"Check 4.2: Non-member denied on org dashboard (got {r_dash_outsider.status_code})",
        )

        # -------------------------------------------------------------------
        # Check 5: frontend hydration with zero orgs renders personal workspace, no redirect loop
        # -------------------------------------------------------------------
        # Test fresh outsider hydration: memberships empty, is_single_user True, personal workspace intact
        r_outsider_me = await ac.get("/api/v1/auth/me", headers=outsider_headers)
        out_me = r_outsider_me.json()
        runner.assert_true(
            r_outsider_me.status_code == 200
            and out_me.get("is_single_user") is True
            and len(out_me.get("memberships", [])) == 0,
            "Check 5: Zero-org user hydrates cleanly into personal workspace (single_user=True, memberships=[])",
        )

        # -------------------------------------------------------------------
        # Check 6: gateway master key returns 200 for scan; viewer key gets 403
        # -------------------------------------------------------------------
        # Fetch default project
        r_projs = await ac.get(f"/api/v1/orgs/{org_id}/projects", headers=owner_headers)
        proj_list = r_projs.json().get("projects", [])
        runner.assert_true(len(proj_list) > 0, "Default project created with organization")
        default_proj = proj_list[0]
        proj_slug = default_proj["slug"]

        # Generate master key
        r_mkey = await ac.post(
            f"/api/v1/orgs/{org_id}/projects/{default_proj['id']}/keys",
            headers=owner_headers,
            json={"name": "Test Master Key", "role": "master"},
        )
        master_key = r_mkey.json().get("api_key")

        # Generate viewer key
        r_vkey = await ac.post(
            f"/api/v1/orgs/{org_id}/projects/{default_proj['id']}/keys",
            headers=owner_headers,
            json={"name": "Test Viewer Key", "role": "viewer"},
        )
        viewer_key = r_vkey.json().get("api_key")

        # Gateway request with Master Key -> 200
        gw_payload = {"action": "analyze_log", "data": {"log": "Accepted publickey for root"}}
        r_gw_m = await ac.post(
            f"/api/v1/p/{proj_slug}/gateway",
            headers={"Authorization": f"Bearer {master_key}"},
            json=gw_payload,
        )
        runner.assert_true(
            r_gw_m.status_code == 200,
            f"Check 6.1: Gateway accepts Bearer master key -> 200 (got {r_gw_m.status_code})",
        )

        # Gateway request with Viewer Key -> 403
        r_gw_v = await ac.post(
            f"/api/v1/p/{proj_slug}/gateway",
            headers={"Authorization": f"Bearer {viewer_key}"},
            json=gw_payload,
        )
        runner.assert_true(
            r_gw_v.status_code == 403,
            f"Check 6.2: Gateway rejects viewer key for analysis -> 403 (got {r_gw_v.status_code})",
        )

        # -------------------------------------------------------------------
        # Check 7: personal login + personal routes unaffected (spot suite)
        # -------------------------------------------------------------------
        r_pers_dash = await ac.get("/api/v1/dashboard/summary", headers=owner_headers)
        runner.assert_true(
            r_pers_dash.status_code == 200,
            f"Check 7.1: Personal /dashboard/summary returns 200 (got {r_pers_dash.status_code})",
        )
        r_pers_notif = await ac.put(
            "/api/v1/auth/notification-email",
            headers=owner_headers,
            json={"notification_email": f"alert-{uid1}@example.com"},
        )
        runner.assert_true(
            r_pers_notif.status_code == 200,
            f"Check 7.2: Personal notification email update returns 200 (got {r_pers_notif.status_code})",
        )

        # -------------------------------------------------------------------
        # Check 8: revoke member -> their org access is gone immediately (RLS blocks)
        # -------------------------------------------------------------------
        # Add analyst as member
        r_add_mem = await ac.post(
            f"/api/v1/orgs/{org_id}/members",
            headers=owner_headers,
            json={"email": analyst_email, "role": "analyst"},
        )
        runner.assert_true(
            r_add_mem.status_code == 201,
            f"Check 8.1: Member added successfully with role='analyst' (got {r_add_mem.status_code})",
        )
        membership_id = r_add_mem.json()["id"]

        # Analyst can view dashboard -> 200
        r_analyst_dash = await ac.get(f"/api/v1/orgs/{org_id}/dashboard", headers=analyst_headers)
        runner.assert_true(
            r_analyst_dash.status_code == 200,
            f"Check 8.2: Added analyst can access org dashboard -> 200 (got {r_analyst_dash.status_code})",
        )

        # Revoke member
        r_revoke = await ac.delete(
            f"/api/v1/orgs/{org_id}/members/{membership_id}",
            headers=owner_headers,
        )
        runner.assert_true(
            r_revoke.status_code == 200,
            f"Check 8.3: Member successfully removed (got {r_revoke.status_code})",
        )

        # Analyst access is IMMEDIATELY gone -> 403 or 404
        r_revoked_dash = await ac.get(f"/api/v1/orgs/{org_id}/dashboard", headers=analyst_headers)
        runner.assert_true(
            r_revoked_dash.status_code in (403, 404),
            f"Check 8.4: Revoked member immediately blocked from org dashboard (got {r_revoked_dash.status_code})",
        )
