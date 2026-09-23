"""Suite 45 — Organization Rebuild Automated Test Suite.

Verifies the 3-level architecture:
- Org Monitoring: initial counters, dashboard aggregation, membership
- Project Gateway: master / viewer keys, 501 on unavailable actions, 404 on slug, blocked indicator auto-verdict
- User Controls: event review, release (with 409 indicator collision check), permanent blocking, false positive
- Security & DB: RLS outsider isolation, plaintext-once keys, slot freeing on revoke, realtime publication, zero USING(true) policies
"""

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from app.core.security import CurrentUser, get_current_user
from app.db.models import OrgApiKey, OrgBlockedIndicator, OrgEvent, OrgMember, OrgOrganization, OrgProject, User
from app.db.session import async_session_maker
from app.main import app

logger = logging.getLogger("cyberguard.test_org_rebuild")


async def run_org_rebuild_tests(runner) -> None:
    print("\n[Suite 45] ORG-REBUILD — Organization System 3-Level Architecture")

    from app.core.config import get_settings
    _saved_org_enabled = get_settings().ORG_ENABLED
    get_settings().ORG_ENABLED = True

    try:
        await _run_org_rebuild_body(runner)
    finally:
        get_settings().ORG_ENABLED = _saved_org_enabled


async def _run_org_rebuild_body(runner) -> None:
    admin_id = str(uuid.uuid4())
    outsider_id = str(uuid.uuid4())

    admin_user = CurrentUser(
        id=admin_id,
        email=f"admin-{admin_id[:8]}@example.com",
        full_name="Rebuild Admin",
        username=f"admin_{admin_id[:8]}",
        account_type="user",
    )
    outsider_user = CurrentUser(
        id=outsider_id,
        email=f"outsider-{outsider_id[:8]}@example.com",
        full_name="Outsider User",
        username=f"outsider_{outsider_id[:8]}",
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
            id=outsider_user.id,
            email=outsider_user.email,
            full_name=outsider_user.full_name,
            username=outsider_user.username,
            account_type="user",
        ))
        await db_session.commit()

    # Set dependency override for admin user
    app.dependency_overrides[get_current_user] = lambda: admin_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Context to share across checks
        org_id = None
        project_id = None
        project_slug = f"rebuild-proj-{uuid.uuid4().hex[:6]}"
        master_key = None
        master_key_id = None
        viewer_key = None
        clean_event_id = None
        blocked_event_id = None
        auto_block_ev_id = None

        # -------------------------------------------------------------------
        # Check 1: org+project+key create
        # -------------------------------------------------------------------
        try:
            # Create org
            r_org = await client.post("/api/v1/orgs", json={"name": "Rebuild Test Org"})
            runner.assert_true(
                r_org.status_code == 201 and "id" in r_org.json(),
                "1. org+project+key create (organization)",
                f"Status: {r_org.status_code}, Body: {r_org.text}",
            )
            org_id = r_org.json()["id"]

            # Create project
            r_proj = await client.post(
                f"/api/v1/orgs/{org_id}/projects",
                json={"name": "Rebuild Project", "slug": project_slug},
            )
            runner.assert_true(
                r_proj.status_code == 201 and r_proj.json().get("slug") == project_slug,
                "1. org+project+key create (project)",
                f"Status: {r_proj.status_code}, Body: {r_proj.text}",
            )
            project_id = r_proj.json()["id"]

            # Create master key
            r_key = await client.post(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/keys",
                json={"name": "Master Key", "role": "master"},
            )
            k_body = r_key.json()
            master_key = k_body.get("api_key")
            master_key_id = k_body.get("id")
            runner.assert_true(
                r_key.status_code == 201 and bool(master_key) and master_key.startswith("cg_org_"),
                "1. org+project+key create (master API key plaintext)",
                f"Status: {r_key.status_code}, Key: {master_key}",
            )
        except Exception as exc:
            runner.assert_true(False, "1. org+project+key create", str(exc))

        # -------------------------------------------------------------------
        # Check 2: gateway master 200 + event row
        # -------------------------------------------------------------------
        try:
            payload = {
                "action": "analyze_log",
                "data": {
                    "message": "User authenticated successfully",
                    "ip": "10.0.0.1",
                    "service": "auth",
                },
            }
            r_gw = await client.post(
                f"/api/v1/p/{project_slug}/gateway",
                json=payload,
                headers={"Authorization": f"Bearer {master_key}"},
            )
            gw_data = r_gw.json()
            clean_event_id = gw_data.get("event_id")

            # Verify in DB
            db_row_exists = False
            async with async_session_maker() as db:
                await db.execute(text("SELECT set_config('app.user_id', :uid, true)"), {"uid": admin_id})
                ev = await db.get(OrgEvent, clean_event_id)
                if ev and ev.verdict == "pending_review" and ev.source == "gateway":
                    db_row_exists = True

            runner.assert_true(
                r_gw.status_code == 200
                and gw_data.get("verdict") == "pending_review"
                and db_row_exists,
                "2. gateway master 200 + event row inserted",
                f"Status: {r_gw.status_code}, Body: {gw_data}, DB row exists: {db_row_exists}",
            )
        except Exception as exc:
            runner.assert_true(False, "2. gateway master 200 + event row", str(exc))

        # -------------------------------------------------------------------
        # Check 3: viewer 403
        # -------------------------------------------------------------------
        try:
            r_vkey = await client.post(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/keys",
                json={"name": "Viewer Key", "role": "viewer"},
            )
            viewer_key = r_vkey.json().get("api_key")

            r_vgw = await client.post(
                f"/api/v1/p/{project_slug}/gateway",
                json={"action": "analyze_log", "data": {"message": "test"}},
                headers={"Authorization": f"Bearer {viewer_key}"},
            )
            runner.assert_true(
                r_vgw.status_code == 403,
                "3. viewer 403 on analyze action",
                f"Status: {r_vgw.status_code}, Detail: {r_vgw.text}",
            )
        except Exception as exc:
            runner.assert_true(False, "3. viewer 403", str(exc))

        # -------------------------------------------------------------------
        # Check 4: bad key / missing key 401 & bad payload 422
        # -------------------------------------------------------------------
        try:
            # 4a: Bad key -> 401
            r_bad = await client.post(
                f"/api/v1/p/{project_slug}/gateway",
                json={"action": "analyze_log", "data": {"message": "test"}},
                headers={"Authorization": "Bearer cg_org_totally_invalid_token_9999"},
            )
            # 4b: Missing key -> 401
            r_missing = await client.post(
                f"/api/v1/p/{project_slug}/gateway",
                json={"action": "analyze_log", "data": {"message": "test"}},
            )
            # 4c: Bad payload -> 422
            r_payload = await client.post(
                f"/api/v1/p/{project_slug}/gateway",
                json={"invalid": "no action or data"},
                headers={"Authorization": f"Bearer {master_key}"},
            )
            runner.assert_true(
                r_bad.status_code == 401 and r_missing.status_code == 401 and r_payload.status_code == 422,
                "4. gateway matrix (bad key 401, missing key 401, bad payload 422)",
                f"Bad: {r_bad.status_code}, Missing: {r_missing.status_code}, Payload: {r_payload.status_code}",
            )
        except Exception as exc:
            runner.assert_true(False, "4. gateway matrix (bad key, missing key, bad payload)", str(exc))

        # -------------------------------------------------------------------
        # Check 5: unknown slug 404
        # -------------------------------------------------------------------
        try:
            r_slug = await client.post(
                "/api/v1/p/nonexistent-project-slug-xyz/gateway",
                json={"action": "analyze_log", "data": {"message": "test"}},
                headers={"Authorization": f"Bearer {master_key}"},
            )
            runner.assert_true(
                r_slug.status_code == 404,
                "5. unknown slug 404 not found",
                f"Status: {r_slug.status_code}, Detail: {r_slug.text}",
            )
        except Exception as exc:
            runner.assert_true(False, "5. unknown slug 404", str(exc))

        # -------------------------------------------------------------------
        # Check 6: unavailable analyzer 501 (skip-if-available variant)
        # -------------------------------------------------------------------
        try:
            r_501 = await client.post(
                f"/api/v1/p/{project_slug}/gateway",
                json={"action": "analyze_quantum_future", "data": {"message": "test"}},
                headers={"Authorization": f"Bearer {master_key}"},
            )
            body_501 = r_501.json()
            runner.assert_true(
                r_501.status_code == 501
                and body_501.get("error") == "analyzer_not_implemented"
                and body_501.get("analyzer") == "analyze_quantum_future",
                "6. unavailable analyzer 501",
                f"Status: {r_501.status_code}, Body: {body_501}",
            )
        except Exception as exc:
            runner.assert_true(False, "6. unavailable analyzer 501", str(exc))

        # -------------------------------------------------------------------
        # Check 7: blocked-indicator auto-verdict
        # -------------------------------------------------------------------
        try:
            # Block an IP
            blocked_ip = "198.51.100.99"
            r_add_b = await client.post(
                f"/api/v1/orgs/{org_id}/blocked-indicators",
                json={
                    "indicator_type": "ip",
                    "indicator_value": blocked_ip,
                    "reason": "Known scanner IP",
                },
            )
            runner.assert_true(r_add_b.status_code == 201, "7. blocked-indicator added")

            # Ingest payload containing this IP
            r_hit = await client.post(
                f"/api/v1/p/{project_slug}/gateway",
                json={"action": "analyze_log", "data": {"message": "probe", "ip": blocked_ip}},
                headers={"Authorization": f"Bearer {master_key}"},
            )
            hit_data = r_hit.json()
            blocked_event_id = hit_data.get("event_id")

            runner.assert_true(
                r_hit.status_code == 200
                and hit_data.get("verdict") == "blocked_permanently"
                and hit_data.get("blocked_indicator_matched") is True,
                "7. blocked-indicator auto-verdict = blocked_permanently",
                f"Status: {r_hit.status_code}, Body: {hit_data}",
            )
        except Exception as exc:
            runner.assert_true(False, "7. blocked-indicator auto-verdict", str(exc))

        # -------------------------------------------------------------------
        # Check 8: event release OK
        # -------------------------------------------------------------------
        try:
            r_rel = await client.patch(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/events/{clean_event_id}",
                json={"action": "released"},
            )
            runner.assert_true(
                r_rel.status_code == 200 and r_rel.json().get("verdict") == "released",
                "8. event release OK",
                f"Status: {r_rel.status_code}, Body: {r_rel.text}",
            )
        except Exception as exc:
            runner.assert_true(False, "8. event release OK", str(exc))

        # -------------------------------------------------------------------
        # Check 9: release-with-blocked-indicator 409
        # -------------------------------------------------------------------
        try:
            r_conflict = await client.patch(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/events/{blocked_event_id}",
                json={"action": "released"},
            )
            runner.assert_true(
                r_conflict.status_code == 409,
                "9. release-with-blocked-indicator 409 conflict",
                f"Status: {r_conflict.status_code}, Detail: {r_conflict.text}",
            )
        except Exception as exc:
            runner.assert_true(False, "9. release-with-blocked-indicator 409", str(exc))

        # -------------------------------------------------------------------
        # Check 10: block_permanently inserts indicators
        # -------------------------------------------------------------------
        try:
            new_target_ip = "203.0.113.77"
            r_ing = await client.post(
                f"/api/v1/p/{project_slug}/gateway",
                json={"action": "analyze_log", "data": {"message": "malicious brute force", "ip": new_target_ip}},
                headers={"Authorization": f"Bearer {master_key}"},
            )
            auto_block_ev_id = r_ing.json().get("event_id")

            # Transition verdict to blocked_permanently
            r_bp = await client.patch(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/events/{auto_block_ev_id}",
                json={"action": "blocked_permanently"},
            )

            # Check that new_target_ip is now present in org_blocked_indicators
            async with async_session_maker() as db:
                await db.execute(text("SELECT set_config('app.user_id', :uid, true)"), {"uid": admin_id})
                ind = await db.scalar(
                    select(OrgBlockedIndicator).where(
                        OrgBlockedIndicator.organization_id == org_id,
                        OrgBlockedIndicator.indicator_value == new_target_ip,
                    )
                )
                ind_inserted = ind is not None

            runner.assert_true(
                r_bp.status_code == 200 and ind_inserted,
                "10. block_permanently inserts indicators",
                f"Status: {r_bp.status_code}, Indicator inserted: {ind_inserted}",
            )
        except Exception as exc:
            runner.assert_true(False, "10. block_permanently inserts indicators", str(exc))

        # -------------------------------------------------------------------
        # Check 11: false_positive sets verdict
        # -------------------------------------------------------------------
        try:
            r_fp = await client.patch(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/events/{auto_block_ev_id}",
                json={"action": "false_positive"},
            )
            runner.assert_true(
                r_fp.status_code == 200 and r_fp.json().get("verdict") == "false_positive",
                "11. false_positive sets verdict",
                f"Status: {r_fp.status_code}, Body: {r_fp.text}",
            )
        except Exception as exc:
            runner.assert_true(False, "11. false_positive sets verdict", str(exc))

        # -------------------------------------------------------------------
        # Check 12: counters initial aggregates correct
        # -------------------------------------------------------------------
        try:
            r_cnt = await client.get(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/counters/initial"
            )
            cnt_data = r_cnt.json()
            is_valid = (
                r_cnt.status_code == 200
                and isinstance(cnt_data.get("total_24h"), int)
                and cnt_data.get("total_24h") >= 3
                and "critical" in cnt_data.get("by_severity", {})
                and "log" in cnt_data.get("by_type", {})
                and isinstance(cnt_data.get("pending_review"), int)
                and cnt_data.get("blocked_indicators_count", 0) >= 2
            )
            runner.assert_true(
                is_valid,
                "12. counters initial aggregates correct",
                f"Status: {r_cnt.status_code}, Data: {cnt_data}",
            )
        except Exception as exc:
            runner.assert_true(False, "12. counters initial aggregates", str(exc))

        # -------------------------------------------------------------------
        # Check 13: RLS outsider 0 rows on org_events+blocked_indicators+projects
        # -------------------------------------------------------------------
        try:
            async with async_session_maker() as db:
                await db.execute(text("SELECT set_config('app.user_id', :uid, true)"), {"uid": outsider_id})
                ev_cnt = await db.scalar(
                    text("SELECT count(*) FROM cyberguard.org_events WHERE organization_id = :org"),
                    {"org": org_id},
                )
                bi_cnt = await db.scalar(
                    text("SELECT count(*) FROM cyberguard.org_blocked_indicators WHERE organization_id = :org"),
                    {"org": org_id},
                )
                pr_cnt = await db.scalar(
                    text("SELECT count(*) FROM cyberguard.org_projects WHERE organization_id = :org"),
                    {"org": org_id},
                )
                ak_cnt = await db.scalar(
                    text("SELECT count(*) FROM cyberguard.org_api_keys WHERE organization_id = :org"),
                    {"org": org_id},
                )

            isolated = (ev_cnt == 0 and bi_cnt == 0 and pr_cnt == 0 and ak_cnt == 0)
            runner.assert_true(
                isolated,
                "13. RLS outsider 0 rows on org_events+blocked_indicators+projects+keys",
                f"ev_cnt: {ev_cnt}, bi_cnt: {bi_cnt}, pr_cnt: {pr_cnt}, ak_cnt: {ak_cnt}",
            )
        except Exception as exc:
            runner.assert_true(False, "13. RLS outsider 0 rows", str(exc))

        # -------------------------------------------------------------------
        # Check 14: key plaintext-once + revoke frees slot
        # -------------------------------------------------------------------
        try:
            # 1. Plaintext-once check
            r_list_keys = await client.get(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/keys"
            )
            keys_list = r_list_keys.json().get("keys", [])
            has_no_plaintext = all("api_key" not in k and "key_hash" not in k for k in keys_list)

            # 2. Duplicate active master key rejected (slot occupied)
            r_dup = await client.post(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/keys",
                json={"name": "Second Master", "role": "master"},
            )
            slot_occupied_409 = r_dup.status_code == 409

            # 3. Revoke active master key
            r_rev = await client.post(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/keys/{master_key_id}/revoke"
            )
            revoked_ok = r_rev.status_code == 200

            # 4. Generate new master key succeeds (slot freed)
            r_new = await client.post(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/keys",
                json={"name": "New Master After Revoke", "role": "master"},
            )
            new_key_ok = r_new.status_code == 201

            runner.assert_true(
                has_no_plaintext and slot_occupied_409 and revoked_ok and new_key_ok,
                "14. key plaintext-once + revoke frees slot",
                f"no_plaintext: {has_no_plaintext}, dup_rejected: {slot_occupied_409}, revoked: {revoked_ok}, new_created: {new_key_ok}",
            )
        except Exception as exc:
            runner.assert_true(False, "14. key plaintext-once + revoke frees slot", str(exc))

        # -------------------------------------------------------------------
        # Check 15: realtime publication contains org_events
        # -------------------------------------------------------------------
        try:
            async with async_session_maker() as db:
                pub_check = await db.scalar(
                    text(
                        "SELECT count(*) FROM pg_publication_tables "
                        "WHERE pubname = 'supabase_realtime' AND tablename = 'org_events'"
                    )
                )
            runner.assert_true(
                pub_check == 1,
                "15. realtime publication contains org_events",
                f"Count in supabase_realtime: {pub_check}",
            )
        except Exception as exc:
            runner.assert_true(False, "15. realtime publication contains org_events", str(exc))

        # -------------------------------------------------------------------
        # Check 16: no USING(true) org policies exist (pg_policies assert)
        # -------------------------------------------------------------------
        try:
            async with async_session_maker() as db:
                rows = (
                    await db.execute(
                        text(
                            "SELECT tablename, policyname, qual "
                            "FROM pg_policies "
                            "WHERE schemaname = 'cyberguard' "
                            "  AND tablename LIKE 'org_%' "
                            "  AND (qual = 'true' OR qual = '(true)')"
                        )
                    )
                ).all()
            zero_true_policies = len(rows) == 0
            runner.assert_true(
                zero_true_policies,
                "16. no USING(true) org policies exist (pg_policies assert)",
                f"Offending policies found: {rows}",
            )
        except Exception as exc:
            runner.assert_true(False, "16. no USING(true) org policies", str(exc))

    # Clean up overrides
    app.dependency_overrides.pop(get_current_user, None)
