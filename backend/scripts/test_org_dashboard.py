"""Suite 51 — ORG-DASHBOARD-P1 Live Counters Automated Test Suite.

Verifies GET /orgs/{org_id}/projects/{project_id}/counters/initial:
- aggregates 10 seeded mixed-severity/type events correctly
  (total_24h, by_severity, by_type, pending_review, blocked_indicators_count)
- verdict UPDATE (pending_review -> blocked_permanently) decrements
  pending_review on re-seed AND emits a best-effort realtime broadcast
  with kind=update + previous_verdict for live dashboards
"""

import uuid

from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.core.security import CurrentUser, get_current_user
from app.db.models import OrgEvent, User
from app.main import app


async def run_org_dashboard_tests(runner) -> None:
    print("\n[Suite 51] ORG-DASHBOARD-P1 — Live Counters seed + realtime bridge")

    from app.core.config import get_settings
    _saved_org_enabled = get_settings().ORG_ENABLED
    get_settings().ORG_ENABLED = True

    try:
        await _run_body(runner)
    finally:
        get_settings().ORG_ENABLED = _saved_org_enabled


async def _run_body(runner) -> None:
    admin_id = str(uuid.uuid4())

    admin_user = CurrentUser(
        id=admin_id,
        email=f"dash-admin-{admin_id[:8]}@example.com",
        full_name="Dash Admin",
        username=f"dash_admin_{admin_id[:8]}",
        account_type="user",
    )

    from app.db.admin import _get_admin_session_maker
    admin_maker = _get_admin_session_maker()

    async with admin_maker() as db_session:
        db_session.add(User(
            id=admin_user.id,
            email=admin_user.email,
            full_name=admin_user.full_name,
            username=admin_user.username,
            account_type="user",
        ))
        await db_session.commit()

    app.dependency_overrides[get_current_user] = lambda: admin_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        org_id = None
        project_id = None
        try:
            r_org = await client.post("/api/v1/orgs", json={"name": "Dashboard Test Org"})
            assert r_org.status_code == 201, r_org.text
            org_id = r_org.json()["id"]

            r_proj = await client.post(
                f"/api/v1/orgs/{org_id}/projects",
                json={"name": "Dashboard Proj", "slug": f"dash-{uuid.uuid4().hex[:6]}"},
            )
            assert r_proj.status_code == 201, r_proj.text
            project_id = r_proj.json()["id"]

            # Seed 10 mixed events (service-role session: bypass RLS)
            # severities: critical=3, high=3, medium=1, low=3
            # types:      network=5, ato=3, log=2
            # verdicts:   8 pending_review, 2 blocked_permanently
            seed_rows = [
                ("network_event", "critical", "pending_review"),
                ("network_event", "critical", "pending_review"),
                ("network_event", "high", "pending_review"),
                ("network_event", "high", "blocked_permanently"),
                ("network_event", "low", "pending_review"),
                ("ato_event", "critical", "pending_review"),
                ("ato_event", "high", "pending_review"),
                ("ato_event", "medium", "blocked_permanently"),
                ("log_event", "low", "pending_review"),
                ("log_event", "low", "pending_review"),
            ]
            async with admin_maker() as db:
                async with db.begin():
                    for etype, sev, verdict in seed_rows:
                        db.add(OrgEvent(
                            id=str(uuid.uuid4()),
                            project_id=project_id,
                            organization_id=org_id,
                            event_type=etype,
                            severity=sev,
                            source="gateway",
                            raw_data={"suite": "51"},
                            analysis_result={"risk_score": 50},
                            verdict=verdict,
                        ))

            # ---- Check 1: seed fetch aggregates --------------------------------
            try:
                r = await client.get(f"/api/v1/orgs/{org_id}/projects/{project_id}/counters/initial")
                assert r.status_code == 200, r.text
                body = r.json()
                assert body["total_24h"] == 10, body
                assert body["by_severity"] == {
                    "critical": 3, "high": 3, "medium": 1, "low": 3,
                }, body["by_severity"]
                assert body["by_type"] == {"log": 2, "ato": 3, "network": 5}, body["by_type"]
                assert body["pending_review"] == 8, body
                assert "blocked_indicators_count" in body, body
                runner.assert_true(
                    True, "1. counters/initial aggregates 10 mixed events correctly"
                )
            except Exception as exc:  # noqa: BLE001
                runner.assert_true(False, "1. counters/initial aggregates 10 mixed events correctly", str(exc))

            # ---- Check 2: verdict update decrements pending + broadcasts -------
            broadcasts: list[dict] = []

            async def _capture_broadcast(event, kind="insert", previous_verdict=None):
                broadcasts.append({
                    "event_id": str(event.id),
                    "kind": kind,
                    "previous_verdict": previous_verdict,
                    "verdict": event.verdict,
                    "severity": event.severity,
                    "event_type": event.event_type,
                    "project_id": str(event.project_id),
                })
                return True

            import app.services.org_event_broadcaster as broadcaster_mod

            saved_fn = broadcaster_mod.broadcast_org_event

            # (fetch a pending event id from the events list endpoint)
            r_list = await client.get(
                f"/api/v1/orgs/{org_id}/projects/{project_id}/events?limit=50"
            )
            assert r_list.status_code == 200, r_list.text
            rows = r_list.json().get("events") or r_list.json().get("items") or []
            pending = next(e for e in rows if e["verdict"] == "pending_review" and e["severity"] == "high")

            broadcaster_mod.broadcast_org_event = _capture_broadcast
            try:
                r_patch = await client.patch(
                    f"/api/v1/orgs/{org_id}/projects/{project_id}/events/{pending['id']}",
                    json={"action": "blocked_permanently", "reason": "suite 51"},
                )
                assert r_patch.status_code == 200, r_patch.text

                r2 = await client.get(f"/api/v1/orgs/{org_id}/projects/{project_id}/counters/initial")
                body2 = r2.json()
                assert body2["pending_review"] == 7, body2
                assert body2["total_24h"] == 10, body2
                assert body2["by_severity"]["high"] == 3, body2["by_severity"]

                assert len(broadcasts) == 1, broadcasts
                b = broadcasts[0]
                assert b["kind"] == "update", b
                assert b["previous_verdict"] == "pending_review", b
                assert b["verdict"] == "blocked_permanently", b
                assert b["event_id"] == pending["id"], b
                assert b["project_id"] == project_id, b

                runner.assert_true(
                    True, "2. verdict UPDATE decrements pending_review + emits realtime broadcast"
                )
            except Exception as exc:  # noqa: BLE001
                runner.assert_true(False, "2. verdict UPDATE decrements pending_review + emits realtime broadcast", str(exc))
            finally:
                broadcaster_mod.broadcast_org_event = saved_fn
        finally:
            app.dependency_overrides.pop(get_current_user, None)
            # cleanup seeded rows (org cascade removes events/projects/members)
            if org_id:
                try:
                    async with admin_maker() as db:
                        async with db.begin():
                            await db.execute(text(
                                "DELETE FROM cyberguard.org_organizations WHERE id = :oid"
                            ), {"oid": org_id})
                except Exception:  # noqa: BLE001
                    pass
