"""SCENARIO-3 tests: org-scoped account-takeover detection.

Covers:
- AccountTakeoverDetector unit tests (rule engine, anomaly scoring, threat
  intel, fusion/level mapping, dedup across events).
- API security: the org scope is resolved SERVER-SIDE from the credential —
  the request body never carries an organization_id; personal JWTs fail
  closed; the JWT org path stamps organization_id/project_id onto the
  persisted Alert + Event; one org's alerts are invisible to another's.
"""

import uuid

import pytest
from sqlalchemy import select

from app.services.ato_detector import (
    AccountTakeoverDetector,
    MOCK_MALICIOUS_IPS,
    W_COUNTRY_MISMATCH,
    W_FAILED_BURST,
    W_MALICIOUS_IP,
    W_MASS_FILE_ACCESS,
    W_NEW_DEVICE,
    W_ODD_HOUR_LOGIN,
    W_OFF_BASELINE_HOURS,
    W_PASSWORD_CHANGED,
)

BASELINE = {
    "user": "sarah.chen@acme.com",
    "typical_login_start": "09:00",
    "typical_login_end": "10:00",
    "home_country": "US",
    "known_ips": ["98.42.117.6", "10.0.4.15"],
    "known_devices": ["MAC-BOOK-A7F3", "IPHONE-12-SARAH"],
}

DEMO_TIMELINE = [
    {
        "timestamp": "2026-10-06T03:17:00",
        "event_type": "login_success",
        "source_ip": "203.0.113.77",
        "country": "RU",
        "device_id": "WIN-XK22B9",
    },
    {
        "timestamp": "2026-10-06T03:18:00",
        "event_type": "failed_login",
        "failed_attempts": 8,
        "source_ip": "203.0.113.77",
        "country": "RU",
        "device_id": "WIN-XK22B9",
    },
    {
        "timestamp": "2026-10-06T03:20:00",
        "event_type": "login_success",
        "source_ip": "203.0.113.77",
        "country": "RU",
        "device_id": "WIN-XK22B9",
    },
    {"timestamp": "2026-10-06T03:22:00", "event_type": "password_change"},
    {"timestamp": "2026-10-06T03:25:00", "event_type": "file_access", "files_accessed": 150},
]


def _types(result):
    return {i["type"] for i in result["indicators"]}


class TestRuleEngine:
    def test_failed_attempts_threshold(self):
        under = AccountTakeoverDetector().analyze(BASELINE, [
            {"timestamp": "2026-10-06T09:15:00", "event_type": "failed_login", "failed_attempts": 4}
        ])
        assert "failed_login_burst" not in _types(under)

        at = AccountTakeoverDetector().analyze(BASELINE, [
            {"timestamp": "2026-10-06T09:15:00", "event_type": "failed_login", "failed_attempts": 5}
        ])
        assert "failed_login_burst" in _types(at)
        assert at["risk_score"] == W_FAILED_BURST

    def test_odd_hour_window_bounds(self):
        at_1am = AccountTakeoverDetector().analyze(BASELINE, [
            {"timestamp": "2026-10-06T01:00:00", "event_type": "login_success"}
        ])
        assert "odd_hour_login" in _types(at_1am)

        # 05:00 sharp is OUTSIDE the 01:00-05:00 window
        at_5am = AccountTakeoverDetector().analyze(BASELINE, [
            {"timestamp": "2026-10-06T05:00:00", "event_type": "login_success"}
        ])
        assert "odd_hour_login" not in _types(at_5am)

    def test_password_changed_flag(self):
        result = AccountTakeoverDetector().analyze(BASELINE, [
            {"timestamp": "2026-10-06T09:15:00", "event_type": "login_success"},
            {"timestamp": "2026-10-06T09:20:00", "event_type": "password_change"},
        ])
        assert "password_changed" in _types(result)
        assert result["risk_score"] == W_PASSWORD_CHANGED

    def test_password_changed_boolean_flag_on_login(self):
        result = AccountTakeoverDetector().analyze(BASELINE, [
            {
                "timestamp": "2026-10-06T09:15:00",
                "event_type": "login_success",
                "password_changed": True,
            }
        ])
        assert "password_changed" in _types(result)

    def test_files_accessed_threshold(self):
        at_limit = AccountTakeoverDetector().analyze(BASELINE, [
            {"timestamp": "2026-10-06T09:15:00", "event_type": "file_access", "files_accessed": 50}
        ])
        assert "mass_data_access" not in _types(at_limit)

        over = AccountTakeoverDetector().analyze(BASELINE, [
            {"timestamp": "2026-10-06T09:15:00", "event_type": "file_access", "files_accessed": 51}
        ])
        assert "mass_data_access" in _types(over)
        assert over["risk_score"] == W_MASS_FILE_ACCESS


class TestAnomalyScoring:
    def test_country_mismatch(self):
        result = AccountTakeoverDetector().analyze(BASELINE, [
            {
                "timestamp": "2026-10-06T09:15:00",
                "event_type": "login_success",
                "country": "RU",
                "device_id": "MAC-BOOK-A7F3",
            }
        ])
        assert "country_mismatch" in _types(result)
        assert result["risk_score"] == W_COUNTRY_MISMATCH

    def test_new_device(self):
        result = AccountTakeoverDetector().analyze(BASELINE, [
            {
                "timestamp": "2026-10-06T09:15:00",
                "event_type": "login_success",
                "country": "US",
                "device_id": "WIN-XK22B9",
            }
        ])
        assert "unrecognized_device" in _types(result)
        assert result["risk_score"] == W_NEW_DEVICE

    def test_off_baseline_hours(self):
        result = AccountTakeoverDetector().analyze(BASELINE, [
            {
                "timestamp": "2026-10-06T14:00:00",
                "event_type": "login_success",
                "country": "US",
                "device_id": "MAC-BOOK-A7F3",
            }
        ])
        assert "off_baseline_hours" in _types(result)
        assert result["risk_score"] == W_OFF_BASELINE_HOURS

    def test_baseline_activity_scores_zero(self):
        result = AccountTakeoverDetector().analyze(BASELINE, [
            {
                "timestamp": "2026-10-06T09:15:00",
                "event_type": "login_success",
                "country": "US",
                "device_id": "MAC-BOOK-A7F3",
                "source_ip": "98.42.117.6",
            },
            {"timestamp": "2026-10-06T09:40:00", "event_type": "file_access", "files_accessed": 12},
        ])
        assert result["risk_score"] == 0
        assert result["risk_level"] == "low"
        assert result["verdict"] == "no_takeover_detected"


class TestThreatIntel:
    def test_malicious_ip_hit(self):
        malicious_ip = sorted(MOCK_MALICIOUS_IPS)[0]
        result = AccountTakeoverDetector().analyze(BASELINE, [
            {
                "timestamp": "2026-10-06T09:15:00",
                "event_type": "login_success",
                "country": "US",
                "device_id": "MAC-BOOK-A7F3",
                "source_ip": malicious_ip,
            }
        ])
        assert "malicious_ip" in _types(result)
        assert result["risk_score"] == W_MALICIOUS_IP
        assert result["threat_intel"]["hits"] == [malicious_ip]

    def test_unknown_ip_no_hit(self):
        result = AccountTakeoverDetector().analyze(BASELINE, [
            {
                "timestamp": "2026-10-06T09:15:00",
                "event_type": "login_success",
                "source_ip": "203.0.113.77",
            }
        ])
        assert "malicious_ip" not in _types(result)
        assert result["threat_intel"]["hits"] == []


class TestFusion:
    def test_demo_timeline_scores_92_high(self):
        result = AccountTakeoverDetector().analyze(BASELINE, DEMO_TIMELINE)
        assert result["risk_score"] == 92
        assert result["risk_level"] == "high"
        assert result["verdict"] == "account_takeover_detected"
        descriptions = [i["description"] for i in result["indicators"]]
        assert "Login at unusual time (03:17 AM)" in descriptions
        assert "Multiple failed login attempts (8)" in descriptions
        assert "Password changed shortly after login" in descriptions
        assert "Unusual volume of data access (150 files)" in descriptions
        assert any("Country mismatch" in d for d in descriptions)
        assert result["recommended_actions"] == [
            "Temporarily restrict the session/account.",
            "Force credential reset & ask for additional verification.",
            "Notify the security administrator.",
        ]

    def test_repeat_anomalies_count_once(self):
        # Two logins from the same rogue country: the country anomaly is ONE
        # signal, not two — the fusion must not double-count.
        events = [
            {
                "timestamp": "2026-10-06T03:17:00",
                "event_type": "login_success",
                "country": "RU",
                "device_id": "MAC-BOOK-A7F3",
            },
            {
                "timestamp": "2026-10-06T03:20:00",
                "event_type": "login_success",
                "country": "RU",
                "device_id": "MAC-BOOK-A7F3",
            },
        ]
        result = AccountTakeoverDetector().analyze(BASELINE, events)
        # odd_hour (12) + country mismatch (12, ONCE) + off-baseline hours (7)
        assert result["risk_score"] == W_ODD_HOUR_LOGIN + W_COUNTRY_MISMATCH + W_OFF_BASELINE_HOURS
        assert len([i for i in result["indicators"] if i["type"] == "country_mismatch"]) == 1

    def test_critical_level_mapping(self):
        events = [dict(e) for e in DEMO_TIMELINE]
        events[0]["source_ip"] = sorted(MOCK_MALICIOUS_IPS)[0]  # +15 threat intel -> 107 -> cap 100
        result = AccountTakeoverDetector().analyze(BASELINE, events)
        assert result["risk_score"] == 100
        assert result["risk_level"] == "critical"

    def test_medium_level_actions(self):
        result = AccountTakeoverDetector().analyze(BASELINE, [
            {
                "timestamp": "2026-10-06T14:00:00",
                "event_type": "login_success",
                "country": "RU",
                "device_id": "WIN-XK22B9",
            },
            {"timestamp": "2026-10-06T14:05:00", "event_type": "password_change"},
        ])
        assert result["risk_level"] == "medium"
        assert result["recommended_actions"] != AccountTakeoverDetector.recommended_actions("high")

    def test_timeline_annotation(self):
        result = AccountTakeoverDetector().analyze(BASELINE, DEMO_TIMELINE)
        flagged_scores = [(e["flagged"], e["event_score"]) for e in result["timeline"]]
        # 03:17 login carries odd-hour + country + device + off-baseline
        assert flagged_scores[0][1] == W_ODD_HOUR_LOGIN + W_COUNTRY_MISMATCH + W_NEW_DEVICE + W_OFF_BASELINE_HOURS
        # 03:18 failed burst
        assert "failed_login_burst" in flagged_scores[1][0]
        # 03:22 password change
        assert "password_changed" in flagged_scores[3][0]


# ---------------------------------------------------------------------------
# API security: server-side tenant resolution + multi-tenant isolation
# ---------------------------------------------------------------------------

FUSION_PAYLOAD = {
    "source": "pytest",
    "account_id": "sarah.chen@acme.com",
    "baseline_profile": BASELINE,
    "suspicious_events": DEMO_TIMELINE,
}


async def _seed_org(db, owner_id: str, name: str, slug: str):
    from app.db.models import OrgOrganization, OrgProject

    org = OrgOrganization(id=str(uuid.uuid4()), name=name, owner_id=owner_id)
    db.add(org)
    await db.flush()
    project = OrgProject(
        id=str(uuid.uuid4()), organization_id=org.id, name=f"{name} Project", slug=slug
    )
    db.add(project)
    await db.commit()
    return org, project


@pytest.mark.asyncio
async def test_ato_fusion_requires_organization(client):
    """Personal JWT (no org context) must fail closed on the org ATO flow."""
    resp = await client.post("/api/v1/analysis/account-takeover", json=FUSION_PAYLOAD)
    assert resp.status_code == 403
    body = resp.json()
    assert "organization" in str(body.get("message") or body.get("detail") or body).lower()


@pytest.mark.asyncio
async def test_ato_org_flow_stamps_tenant(client):
    """Org JWT path: alert + event stamped with the server-resolved org and
    project; a client-supplied organization_id in the body is ignored."""
    from app.db.models import Alert, Event, User
    from app.db.session import async_session_maker

    async with async_session_maker() as db:
        user = (
            await db.execute(
                User.__table__.select().where(User.email == "eval@cyberguard.local")
            )
        ).first()
        if user is None:
            user = (
                await db.execute(User.__table__.select().where(User.id == "user-eval"))
            ).first()
        owner_id = user._mapping["id"] if user is not None else "user-eval"
        org, project = await _seed_org(db, owner_id, "ATO Org A", f"ato-a-{uuid.uuid4().hex[:8]}")

        # Persist the active project so the JWT path stamps project_id.
        await db.execute(
            User.__table__.update()
            .where(User.id == owner_id)
            .values(active_project_id=project.id)
        )
        await db.commit()

    try:
        resp = await client.post(
            "/api/v1/analysis/account-takeover",
            json={**FUSION_PAYLOAD, "organization_id": str(org.id)},
            headers={"X-Organization-Id": str(org.id)},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()

        # Tenant resolved server-side from the membership header.
        assert data["organization"]["id"] == str(org.id)
        assert data["project"]["id"] == str(project.id)
        assert data["risk_score"] == 92
        assert data["risk_level"] == "high"
        assert data["verdict"] == "account_takeover_detected"
        assert data["alert_id"] and data["event_id"]

        async with async_session_maker() as db:
            alert = (
                await db.execute(Alert.__table__.select().where(Alert.id == data["alert_id"]))
            ).first()
            event = (
                await db.execute(Event.__table__.select().where(Event.id == data["event_id"]))
            ).first()
            assert alert is not None and event is not None
            assert alert._mapping["organization_id"] == str(org.id)
            assert alert._mapping["project_id"] == str(project.id)
            assert event._mapping["organization_id"] == str(org.id)
            assert event._mapping["project_id"] == str(project.id)
    finally:
        async with async_session_maker() as db:
            await db.execute(
                User.__table__.update()
                .where(User.id == owner_id)
                .values(active_project_id=None)
            )
            await db.commit()


@pytest.mark.asyncio
async def test_ato_org_isolation(client):
    """Org A's ATO analysis must be invisible to (and untriggersble from)
    Org B: a non-member cannot resolve Org B as tenant, and org-scoped
    queries never cross the boundary."""
    from app.core.security import TenantContext, tenant_criteria
    from app.db.models import Alert, User
    from app.db.session import async_session_maker

    async with async_session_maker() as db:
        user = (
            await db.execute(User.__table__.select().where(User.id == "user-eval"))
        ).first()
        if user is None:
            user = (
                await db.execute(
                    User.__table__.select().where(User.email == "eval@cyberguard.local")
                )
            ).first()
        owner_id = user._mapping["id"] if user is not None else "user-eval"
        org_a, project_a = await _seed_org(db, owner_id, "ATO Isolation A", f"iso-a-{uuid.uuid4().hex[:8]}")
        # Org B is owned by a different (non-seeded) user: the eval user is
        # neither owner nor member.
        org_b, _ = await _seed_org(db, f"other-{uuid.uuid4().hex[:12]}", "ATO Isolation B", f"iso-b-{uuid.uuid4().hex[:8]}")
        await db.commit()

    # 1. Run the analysis inside Org A.
    resp = await client.post(
        "/api/v1/analysis/account-takeover",
        json=FUSION_PAYLOAD,
        headers={"X-Organization-Id": str(org_a.id)},
    )
    assert resp.status_code == 200, resp.text
    alert_id = resp.json()["alert_id"]

    # 2. A non-member cannot trigger/analyze against Org B at all.
    denied = await client.post(
        "/api/v1/analysis/account-takeover",
        json=FUSION_PAYLOAD,
        headers={"X-Organization-Id": str(org_b.id)},
    )
    assert denied.status_code == 403

    # 3. Org B's tenant context cannot see Org A's alert.
    tenant_b = TenantContext(
        user_id=owner_id,
        owner_user_id="other-user",
        organization_id=str(org_b.id),
        organization_name="ATO Isolation B",
        role="admin",
        is_single_user=False,
        project_id=None,
    )
    async with async_session_maker() as db:
        visible = (
            await db.execute(
                select(Alert).where(tenant_criteria(Alert, tenant_b), Alert.id == alert_id)
            )
        ).scalar_one_or_none()
        assert visible is None, "Org B must not see Org A's ATO alert"
        # ...while Org A's own context does see it.
        tenant_a = TenantContext(
            user_id=owner_id,
            owner_user_id=owner_id,
            organization_id=str(org_a.id),
            organization_name="ATO Isolation A",
            role="admin",
            is_single_user=False,
            project_id=str(project_a.id),
        )
        own = (
            await db.execute(
                select(Alert).where(tenant_criteria(Alert, tenant_a), Alert.id == alert_id)
            )
        ).scalar_one_or_none()
        assert own is not None


@pytest.mark.asyncio
async def test_ato_viewer_role_denied(client):
    """Viewer-role members cannot run the ATO analysis."""
    from app.db.models import OrgMember, OrgOrganization, User
    from app.db.session import async_session_maker

    async with async_session_maker() as db:
        user = (
            await db.execute(User.__table__.select().where(User.id == "user-eval"))
        ).first()
        if user is None:
            user = (
                await db.execute(
                    User.__table__.select().where(User.email == "eval@cyberguard.local")
                )
            ).first()
        owner_id = user._mapping["id"] if user is not None else "user-eval"
        org = OrgOrganization(id=str(uuid.uuid4()), name="ATO Viewer Org", owner_id=owner_id)
        db.add(org)
        await db.flush()
        db.add(
            OrgMember(
                id=str(uuid.uuid4()),
                organization_id=org.id,
                user_id=owner_id,
                role="viewer",
            )
        )
        # Demote the user's membership resolution: get_tenant_context returns
        # the member row's role when a member row exists.
        await db.commit()

        resp = await client.post(
            "/api/v1/analysis/account-takeover",
            json=FUSION_PAYLOAD,
            headers={"X-Organization-Id": str(org.id)},
        )
        # Cleanup before assertions (org rows are harmless leftovers, but the
        # member row must go so other tests resolving the same user are clean).
        await db.execute(
            OrgMember.__table__.delete().where(OrgMember.organization_id == org.id)
        )
        await db.execute(
            OrgOrganization.__table__.delete().where(OrgOrganization.id == org.id)
        )
        await db.commit()

    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# ATO-UI-OVERHAUL: 3-tier enforcement + list/detail endpoints
# ---------------------------------------------------------------------------

from app.services.ato_detector import TIER_MEDIUM_MAX, TIER_SAFE_MAX, classify_enforcement


class TestThreeTierEnforcement:
    def test_safe_band(self):
        assert classify_enforcement(0)["action_taken"] == "ALLOWED"
        assert classify_enforcement(TIER_SAFE_MAX - 1)["action_taken"] == "ALLOWED"
        safe = classify_enforcement(10)
        assert safe["tier"] == "safe"
        assert safe["notified"] is False
        assert safe["account_restricted"] is False

    def test_medium_band(self):
        assert classify_enforcement(TIER_SAFE_MAX)["action_taken"] == "USER_NOTIFIED"
        assert classify_enforcement(TIER_MEDIUM_MAX - 1)["action_taken"] == "USER_NOTIFIED"
        medium = classify_enforcement(50)
        assert medium["tier"] == "medium"
        assert medium["notified"] is True
        assert medium["account_restricted"] is False

    def test_critical_band(self):
        assert classify_enforcement(TIER_MEDIUM_MAX)["action_taken"] == "ACCOUNT_RESTRICTED"
        assert classify_enforcement(92)["action_taken"] == "ACCOUNT_RESTRICTED"
        assert classify_enforcement(100)["action_taken"] == "ACCOUNT_RESTRICTED"
        critical = classify_enforcement(92)
        assert critical["tier"] == "critical"
        assert critical["notified"] is True
        assert critical["account_restricted"] is True
        assert critical["actions"] == ["ACCOUNT_RESTRICTED", "USER_NOTIFIED"]

    def test_score_clamped(self):
        assert classify_enforcement(-5)["tier"] == "safe"
        assert classify_enforcement(500)["tier"] == "critical"

    def test_demo_timeline_is_critical(self):
        assert classify_enforcement(92)["account_restricted"] is True


MEDIUM_TIMELINE = [
    {
        "timestamp": "2026-10-06T03:30:00",
        "event_type": "login_success",
        "source_ip": "198.51.100.9",
        "country": "CA",
        "device_id": "WIN-NEW-BOX",
    }
]
SAFE_TIMELINE = [
    {
        "timestamp": "2026-10-06T09:20:00",
        "event_type": "login_success",
        "source_ip": "98.42.117.6",
        "country": "US",
        "device_id": "MAC-BOOK-A7F3",
    }
]


async def _post_ato(client, org_id: str, payload: dict):
    return await client.post(
        "/api/v1/analysis/account-takeover",
        json={**FUSION_PAYLOAD, **payload},
        headers={"X-Organization-Id": str(org_id)},
    )


@pytest.mark.asyncio
async def test_ato_events_list_and_tier_actions(client):
    """The org list endpoint returns the org's own ATO events with the
    3-tier action_taken; other orgs' events never appear."""
    from app.db.models import User
    from app.db.session import async_session_maker

    async with async_session_maker() as db:
        user = (
            await db.execute(User.__table__.select().where(User.id == "user-eval"))
        ).first()
        if user is None:
            user = (
                await db.execute(
                    User.__table__.select().where(User.email == "eval@cyberguard.local")
                )
            ).first()
        owner_id = user._mapping["id"] if user is not None else "user-eval"
        org, project = await _seed_org(db, owner_id, "ATO List Org", f"list-{uuid.uuid4().hex[:8]}")
        other, _ = await _seed_org(db, f"other-{uuid.uuid4().hex[:12]}", "ATO List Other", f"listo-{uuid.uuid4().hex[:8]}")
        await db.commit()

    # Seed one event per tier inside the org.
    r_crit = await _post_ato(client, org.id, {"account_id": "critical@acme.com"})
    r_med = await _post_ato(
        client,
        org.id,
        {"account_id": "medium@acme.com", "suspicious_events": MEDIUM_TIMELINE},
    )
    r_safe = await _post_ato(
        client,
        org.id,
        {"account_id": "safe@acme.com", "suspicious_events": SAFE_TIMELINE},
    )
    assert r_crit.status_code == 200 and r_med.status_code == 200 and r_safe.status_code == 200
    assert r_crit.json()["action_taken"] == "ACCOUNT_RESTRICTED"
    assert r_med.json()["action_taken"] == "USER_NOTIFIED"
    assert r_safe.json()["action_taken"] == "ALLOWED"

    # List from the owning org: all three visible, desc order.
    listed = await client.get(
        "/api/v1/analysis/account-takeover/events",
        headers={"X-Organization-Id": str(org.id)},
    )
    assert listed.status_code == 200, listed.text
    rows = listed.json()["events"]
    by_email = {r["user_email"]: r for r in rows}
    assert {"critical@acme.com", "medium@acme.com", "safe@acme.com"} <= set(by_email)
    assert by_email["critical@acme.com"]["action_taken"] == "ACCOUNT_RESTRICTED"
    assert by_email["critical@acme.com"]["risk_score"] == 92
    assert by_email["medium@acme.com"]["action_taken"] == "USER_NOTIFIED"
    assert by_email["safe@acme.com"]["action_taken"] == "ALLOWED"
    for row in rows:
        assert set(row) >= {"id", "timestamp", "user_email", "risk_score", "action_taken"}

    # Isolation: listing from another org (non-member) is denied outright,
    # and the other org's context cannot see these events.
    denied = await client.get(
        "/api/v1/analysis/account-takeover/events",
        headers={"X-Organization-Id": str(other.id)},
    )
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_ato_event_detail_readonly(client):
    """Detail endpoint returns baseline + annotated timeline + enforcement;
    another org's event id 404s instead of leaking."""
    from app.db.models import User
    from app.db.session import async_session_maker

    async with async_session_maker() as db:
        user = (
            await db.execute(User.__table__.select().where(User.id == "user-eval"))
        ).first()
        if user is None:
            user = (
                await db.execute(
                    User.__table__.select().where(User.email == "eval@cyberguard.local")
                )
            ).first()
        owner_id = user._mapping["id"] if user is not None else "user-eval"
        org, _ = await _seed_org(db, owner_id, "ATO Detail Org", f"detail-{uuid.uuid4().hex[:8]}")
        other, _ = await _seed_org(db, f"other-{uuid.uuid4().hex[:12]}", "ATO Detail Other", f"detailo-{uuid.uuid4().hex[:8]}")
        # Eval user IS a member of the other org: the tenant resolves there,
        # so the cross-tenant read must 404 (scoped empty), never leak.
        from app.db.models import OrgMember

        db.add(
            OrgMember(
                id=str(uuid.uuid4()),
                organization_id=other.id,
                user_id=owner_id,
                role="admin",
            )
        )
        await db.commit()

    created = await _post_ato(client, org.id, {"account_id": "detail@acme.com"})
    event_id = created.json()["event_id"]

    detail = await client.get(
        f"/api/v1/analysis/account-takeover/events/{event_id}",
        headers={"X-Organization-Id": str(org.id)},
    )
    assert detail.status_code == 200, detail.text
    data = detail.json()
    assert data["event_id"] == event_id
    assert data["action_taken"] == "ACCOUNT_RESTRICTED"
    assert data["enforcement"]["notified"] is True
    assert data["baseline_profile"]["home_country"] == "US"
    assert len(data["suspicious_events"]) == len(DEMO_TIMELINE)
    assert all("flagged" in e for e in data["suspicious_events"])
    assert data["explanation"]
    assert data["alert_id"]
    assert data["indicators"]

    # Cross-tenant read: 404, never a leak.
    cross = await client.get(
        f"/api/v1/analysis/account-takeover/events/{event_id}",
        headers={"X-Organization-Id": str(other.id)},
    )
    assert cross.status_code == 404

    # Personal JWT (no org) is denied on list and detail.
    assert (
        await client.get("/api/v1/analysis/account-takeover/events")
    ).status_code == 403
    assert (
        await client.get(f"/api/v1/analysis/account-takeover/events/{event_id}")
    ).status_code == 403
