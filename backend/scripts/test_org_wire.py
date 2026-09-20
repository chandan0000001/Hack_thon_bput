"""ORG-WIRE — org-stamped pipeline events, org-branch RLS, fan-out, gateway
log linkage (Suite 39, 12 checks).

 1. record_event stamps SecurityEvent with the owner's ACTIVE org id.
 2. create_alert stamps Alert with the active org when the tenant carries none.
 3. Personal-mode stamp resolves to the PERSONAL org id.
 4. Non-owner admin member SELECTs org-stamped security_events (> 0) — the
    regression ORG-FIX-1 exposed, now closed by the org-branch policies.
 5. Outsider sees 0 rows on the 5 widened tables (org-stamped or not).
 6. Owner sees own rows via the OWNER branch even when organization_id IS NULL.
 7. Non-personal critical verdict -> fan-out fires (mock transport) with the
    org id + min_role routing; org_notification_logs row persists.
 8. Personal verdict -> fan-out SUPPRESSED (no double email; Phase-7 rule).
 9. Gateway ingest_log dual-write: OrgLogEvent (analyzed) in /logs/stream AND
    the generic Event row still created.
10. Dashboard summary for a NON-owner admin counts org-stamped events (> 0).
11. Personal-stamped rows invisible to other org members (no cross-leak).
12. e2e pipeline: fetch->analysis for an org-active user -> SecurityEvent
    stamped with the org id + org_notification_logs row for the verdict.

Run via run_all_tests.py (Suite 39) or standalone:
    uv run python scripts/test_org_wire.py
"""

import asyncio
import base64
import sys
import uuid
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from app.core.security import CurrentUser, TenantContext, get_current_user
from app.db.admin import _get_admin_session_maker
from app.db.session import async_session_maker, current_user_id, engine
from app.main import app
from app.services.org_context import invalidate as invalidate_org_cache
from app.services.org_context import resolve_org_id


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


async def run_org_wire_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("ORG-WIRE: org-stamped pipeline, org-branch RLS, fan-out, gateway")
    print("-" * 60)

    if "postgresql" not in str(engine.dialect.name):
        check(True, "ORG-WIRE suite skipped without PostgreSQL")
        print("         Skipped: no PostgreSQL configured")
        return

    stamp = uuid.uuid4().hex[:8]
    admin = CurrentUser(id=f"s39-admin-{stamp}", email=f"s39-admin-{stamp}@cyberguard.test", full_name="S39 Admin")
    sec_admin = CurrentUser(id=f"s39-secadm-{stamp}", email=f"s39-secadm-{stamp}@cyberguard.test", full_name="S39 SecAdmin")
    outsider = CurrentUser(id=f"s39-out-{stamp}", email=f"s39-out-{stamp}@cyberguard.test", full_name="S39 Outsider")
    personal = CurrentUser(id=f"s39-pers-{stamp}", email=f"s39-pers-{stamp}@cyberguard.test", full_name="S39 Personal")

    org_id = ""
    personal_org_id = ""
    app.dependency_overrides[get_current_user] = _mock_get_current_user
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # ---------- provisioning ----------
            async with async_session_maker() as db:
                for u in (admin, sec_admin, outsider, personal):
                    await _ensure_user(db, u.id, u.email or "")

            _Identity.user = admin
            invalidate_org_cache()
            res = await client.post("/api/v1/orgs", json={"name": f"Org Wire Org {stamp}"})
            org_id = res.json()["id"]
            await client.post(f"/api/v1/orgs/{org_id}/members",
                              json={"email": sec_admin.email, "role": "admin"})
            # Personal workspace for the personal user.
            async with _get_admin_session_maker()() as adb:
                personal_org_id = str(uuid.uuid4())
                await adb.execute(text(
                    "insert into cyberguard.organizations (id, name, slug, is_personal, owner_id, status, created_at) "
                    "values (:id, :n, :s, true, :u, 'active', now())"),
                    {"id": personal_org_id, "n": f"Personal {stamp}", "s": f"s39p-{stamp}", "u": personal.id})
                await adb.commit()
            # Activate the admin's org (also the D2 resolution source).
            _Identity.user = admin
            res = await client.post("/api/v1/auth/switch-org", json={"organization_id": org_id})
            invalidate_org_cache()

            # ----------------------------------------------------------
            # 1. record_event stamps SecurityEvent with the ACTIVE org.
            # ----------------------------------------------------------
            current_user_id.set(admin.id)
            async with async_session_maker() as db:
                from app.services.security_history_service import record_event

                event = await record_event(
                    db, owner_user_id=admin.id, event_type="connector_test",
                    actor_type="system", provider="test", severity="high", score=70,
                    operation_status="success",
                )
                await db.commit()
                await db.refresh(event)
            check(event.organization_id == org_id,
                  "record_event stamps SecurityEvent with the owner's ACTIVE org id",
                  f"got={event.organization_id} expected={org_id}")

            # ----------------------------------------------------------
            # 2. create_alert stamps Alert (tenant has no org).
            # ----------------------------------------------------------
            async with async_session_maker() as db:
                from app.services.alert_service import create_alert

                alert = await create_alert(
                    db,
                    tenant=TenantContext(user_id=admin.id, owner_user_id=admin.id,
                                         role="admin", is_single_user=False),
                    event_id=None, module="phishing", raw_data={"subject": "S39 alert"},
                    indicators=[], score=60, severity="high",
                    llm_output={"explanation": "s39"}, created_by="suite39",
                )
                await db.commit()
                alert_id = alert.id
            check(alert.organization_id == org_id,
                  "create_alert stamps Alert with the resolved org (tenant org was None)",
                  f"got={alert.organization_id} expected={org_id}")

            # ActionExecution org-stamped row for the org-branch spot check (4/10).
            async with _get_admin_session_maker()() as adb:
                await adb.execute(text(
                    "insert into cyberguard.action_executions (id, organization_id, owner_user_id, alert_id, "
                    "action_type, target, status, execution_mode, triggered_by, requires_approval, "
                    "risk_score, severity, threat_type, module, created_at, updated_at) "
                    "values (:id, :org, :owner, :alert, 'quarantine', '{}'::jsonb, 'success', 'server', "
                    "'system', false, 60, 'high', 'phishing', 'phishing', now(), now())"),
                    {"id": str(uuid.uuid4()), "org": org_id, "owner": admin.id, "alert": alert_id})
                await adb.commit()

            # ----------------------------------------------------------
            # 3. Personal-mode stamp = PERSONAL org id.
            # ----------------------------------------------------------
            current_user_id.set(personal.id)
            invalidate_org_cache()
            async with async_session_maker() as db:
                pevent = await record_event(
                    db, owner_user_id=personal.id, event_type="connector_test",
                    actor_type="system", provider="test", severity="low", score=5,
                    operation_status="success",
                )
                await db.commit()
                await db.refresh(pevent)
            check(pevent.organization_id == personal_org_id,
                  "Personal-mode stamp resolves to the PERSONAL org id",
                  f"got={pevent.organization_id} expected={personal_org_id}")

            # ----------------------------------------------------------
            # 4. Non-owner admin member sees org-stamped security_events.
            # ----------------------------------------------------------
            seen = await _count_as(sec_admin.id,
                                   "select count(*) from cyberguard.security_events where organization_id = :o",
                                   {"o": org_id})
            check(seen > 0,
                  "Non-owner admin member SELECT sees org-stamped security_events (> 0)", f"seen={seen}")

            # ----------------------------------------------------------
            # 5. Outsider sees 0 rows on all 5 widened tables.
            # ----------------------------------------------------------
            widened = ("events", "alerts", "action_executions", "security_events", "audit_logs")
            outsider_seen = {
                t: await _count_as(outsider.id,
                                   f"select count(*) from cyberguard.{t} where organization_id = :o", {"o": org_id})
                for t in widened
            }
            check(all(v == 0 for v in outsider_seen.values()),
                  "Outsider sees 0 rows on ALL 5 widened tables", str(outsider_seen))

            # ----------------------------------------------------------
            # 6. Owner branch: un-stamped own rows still visible.
            # ----------------------------------------------------------
            async with engine.connect() as conn:
                await conn.execute(text("select set_config('app.user_id', :uid, false)"), {"uid": admin.id})
                await conn.execute(text(
                    "insert into cyberguard.security_events (id, owner_user_id, event_type, actor_type, operation_status, created_at) "
                    "values (:id, :uid, 'connector_test', 'system', 'success', now())"), {"id": str(uuid.uuid4()), "uid": admin.id})
                await conn.commit()
            own = await _count_as(admin.id,
                                  "select count(*) from cyberguard.security_events "
                                  "where owner_user_id = :u and organization_id is null", {"u": admin.id})
            check(own > 0,
                  "Owner sees own rows via the OWNER branch even when organization_id IS NULL", f"own={own}")

            # ----------------------------------------------------------
            # 7 + 8. Fan-out: non-personal fires, personal suppressed.
            # ----------------------------------------------------------
            from app.services import notification_service
            from app.services.org_notification_service import fan_out_email_verdict

            async def _mock_deliver(recipient, subject, body):
                return "db_log", None

            # Register a recipient so min_role routing has an audience.
            _Identity.user = admin
            res = await client.post(f"/api/v1/orgs/{org_id}/notifications/emails",
                                    json={"email": f"s39-soc-{stamp}@cyberguard.test", "role": "analyst"})

            async with _get_admin_session_maker()() as adb:
                before = (await adb.execute(text(
                    "select count(*) from cyberguard.org_notification_logs where organization_id = :o"),
                    {"o": org_id})).scalar()

            current_user_id.set(admin.id)
            invalidate_org_cache()
            async with async_session_maker() as db:
                with patch.object(notification_service, "_deliver", _mock_deliver):
                    fired = await fan_out_email_verdict(
                        db, owner_user_id=admin.id, email_id=f"s39-email-{stamp}",
                        verdict="malicious", severity="critical", classification="phishing",
                    )
                await db.commit()
            async with _get_admin_session_maker()() as adb:
                after = (await adb.execute(text(
                    "select count(*) from cyberguard.org_notification_logs where organization_id = :o"),
                    {"o": org_id})).scalar()
                meta = await adb.execute(text(
                    "select event_metadata from cyberguard.org_notification_logs "
                    "where organization_id = :o order by created_at desc limit 1"), {"o": org_id})
                metadata = (meta.scalar() or {}) if after > before else {}
            check(fired and after > before and metadata.get("email_id") == f"s39-email-{stamp}",
                  "Non-personal critical verdict -> fan-out fires (org id, metadata, min_role audience)",
                  f"fired={fired} logs {before}->{after} meta={metadata}")

            async with _get_admin_session_maker()() as adb:
                p_before = (await adb.execute(text(
                    "select count(*) from cyberguard.org_notification_logs where organization_id = :o"),
                    {"o": personal_org_id})).scalar()
            current_user_id.set(personal.id)
            invalidate_org_cache()
            async with async_session_maker() as db:
                with patch.object(notification_service, "_deliver", _mock_deliver):
                    p_fired = await fan_out_email_verdict(
                        db, owner_user_id=personal.id, email_id=f"s39-pemail-{stamp}",
                        verdict="malicious", severity="critical", classification="phishing",
                    )
                await db.commit()
            async with _get_admin_session_maker()() as adb:
                p_after = (await adb.execute(text(
                    "select count(*) from cyberguard.org_notification_logs where organization_id = :o"),
                    {"o": personal_org_id})).scalar()
            check((not p_fired) and p_after == p_before,
                  "Personal verdict -> fan-out SUPPRESSED (Phase-7 per-user path owns the email)",
                  f"fired={p_fired} logs {p_before}->{p_after}")

            # ----------------------------------------------------------
            # 9. Gateway ingest_log dual-write.
            # ----------------------------------------------------------
            res_key = await client.post(f"/api/v1/orgs/{org_id}/api-keys", json={"name": "S39 Gateway"})
            gw_key = res_key.json().get("key", "")
            _Identity.user = None
            res_gw = await client.post(
                f"/api/v1/org/{org_id}/gateway",
                headers={"org_authorization": gw_key},
                json={"action": "ingest_log",
                      "data": {"event_type": "failed_login", "source_ip": "203.0.113.9", "user": "s39"}},
            )
            gw_ok = res_gw.status_code == 200
            log_id = res_gw.json().get("result", {}).get("log_id", "") if gw_ok else ""
            _Identity.user = sec_admin
            res_stream = await client.get(f"/api/v1/org/{org_id}/logs/stream")
            stream_ids = [row.get("id") for row in res_stream.json()] if res_stream.status_code == 200 else []
            event_rows = await _count_as(sec_admin.id,
                                         "select count(*) from cyberguard.events where organization_id = :o",
                                         {"o": org_id})
            check(gw_ok and log_id and log_id in stream_ids and event_rows > 0,
                  "Gateway ingest_log dual-write: OrgLogEvent in /logs/stream + Event row still created",
                  f"gw={res_gw.status_code} log_id={log_id} in_stream={log_id in stream_ids} events={event_rows}")

            # ----------------------------------------------------------
            # 10. Dashboard summary for a NON-owner admin (> 0).
            # ----------------------------------------------------------
            res_dash = await client.get(f"/api/v1/org/{org_id}/dashboard/summary")
            total_scans = res_dash.json().get("total_scans", -1) if res_dash.status_code == 200 else -1
            check(res_dash.status_code == 200 and total_scans > 0,
                  "Dashboard summary for a NON-owner admin counts org-stamped events (> 0)",
                  f"status={res_dash.status_code} total_scans={total_scans}")

            # ----------------------------------------------------------
            # 11. Personal-stamped rows invisible to other org members.
            # ----------------------------------------------------------
            leak = await _count_as(sec_admin.id,
                                   "select count(*) from cyberguard.security_events where organization_id = :o",
                                   {"o": personal_org_id})
            check(leak == 0,
                  "Personal-stamped rows invisible to other org members (no cross-leak via org branch)",
                  f"seen={leak}")

            # ----------------------------------------------------------
            # 12. e2e pipeline: fetch->analysis -> stamped SecurityEvent
            #     + org_notification_logs row (non-personal org).
            # ----------------------------------------------------------
            from app.db.models import GmailAccount, ProcessedEmail
            from app.services.gmail.analysis_service import process_email_analysis
            from app.services.idempotency_service import ensure_processed_email

            _Identity.user = admin
            acc_id = ""
            async with _get_admin_session_maker()() as adb:
                account = GmailAccount(owner_user_id=admin.id, email=f"s39-{stamp}@gmail.test",
                                       sync_status="active", last_history_id="1")
                account.set_access_token(f"mock_a_{stamp}")
                account.set_refresh_token(f"mock_r_{stamp}")
                adb.add(account)
                await adb.commit()
                await adb.refresh(account)
                acc_id = account.id
            current_user_id.set(admin.id)
            async with async_session_maker() as db:
                pe = await ensure_processed_email(db, admin.id, f"msg_s39_{stamp}", acc_id)
                pe.subject = "URGENT: verify your account now"
                pe.sender = "security-alerts@paypa1-support.com"
                pe.processing_status = "fetched"
                pe.signals = {
                    "normalized_email": {
                        "subject": pe.subject, "sender": pe.sender,
                        "body_text": "Click http://185.220.101.7/login to verify or your account will be suspended.",
                    },
                    "urls": ["http://185.220.101.7/login"],
                    "headers": {"From": pe.sender, "Subject": pe.subject},
                    "size_bytes": 1200,
                }
                await db.commit()
                pe_id = pe.id
            result = await process_email_analysis(db, processed_email_id=pe_id)
            with patch.object(notification_service, "_deliver", _mock_deliver):
                async with async_session_maker() as db:
                    e2e_fired = await fan_out_email_verdict(
                        db, owner_user_id=admin.id, email_id=pe_id,
                        verdict=None, severity=None,
                        classification=result.get("classification"),
                    )
                    await db.commit()
            stamped = await _count_as(sec_admin.id,
                                      "select count(*) from cyberguard.security_events "
                                      "where organization_id = :o and provider_message_id = :m",
                                      {"o": org_id, "m": f"msg_s39_{stamp}"})
            fan_logs = await _count_as(sec_admin.id,
                                       "select count(*) from cyberguard.org_notification_logs "
                                       "where organization_id = :o and event_type = 'critical_log'",
                                       {"o": org_id})
            check(stamped > 0 and e2e_fired and fan_logs > 0,
                  "e2e pipeline: analysis SecurityEvent org-stamped + fan-out org_notification_logs row",
                  f"stamped={stamped} fired={e2e_fired} fan_logs={fan_logs} "
                  f"classification={result.get('classification')}")
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        current_user_id.set(None)
        invalidate_org_cache()


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
            print(f"\nORG-WIRE: {self.passed}/{self.passed + self.failed} passed")
            return 1 if self.failed else 0

    runner = _Runner()
    print("\n🔗 CYBERGUARD ORG-WIRE TESTS\n" + "=" * 60)
    await run_org_wire_tests(runner)
    print("=" * 60)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
