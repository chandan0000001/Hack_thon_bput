"""ORG-LIVE-VIEWS — feature streams, ingestion status, project scoping
(Suite 41, 12 checks).

 1. streams/{feature} returns ONLY that feature's rows (phishing stream
    excludes url alerts and log events).
 2. project_slug filters to that project; __all__ returns org-wide.
 3. severity filter works on both sources.
 4. q search matches the summary/title.
 5. Keyset cursor pagination: pages concatenate to the full set, no overlap.
 6. Detail endpoint returns the stored analysis (analysis_result for logs,
    indicators for alerts).
 7. Outsider identity sees 0 rows through RLS.
 8. Non-member API call → 403.
 9. Ingestion status fields present with correct types.
10. A gateway-ingested scan appears in the matching stream within one call.
11. A connector-tagged event surfaces with source=connector.
12. Migration 0021 contains zero auth-schema references.

Run via run_all_tests.py (Suite 41) or standalone:
    uv run python scripts/test_org_streams.py
"""

import asyncio
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


async def run_org_streams_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("ORG-LIVE-VIEWS: feature streams, ingestion status, RLS")
    print("-" * 60)

    if "postgresql" not in str(engine.dialect.name):
        check(True, "ORG-LIVE-VIEWS suite skipped without PostgreSQL")
        print("         Skipped: no PostgreSQL configured")
        return

    stamp = uuid.uuid4().hex[:8]
    admin = CurrentUser(id=f"s41-admin-{stamp}", email=f"s41-admin-{stamp}@cyberguard.test", full_name="S41 Admin")
    outsider = CurrentUser(id=f"s41-out-{stamp}", email=f"s41-out-{stamp}@cyberguard.test", full_name="S41 Outsider")

    org_id = ""
    app.dependency_overrides[get_current_user] = _mock_get_current_user
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # ---------- provisioning ----------
            async with async_session_maker() as db:
                for u in (admin, outsider):
                    await _ensure_user(db, u.id, u.email or "")

            _Identity.user = admin
            res = await client.post("/api/v1/orgs", json={"name": f"Streams Org {stamp}"})
            org_id = res.json()["id"]
            res = await client.get(f"/api/v1/orgs/{org_id}/projects")
            general = [p for p in res.json() if p["slug"] == "general"][0]
            general_id = general["id"]

            # Second project for scoping checks
            res = await client.post(f"/api/v1/orgs/{org_id}/projects", json={"name": "Beta"})
            beta_id = res.json()["id"]
            beta_slug = res.json()["slug"]

            # ---------- seed rows (admin identity, owner-scoped) ----------
            event_ids: list[str] = []
            seeded: dict[str, dict] = {}

            async with async_session_maker() as db:
                current_user_id.set(admin.id)
                from datetime import datetime, timedelta, timezone

                from app.db.models import Alert, Event, OrgLogEvent

                now = datetime.now(timezone.utc)

                def _event(eid: str, etype: str, source: str, project: str | None = None) -> Event:
                    return Event(
                        id=eid,
                        organization_id=org_id,
                        project_id=project or general_id,
                        owner_user_id=admin.id,
                        event_type=etype,
                        source=source,
                        raw_data={},
                        status="completed",
                        created_by=admin.id,
                        created_at=now,
                    )

                # phishing alerts (5 for pagination + filters + search)
                for i in range(5):
                    eid = str(uuid.uuid4())
                    aid = str(uuid.uuid4())
                    title = f"S41 phish row {i}"
                    if i == 0:
                        title = "S41 needle-xyz-42 unique phishing"
                    severity = "high" if i % 2 == 0 else "medium"
                    db.add(_event(eid, "phishing_email", "gateway"))
                    db.add(Alert(
                        id=aid, organization_id=org_id, project_id=general_id,
                        owner_user_id=admin.id, event_id=eid, title=title,
                        module="phishing", severity=severity, risk_score=70 + i,
                        status="new", summary=title, indicators=[{"type": "urgency", "value": "act now", "weight": 10, "severity": "high", "description": "urgency"}],
                        explanation="s41 explanation", mitre=[], created_at=now - timedelta(minutes=i),
                    ))
                    seeded[aid] = {"title": title, "severity": severity, "feature": "phishing"}
                # url alert (different feature, general project)
                db.add(_event(str(uuid.uuid4()), "malicious_url", "api"))
                db.add(Alert(
                    id=str(uuid.uuid4()), organization_id=org_id, project_id=general_id,
                    owner_user_id=admin.id, event_id=event_ids[-1] if event_ids else None,
                    title="S41 url row", module="url", severity="medium", risk_score=50,
                    status="new", summary="S41 url row", indicators=[], explanation="", mitre=[],
                    created_at=now,
                ))
                # connector-tagged phishing event in Beta project (check 11)
                ceid = str(uuid.uuid4())
                caid = str(uuid.uuid4())
                db.add(_event(ceid, "phishing_email", "connector", project=beta_id))
                db.add(Alert(
                    id=caid, organization_id=org_id, project_id=beta_id,
                    owner_user_id=admin.id, event_id=ceid, title="S41 connector row",
                    module="phishing", severity="low", risk_score=20,
                    status="new", summary="S41 connector row", indicators=[], explanation="", mitre=[],
                    created_at=now,
                ))
                seeded[caid] = {"title": "S41 connector row", "severity": "low", "feature": "phishing"}
                # org_log_event with analysis_result (checks 1/4/6)
                db.add(OrgLogEvent(
                    id=str(uuid.uuid4()), organization_id=org_id, project_id=general_id,
                    log_type="auth", raw_data={"user": "s41"},
                    analysis_result={"risk_score": 55, "severity": "high",
                                     "summary": "S41 brute force pattern", "indicators": []},
                    severity="high", created_by=admin.id, created_at=now,
                ))
                await db.commit()
                current_user_id.set(None)

            base = f"/api/v1/org/{org_id}/projects"

            # ---------- 1. feature isolation ----------
            res = await client.get(f"{base}/general/streams/phishing")
            rows = res.json()["rows"]
            check(
                res.status_code == 200
                and rows
                and all(r["feature"] == "phishing" for r in rows)
                and all("url row" not in (r["summary"] or "") for r in rows),
                "41.1 phishing stream returns only phishing rows",
                f"status={res.status_code} features={ {r['feature'] for r in rows} }",
            )
            res_logs = await client.get(f"{base}/general/streams/logs")
            log_rows = res_logs.json()["rows"]
            check(
                res_logs.status_code == 200
                and len(log_rows) == 1
                and log_rows[0]["event_type"] == "auth"
                and log_rows[0]["source"] == "gateway",
                "41.1b logs stream returns the analyzed log event",
                f"status={res_logs.status_code} rows={log_rows}",
            )

            # ---------- 2. project scoping + __all__ ----------
            res = await client.get(f"{base}/general/streams/phishing")
            general_ids = {r["id"] for r in res.json()["rows"]}
            res_beta = await client.get(f"{base}/{beta_slug}/streams/phishing")
            beta_ids = {r["id"] for r in res_beta.json()["rows"]}
            res_all = await client.get(f"{base}/__all__/streams/phishing")
            all_ids = {r["id"] for r in res_all.json()["rows"]}
            check(
                general_ids and beta_ids and not (general_ids & beta_ids)
                and all_ids == general_ids | beta_ids,
                "41.2 project_slug filters; __all__ is org-wide",
                f"general={len(general_ids)} beta={len(beta_ids)} all={len(all_ids)}",
            )

            # ---------- 3. severity filter ----------
            res = await client.get(f"{base}/general/streams/phishing?severity=high")
            sevs = {r["severity"] for r in res.json()["rows"]}
            check(
                res.status_code == 200 and sevs == {"high"},
                "41.3 severity filter returns only high rows",
                f"severities={sevs}",
            )

            # ---------- 4. q search ----------
            res = await client.get(f"{base}/general/streams/phishing?q=needle-xyz-42")
            hits = res.json()["rows"]
            res_empty = await client.get(f"{base}/general/streams/phishing?q=does-not-exist-qq")
            check(
                len(hits) == 1 and "needle-xyz-42" in (hits[0]["summary"] or "")
                and len(res_empty.json()["rows"]) == 0,
                "41.4 q search matches summary (and misses cleanly)",
                f"hits={len(hits)} empty={len(res_empty.json()['rows'])}",
            )
            res_logq = await client.get(f"{base}/general/streams/logs?q=brute force")
            check(
                len(res_logq.json()["rows"]) == 1,
                "41.4b q search matches log analysis_result.summary",
                f"rows={len(res_logq.json()['rows'])}",
            )

            # ---------- 5. cursor pagination ----------
            seen: list[str] = []
            cursor = None
            pages = 0
            while pages < 6:
                url = f"{base}/general/streams/phishing?limit=2"
                if cursor:
                    url += f"&cursor={cursor}"
                res = await client.get(url)
                body = res.json()
                seen.extend(r["id"] for r in body["rows"])
                pages += 1
                cursor = body.get("next_cursor")
                if not cursor:
                    break
            check(
                len(seen) == 5 and len(set(seen)) == 5,
                "41.5 keyset pagination: full set, no overlap",
                f"seen={len(seen)} unique={len(set(seen))} pages={pages}",
            )

            # ---------- 6. detail endpoint ----------
            log_detail_id = log_rows[0]["id"]
            res = await client.get(f"{base}/general/streams/logs/{log_detail_id}")
            detail = res.json()
            check(
                res.status_code == 200
                and detail["analysis"]["analysis_result"].get("risk_score") == 55,
                "41.6a log detail returns analysis_result json",
                f"status={res.status_code} keys={list(detail.get('analysis', {}).keys())}",
            )
            alert_detail_id = hits[0]["id"]
            res = await client.get(f"{base}/general/streams/phishing/{alert_detail_id}")
            detail = res.json()
            check(
                res.status_code == 200
                and detail["row"]["source"] == "gateway"
                and detail["analysis"]["indicators"],
                "41.6b alert detail returns row + indicators",
                f"status={res.status_code} source={detail.get('row', {}).get('source')}",
            )

            # ---------- 7. outsider RLS 0-rows ----------
            outsider_count = await _count_as(
                outsider.id,
                "select count(*) from cyberguard.alerts where organization_id = :org",
                {"org": org_id},
            )
            check(outsider_count == 0, "41.7 outsider RLS session sees 0 stream rows",
                  f"count={outsider_count}")

            # ---------- 8. non-member API 403 ----------
            _Identity.user = outsider
            res = await client.get(f"{base}/general/streams/phishing")
            check(res.status_code == 403, "41.8 non-member API call rejected 403",
                  f"status={res.status_code}")
            _Identity.user = admin

            # ---------- 9. ingestion status ----------
            res = await client.get(f"/api/v1/org/{org_id}/dashboard/summary?project_id={general_id}")
            ing = res.json().get("ingestion", {})
            check(
                res.status_code == 200
                and isinstance(ing.get("gateway_last_event_ts"), (str, type(None)))
                and isinstance(ing.get("gateway_event_count_24h"), int)
                and isinstance(ing.get("connectors_connected"), int)
                and isinstance(ing.get("connectors_total"), int)
                and isinstance(ing.get("pipeline_last_sync_ts"), (str, type(None))),
                "41.9 ingestion status fields present + types correct",
                f"ingestion={ing}",
            )

            # ---------- 10. gateway → stream freshness ----------
            res = await client.post(
                f"/api/v1/orgs/{org_id}/projects/{general_id}/keys",
                json={"role": "master", "name": "s41 master"},
            )
            master_key = res.json()["key"]
            sender = f"s41-fresh-{stamp}@evil.test"
            res = await client.post(
                f"/api/v1/org/{org_id}/projects/general/gateway",
                headers={"org_authorization": master_key},
                json={"action": "scan_email",
                      "data": {"sender": sender, "subject": f"S41 fresh gateway {stamp}",
                               "body": "Verify your password at http://185.220.101.7/login immediately."}},
            )
            check(res.status_code == 200, "41.10a gateway scan accepted", f"status={res.status_code}")
            res = await client.get(f"{base}/general/streams/phishing?limit=200")
            fresh = [r for r in res.json()["rows"] if (r["summary"] or "").find(f"S41 fresh gateway {stamp}") >= 0]
            check(
                len(fresh) == 1 and fresh[0]["source"] == "gateway",
                "41.10b gateway event visible in the stream on the next call",
                f"fresh={len(fresh)} source={fresh[0]['source'] if fresh else None}",
            )

            # ---------- 11. connector source ----------
            res = await client.get(f"{base}/{beta_slug}/streams/phishing")
            conn_rows = [r for r in res.json()["rows"] if r["id"] in seeded and seeded[r["id"]]["title"] == "S41 connector row"]
            check(
                len(conn_rows) == 1 and conn_rows[0]["source"] == "connector",
                "41.11 connector-tagged event surfaces with source=connector",
                f"rows={conn_rows}",
            )

            # ---------- 12. migration 0021 auth-schema refs ----------
            mig = (ROOT / "alembic" / "versions" / "0021_events_realtime_publication.py").read_text()
            bad = [frag for frag in ("auth.uid", "auth.users", "auth.role(", "supabase_auth_admin")
                   if frag in mig]
            check(not bad, "41.12 migration 0021 has zero auth-schema references", f"found={bad}")

    finally:
        app.dependency_overrides.pop(get_current_user, None)
        _Identity.user = None
        if org_id:
            try:
                async with _get_admin_session_maker()() as adb:
                    await adb.execute(text("delete from cyberguard.projects where organization_id = :o"),
                                      {"o": org_id})
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
            print(f"\nORG-LIVE-VIEWS: {self.passed}/{self.passed + self.failed} passed")
            return 1 if self.failed else 0

    runner = _Runner()
    print("\n🔗 CYBERGUARD ORG-LIVE-VIEWS TESTS\n" + "=" * 60)
    await run_org_streams_tests(runner)
    print("=" * 60)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
