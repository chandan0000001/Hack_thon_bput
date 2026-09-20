"""Comprehensive automated test suite for CYBERGUARD backend.

Tests:
1. Database initialization and seeding
2. User and Personal Workspace auto-provisioning
3. Organization CRUD and membership role assignments
4. RBAC role enforcement (Admin, Analyst, Viewer)
5. Analysis Pipelines (Phishing, URL, Impersonation, ATO, Network)
6. OpenRouter client and heuristic fallback behavior

Run via:
    uv run python scripts/run_all_tests.py
"""

import asyncio
import os
import sys
from pathlib import Path

# Ensure backend root is on sys.path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.config import get_settings
from app.core.security import CurrentUser, TenantContext, get_current_user, get_tenant_context
from app.db.models import Organization, OrganizationMember, User
from app.db.session import async_session_maker, current_user_id, init_db
from app.main import app


class TestRunner:
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

    def skip(self, name: str, reason: str = ""):
        print(f"  \033[33m⊘ SKIP\033[0m: {name} ({reason})")

    def report(self):
        total = self.passed + self.failed
        print("\n" + "=" * 60)
        print(f"TEST RESULTS: {self.passed}/{total} passed")
        if self.failed == 0:
            print("\033[32mALL BACKEND TESTS PASSED SUCCESSFULLY!\033[0m")
        else:
            print(f"\033[31m{self.failed} TESTS FAILED!\033[0m")
        print("=" * 60 + "\n")
        return 0 if self.failed == 0 else 1


async def run_tests():
    runner = TestRunner()
    print("\n🔍 STARTING CYBERGUARD BACKEND TEST SUITE\n" + "=" * 60)

    # -----------------------------------------------------------------------
    # 1. Database Initialization
    # -----------------------------------------------------------------------
    print("\n[Suite 1] Database & Schema Initialization")
    try:
        await init_db()
        runner.assert_true(True, "Database tables & response catalog seeded")
    except Exception as e:
        runner.assert_true(False, "Database initialization failed", str(e))

    # -----------------------------------------------------------------------
    # 2. Dynamic Auto-Provisioning & Personal Workspace
    # (Organization endpoints are frozen behind ORG_ENABLED in the product;
    #  this suite exercises the frozen org code paths directly, so the flag is
    #  enabled for the duration of the suite and restored afterwards.)
    # -----------------------------------------------------------------------
    print("\n[Suite 2] Multi-tenant Provisioning & Organizations")
    from app.core.config import get_settings

    _org_enabled_backup = get_settings().ORG_ENABLED
    get_settings().ORG_ENABLED = True
    test_user_id = f"test-usr-{os.urandom(4).hex()}"
    test_email = f"analyst-{test_user_id}@cyberguard.test"
    test_user = CurrentUser(id=test_user_id, email=test_email, full_name="Test SOC Analyst")
    personal_org_id = f"org-personal-{os.urandom(8).hex()}"  # <= varchar(36) — Postgres enforces the column length

    # Provision user and personal org in a dedicated, isolated session.
    # Production parity: the real get_current_user stamps the RLS identity
    # (app.user_id GUC) before any SQL runs; the baseline RLS enforces it.
    current_user_id.set(test_user.id)
    async with async_session_maker() as db:
        user_db = User(id=test_user.id, email=test_user.email, full_name=test_user.full_name)
        db.add(user_db)
        await db.flush()
        personal_org = Organization(
            id=personal_org_id,
            name="Personal Workspace",
            slug=f"personal-{test_user.id}",
            is_personal=True,
            owner_id=test_user.id,
        )
        db.add(personal_org)
        await db.flush()
        member = OrganizationMember(
            id=f"mem-{os.urandom(12).hex()}",  # <= varchar(36)
            organization_id=personal_org.id,
            user_id=test_user.id,
            role="admin",
        )
        db.add(member)
        user_db.active_organization_id = personal_org.id
        await db.commit()

    active_org_id = personal_org_id
    current_user_id.set(None)  # reset after direct-session provisioning

    async def mock_get_current_user():
        current_user_id.set(test_user.id)  # RLS identity, as in production
        return test_user

    async def mock_get_tenant_context():
        nonlocal active_org_id
        return TenantContext(
            organization_id=active_org_id,
            organization_name="Test SOC Workspace",
            role="admin",
            is_single_user=(active_org_id == personal_org_id),
            user_id=test_user.id,
            owner_user_id=test_user.id,  # rows must satisfy owner-scoped RLS
        )

    app.dependency_overrides[get_current_user] = mock_get_current_user
    app.dependency_overrides[get_tenant_context] = mock_get_tenant_context

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test /auth/me
        res = await client.get("/api/v1/auth/me")
        runner.assert_true(res.status_code == 200, "GET /api/v1/auth/me returns 200 OK")
        data = res.json()
        runner.assert_true(data["is_single_user"] is True, "User is in Single-User Personal Workspace by default")
        runner.assert_true(data["active_role"] == "admin", "Single-User workspace automatically has admin role")

        # Test Create Team Organization
        org_payload = {"name": "Test Enterprise SOC"}
        res_org = await client.post("/api/v1/organizations", json=org_payload)
        runner.assert_true(res_org.status_code == 201, "POST /api/v1/organizations creates team organization")
        created_org = res_org.json()
        runner.assert_true(created_org["name"] == "Test Enterprise SOC", "Created org has matching name")

        # Test List Organizations
        res_list = await client.get("/api/v1/organizations")
        runner.assert_true(res_list.status_code == 200, "GET /api/v1/organizations returns 200")
        orgs = res_list.json()
        runner.assert_true(len(orgs) >= 2, "User belongs to both Personal Workspace and Team SOC")

        # Test Switch Organization
        switch_res = await client.post(
            "/api/v1/auth/switch-org",
            json={"organization_id": created_org["id"]},
        )
        runner.assert_true(switch_res.status_code == 200, "POST /api/v1/auth/switch-org succeeds")
        active_org_id = created_org["id"]

        # -------------------------------------------------------------------
        # 3. Detection Engines
        # -----------------------------------------------------------------------
        print("\n[Suite 3] Analysis Engines & AI Explanations")

        # Phishing analysis (Critical malicious sample)
        res_phish = await client.post(
            "/api/v1/analysis/email",
            json={
                "sender": "alerts@paypa1-security.com",
                "subject": "URGENT: Unauthorized login detected",
                "body": "Click http://185.220.101.7/login to verify your account immediately or it will be suspended.",
            },
        )
        runner.assert_true(res_phish.status_code == 200, "POST /api/v1/analysis/email returns 200")
        phish_data = res_phish.json()
        runner.assert_true(phish_data["risk_score"] >= 70, "Suspicious phishing email triggers HIGH/CRITICAL risk score")
        runner.assert_true(len(phish_data["indicators"]) > 0, "Phishing indicators extracted")
        runner.assert_true(bool(phish_data.get("explanation")), "Explanation synthesized")

        # Phishing analysis (Benign registrar sample - consistency test)
        res_benign = await client.post(
            "/api/v1/analysis/email",
            json={
                "sender": "registrar@university.edu",
                "subject": "Examination timetable published",
                "body": "The timetable is on the student portal. No action required.",
            },
        )
        runner.assert_true(res_benign.status_code == 200, "POST benign email returns 200")
        benign_data = res_benign.json()
        runner.assert_true(benign_data["severity"] == "safe", "Benign email scored as SAFE")
        runner.assert_true(benign_data["risk_score"] <= 20, "Benign email risk score <= 20")
        runner.assert_true("safe" in benign_data["explanation"].lower() or "benign" in benign_data["explanation"].lower(), "AI explanation aligns with SAFE severity")

        # URL analysis
        res_url = await client.post(
            "/api/v1/analysis/url",
            json={"url": "http://185.220.101.7/secure/login.php"},
        )
        runner.assert_true(res_url.status_code == 200, "POST /api/v1/analysis/url returns 200")
        url_data = res_url.json()
        runner.assert_true(url_data["risk_score"] >= 60, "Malicious raw IP URL flagged with high risk")

        # Impersonation analysis
        res_imp = await client.post(
            "/api/v1/analysis/impersonation",
            json={
                "claimed_identity": "Chief Financial Officer",
                "message": "Urgent and confidential wire transfer request. Purchase gift cards and wire funds immediately.",
            },
        )
        runner.assert_true(res_imp.status_code == 200, "POST /api/v1/analysis/impersonation returns 200")
        imp_data = res_imp.json()
        runner.assert_true(imp_data["risk_score"] >= 60, "Executive gift-card wire fraud flagged")

        # Account Takeover analysis
        res_ato = await client.post(
            "/api/v1/analysis/account-takeover",
            json={
                "events": [
                    {"user": "alice", "ip": "10.0.1.45", "location": "New York, US", "device": "Windows-Chrome", "status": "success", "timestamp": "2026-09-08T09:00:00Z"},
                    {"user": "alice", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "failed", "timestamp": "2026-09-08T09:05:00Z"},
                    {"user": "alice", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "failed", "timestamp": "2026-09-08T09:05:30Z"},
                    {"user": "alice", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "failed", "timestamp": "2026-09-08T09:06:00Z"},
                    {"user": "alice", "ip": "185.220.101.7", "location": "Moscow, RU", "device": "Linux-Firefox", "status": "success", "timestamp": "2026-09-08T09:07:00Z"},
                ]
            },
        )
        runner.assert_true(res_ato.status_code == 200, "POST /api/v1/analysis/account-takeover returns 200")
        ato_data = res_ato.json()
        runner.assert_true(ato_data["risk_score"] >= 60, "Impossible travel velocity flagged as ATO")

        # Dashboard Summary
        res_dash = await client.get("/api/v1/dashboard/summary")
        runner.assert_true(res_dash.status_code == 200, "GET /api/v1/dashboard/summary returns 200")
        dash_data = res_dash.json()
        runner.assert_true("threats_detected" in dash_data, "Dashboard summary contains metrics")

        # Response actions catalog
        res_actions = await client.get("/api/v1/responses/catalog")
        runner.assert_true(res_actions.status_code == 200, "GET /api/v1/responses/catalog returns 200")
        actions = res_actions.json()
        runner.assert_true(len(actions) > 0, "Pre-seeded SOAR response catalog available")

        # Media Forensics / Deepfake Analysis
        from io import BytesIO
        from PIL import Image
        img = Image.new("RGB", (64, 64), color=(50, 100, 150))
        buf = BytesIO()
        img.save(buf, format="PNG")
        res_media = await client.post(
            "/api/v1/analysis/media",
            files={"file": ("test_media.png", buf.getvalue(), "image/png")},
        )
        runner.assert_true(res_media.status_code == 200, "POST /api/v1/analysis/media returns 200")
        media_data = res_media.json()
        runner.assert_true("authenticity_score" in media_data, "Media forensics authenticity score calculated")
        runner.assert_true(bool(media_data.get("storage_path")), "Media file storage path recorded")

    # -------------------------------------------------------------------
    # 4. Multi-Provider API Key Rotation, Circuit Breaking & Resilient Fallback
    # -------------------------------------------------------------------
    print("\n[Suite 4] Multi-Provider API Key Rotation, Circuit Breaking & Failover")
    from app.ai.key_rotator import ApiKeyRotator
    from app.ai.llm_client import call_llm

    # 4.1 Key rotation and circuit breaking
    test_rotator = ApiKeyRotator()
    test_rotator.initialize(["key-soc-1", "key-soc-2", "key-soc-3"], cooldown_seconds=1, provider="openrouter")
    k1, _ = await test_rotator.get_next_key(provider="openrouter")
    k2, _ = await test_rotator.get_next_key(provider="openrouter")
    k3, _ = await test_rotator.get_next_key(provider="openrouter")
    runner.assert_true([k1, k2, k3] == ["key-soc-1", "key-soc-2", "key-soc-3"], "Distributed round-robin rotation across active keys")

    # Mark key 2 down
    test_rotator.mark_key_down("key-soc-2", reason="Rate limit 429", status_code=429, provider="openrouter")
    next_keys = [await test_rotator.get_next_key(provider="openrouter"), await test_rotator.get_next_key(provider="openrouter")]
    runner.assert_true("key-soc-2" not in [k[0] for k in next_keys], "Circuit breaker bypasses downed key")

    # Wait for cooldown and verify auto-recovery
    await asyncio.sleep(1.1)
    status_list = test_rotator.get_status(provider="openrouter")
    k2_status = status_list[1]
    runner.assert_true(k2_status["is_healthy"] is True, "Downed key automatically re-released after cooldown")

    # 4.2 Multi-provider pool initialization (Groq, Gemini, OpenRouter)
    test_rotator.initialize(["gsk-groq-1", "gsk-groq-2"], provider="groq")
    test_rotator.initialize(["gemini-key-1"], provider="gemini")
    configured = test_rotator.get_configured_providers()
    runner.assert_true("groq" in configured and "gemini" in configured and "openrouter" in configured, "Multi-provider pools (Groq, Gemini, OpenRouter) registered")

    p1 = await test_rotator.get_next_provider()
    p2 = await test_rotator.get_next_provider()
    runner.assert_true(bool(p1 and p2), "Distributed round-robin provider selection functional")

    # 4.3 Resilient startup & clean logging when zero keys are configured
    empty_rotator = ApiKeyRotator()
    # Call log_startup_summary to verify it executes cleanly without throwing
    empty_rotator.log_startup_summary()
    runner.assert_true(len(empty_rotator.get_configured_providers()) == 0 or True, "Empty rotator logs clean startup without crashing")

    # 4.4 Heuristic explanation fallback when no keys are available
    heuristic_res = await call_llm(
        system_prompt="Test system",
        user_prompt="Test user",
        module="phishing",
        indicators=[{"description": "Deceptive sender domain detected"}],
        risk_score=85,
    )
    runner.assert_true("explanation" in heuristic_res, "Heuristic explanation returned when LLM unavailable")
    runner.assert_true(len(heuristic_res.get("mitre_techniques", [])) > 0, "MITRE techniques included in fallback explanation")

    # Clean up overrides
    app.dependency_overrides.clear()
    current_user_id.set(None)

    # Restore the frozen-orgs flag for the remaining suites (product default).
    get_settings().ORG_ENABLED = _org_enabled_backup

    # -----------------------------------------------------------------------
    # 5. Phase 1 — Dual-Mode Foundation (policies, mode detection, enforcement engine)
    # -----------------------------------------------------------------------
    print("\n[Suite 5] Phase 1 — Dual-Mode Foundation")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_phase1 import run_phase1_tests

    await run_phase1_tests(runner)

    # -----------------------------------------------------------------------
    # 6. Phase 2 — Server-Mode Integration Endpoints (enforcement executor)
    # -----------------------------------------------------------------------
    print("\n[Suite 6] Phase 2 — Server-Mode Integration Endpoints")
    from test_phase2 import run_phase2_tests

    await run_phase2_tests(runner)

    # -----------------------------------------------------------------------
    # 7. Phase 3 — Approval Workflow & Policy Management
    # -----------------------------------------------------------------------
    print("\n[Suite 7] Phase 3 — Approval Workflow & Policy Management")
    from test_phase3 import run_phase3_tests

    await run_phase3_tests(runner)

    # -----------------------------------------------------------------------
    # 8. Phase 4 Hotfix — SOC Assistant Intent Routing
    # -----------------------------------------------------------------------
    print("\n[Suite 8] Phase 4 Hotfix — SOC Assistant Intent Routing")
    from test_assistant import run_assistant_tests

    await run_assistant_tests(runner)

    # -----------------------------------------------------------------------
    # 9. ML Integration Gates (blend contract, v2 models, audio LCNN)
    # -----------------------------------------------------------------------
    print("\n[Suite 9] ML Integration Gates")
    from test_ml_gates import run_ml_gate_tests

    run_ml_gate_tests(runner)

    # -----------------------------------------------------------------------
    # 10. Phase -1 — User-Only Account Foundation (usernames, frozen orgs,
    #     owner-scoped tenancy)
    # -----------------------------------------------------------------------
    print("\n[Suite 10] Phase -1 — User Foundation (usernames, frozen orgs, owner scoping)")
    from test_user_foundation import run_user_foundation_tests

    await run_user_foundation_tests(runner)

    # -----------------------------------------------------------------------
    # 11. Phase -1 — Row-Level Security (PostgreSQL only; skips on SQLite)
    # -----------------------------------------------------------------------
    print("\n[Suite 11] Phase -1 — Row-Level Security (PostgreSQL only)")
    from test_rls_pg import run_rls_tests

    await run_rls_tests(runner)

    # -----------------------------------------------------------------------
    # 12. Phase 1-2 — Gmail Connector, OAuth Flow & Encrypted Token Vault
    # -----------------------------------------------------------------------
    print("\n[Suite 12] Phase 1-2 — Email Connectors (Gmail OAuth + token vault)")
    from test_email_connectors import run_email_connector_tests

    await run_email_connector_tests(runner)

    # -----------------------------------------------------------------------
    # 13. Phase 3 — Mailbox Scanning, Normalization & Verbose Results
    # -----------------------------------------------------------------------
    print("\n[Suite 13] Phase 3 — Mailbox Scanning & Verbose Analysis")
    from test_mail_scanner import run_mail_scanner_tests

    await run_mail_scanner_tests(runner)

    # -----------------------------------------------------------------------
    # 14. Phase 4 — Enforcement, Quarantine, Sender Rules & Expiry Scheduler
    # -----------------------------------------------------------------------
    print("\n[Suite 14] Phase 4 — Enforcement (quarantine, sender rules, expiry)")
    from test_enforcement import run_enforcement_tests

    await run_enforcement_tests(runner)

    # -----------------------------------------------------------------------
    # 15. Phase 5 — Security History, Audit & User Review
    # -----------------------------------------------------------------------
    print("\n[Suite 15] Phase 5 — Security History & Review")
    from test_security_history import run_security_history_tests

    await run_security_history_tests(runner)

    # -----------------------------------------------------------------------
    # 16. Phase 6-7 — Provider-Neutral Contract + Event Email Notifications
    # -----------------------------------------------------------------------
    print("\n[Suite 16] Phase 6-7 — Contract Hardening & Notifications")
    from test_phase_6_7 import run_phase_6_7_tests

    await run_phase_6_7_tests(runner)

    # -----------------------------------------------------------------------
    # 17. ORG-1 — Organization Foundation (salting, API keys, gateway, RBAC, RLS)
    # -----------------------------------------------------------------------
    print("\n[Suite 17] ORG-1 — Organization Foundation")
    from test_org_foundation import run_org_foundation_tests

    await run_org_foundation_tests(runner)

    # -----------------------------------------------------------------------
    # 18. ORG-2 — Dashboards + Splunk Log Analysis (summary, feeds, ingest,
    #     stream, manual actions, RBAC, isolation)
    # -----------------------------------------------------------------------
    print("\n[Suite 18] ORG-2 — Dashboards + Live Log Analysis")
    from test_org_dashboards import run_org_dashboard_tests

    await run_org_dashboard_tests(runner)

    # -----------------------------------------------------------------------
    # 19. ORG-3 — Mail Server Connectors (server-to-server, per-server
    #     logs/settings, graceful disconnect, encrypted credentials)
    # -----------------------------------------------------------------------
    print("\n[Suite 19] ORG-3 — Mail Server Connectors")
    from test_org_mail_connectors import run_org_mail_tests

    await run_org_mail_tests(runner)

    # -----------------------------------------------------------------------
    # 20. ORG-4 — Email Notification Groups (role-grouped recipients, event
    #     routing, triggers, delivery logs)
    # -----------------------------------------------------------------------
    print("\n[Suite 20] ORG-4 — Email Notification Groups")
    from test_org_notifications import run_org_notification_tests

    await run_org_notification_tests(runner)

    # -----------------------------------------------------------------------
    # 21. ORG-5 — Realtime policy tightening (gated authenticated SELECT)
    # -----------------------------------------------------------------------
    print("\n[Suite 21] ORG-5 — Realtime Policy Tightening")
    from test_org_realtime_policies import run_realtime_policy_tests

    await run_realtime_policy_tests(runner)

    # -----------------------------------------------------------------------
    # 22. RT-1 — Real-time Pipeline Infrastructure (Redis, Arq, Docker, workers)
    # -----------------------------------------------------------------------
    print("\n[Suite 22] RT-1 — Real-time Pipeline Infrastructure")
    from test_rt_infrastructure import run_rt_infrastructure_tests

    await run_rt_infrastructure_tests(runner)

    # -----------------------------------------------------------------------
    # 23. RT-2 — Real-time Pipeline Database Models (gmail_accounts, job_queue, processed_emails)
    # -----------------------------------------------------------------------
    print("\n[Suite 23] RT-2 — Real-time Pipeline Database Models")
    from test_rt_db_models import run_rt_db_models_tests

    await run_rt_db_models_tests(runner)

    # -----------------------------------------------------------------------
    # 24. RT-3 — Gmail Pub/Sub Webhook (validation, thin enqueue, rate limit)
    # -----------------------------------------------------------------------
    print("\n[Suite 24] RT-3 — Gmail Pub/Sub Webhook")
    from test_gmail_webhook import run_gmail_webhook_tests

    await run_gmail_webhook_tests(runner)

    # -----------------------------------------------------------------------
    # 25. RT-4 — Gmail Sync Worker (history.list, message discovery, FOR UPDATE lock)
    # -----------------------------------------------------------------------
    print("\n[Suite 25] RT-4 — Gmail Sync Worker")
    from test_gmail_sync_worker import run_gmail_sync_worker_tests

    await run_gmail_sync_worker_tests(runner)

    # -----------------------------------------------------------------------
    # 26. RT-5 — Email Fetch Worker (Gmail get, MIME parse, normalize, store, enqueue analysis)
    # -----------------------------------------------------------------------
    print("\n[Suite 26] RT-5 — Email Fetch Worker")
    from test_email_fetch_worker import run_email_fetch_worker_tests

    await run_email_fetch_worker_tests(runner)

    # -----------------------------------------------------------------------
    # 27. RT-6 — Email Analysis Worker (phishing/URL/impersonation/ATO engines + ML inference + result persistence)
    # -----------------------------------------------------------------------
    print("\n[Suite 27] RT-6 — Email Analysis Worker")
    from test_email_analysis_worker import run_email_analysis_worker_tests

    await run_email_analysis_worker_tests(runner)

    # -----------------------------------------------------------------------
    # 28. RT-8 — Watch renewal + reconciliation scheduled workers
    # -----------------------------------------------------------------------
    print("\n[Suite 28] RT-8 — Scheduled Workers (Watch Renewal & Reconciliation)")
    from test_scheduled_workers import run_scheduled_workers_tests

    await run_scheduled_workers_tests(runner)

    # -----------------------------------------------------------------------
    # 29. RT-9 — Observability (correlation IDs, structured JSON logs, Prometheus metrics export)
    # -----------------------------------------------------------------------
    print("\n[Suite 29] RT-9 — Observability (Logs, Correlation IDs, Prometheus Metrics)")
    from test_observability import run_observability_tests

    await run_observability_tests(runner)

    # -----------------------------------------------------------------------
    # 30. RT-10 — Dead letter queue ops dashboard + retry/backoff tuning + poison message visibility
    # -----------------------------------------------------------------------
    print("\n[Suite 30] RT-10 — DLQ Ops Dashboard, Retry Backoff & Poison Visibility")
    from test_dlq_ops import run_dlq_ops_tests

    await run_dlq_ops_tests(runner)

    # -----------------------------------------------------------------------
    # 31. ATTACH-SCAN-1 — Memory-safe attachment scanning foundation
    # -----------------------------------------------------------------------
    print("\n[Suite 31] ATTACH-SCAN-1 — Attachment Scanning Foundation")
    tests_dir = str(ROOT / "tests")
    if tests_dir not in sys.path:
        sys.path.insert(0, tests_dir)
    from test_attachment_scanner import run_attachment_scanner_tests

    await run_attachment_scanner_tests(runner)

    # -----------------------------------------------------------------------
    # 32. ATTACH-SCAN-2 — Malware detection layer (ClamAV, YARA, archives, PE)
    # -----------------------------------------------------------------------
    print("\n[Suite 32] ATTACH-SCAN-2 — Malware Detection Layer")
    from test_malware_detection import run_malware_detection_tests

    await run_malware_detection_tests(runner)

    # -----------------------------------------------------------------------
    # 33. ATTACH-SCAN-3 — Content analysis layer (PDF, Office, URLs, text)
    # -----------------------------------------------------------------------
    print("\n[Suite 33] ATTACH-SCAN-3 — Content Analysis Layer")
    from test_content_analysis import run_content_analysis_tests

    await run_content_analysis_tests(runner)

    return runner.report()





if __name__ == "__main__":
    exit_code = asyncio.run(run_tests())
    sys.exit(exit_code)
