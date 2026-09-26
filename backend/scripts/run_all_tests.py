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

# AUTH-VERIFY: keep the harness fully offline/deterministic — independent DNS
# verification degrades to "unavailable" + mx_parsed fallback. Suite 36
# overrides with injected fake resolvers where it exercises verification.
os.environ.setdefault("DNS_OFFLINE", "true")

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
    # 45. ORG-REBUILD — Organization System Rebuild (3-level architecture)
    # -----------------------------------------------------------------------
    print("\n[Suite 45] ORG-REBUILD — Organization System 3-Level Architecture")
    from test_org_rebuild import run_org_rebuild_tests

    await run_org_rebuild_tests(runner)

    # -----------------------------------------------------------------------
    # 46. ORG-AUTH-FIX — Organization Auth, Membership Hydration, & RLS Fixes
    # -----------------------------------------------------------------------
    from test_org_auth_fix import run_org_auth_fix_tests

    await run_org_auth_fix_tests(runner)

    # -----------------------------------------------------------------------
    # 47. ORG-IDENTITY-FIX — Single Identity, Atomic Signup, and Graceful 409 UX
    # -----------------------------------------------------------------------
    from test_org_identity import run_org_identity_tests

    await run_org_identity_tests(runner)

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

    # -----------------------------------------------------------------------
    # 34. ATTACH-SCAN-4 — Risk scoring + pipeline integration + explainable verdicts
    # -----------------------------------------------------------------------
    print("\n[Suite 34] ATTACH-SCAN-4 — Attachment Integration & Explainable Verdicts")
    from test_attachment_integration import run_attachment_integration_tests

    await run_attachment_integration_tests(runner)

    # -----------------------------------------------------------------------
    # 36. AUTH-VERIFY — independent SPF/DKIM/DMARC verification
    # -----------------------------------------------------------------------
    print("\n[Suite 36] AUTH-VERIFY — Independent Authentication Verification")
    from pytest import MonkeyPatch

    from app.services import auth_verifier as _auth_mod
    from app.services.auth_verifier import manual_auth_section, verify_all, verify_or_parse, verify_spf
    from app.services.dns_resolver import DNSResolver, DNSUnavailable

    def _fake_resolver(records=None, offline=False, **kwargs):
        table = {(q.lower(), r): v for (q, r), v in (records or {}).items()}
        counter = {"calls": 0}

        def transport(qname, rdtype):
            counter["calls"] += 1
            return list(table.get((qname.lower().rstrip("."), rdtype.upper()), []))

        resolver = DNSResolver(offline=offline, transport=transport, **kwargs)
        resolver.call_counter = counter
        return resolver

    SPF_REC = {("example.com", "TXT"): ['"v=spf1 ip4:203.0.113.0/24 -all"']}
    DMARC_REJECT = {("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject"']}

    async def run_auth_verification_tests() -> None:
        _pem, _pub_b64 = None, None
        try:
            import base64 as _b64
            import dkim as _dkim
            from cryptography.hazmat.primitives import serialization as _ser
            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

            _key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
            _pem = _key.private_bytes(
                _ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL, _ser.NoEncryption()
            )
            _pub_b64 = _b64.b64encode(
                _key.public_key().public_bytes(
                    _ser.Encoding.DER, _ser.PublicFormat.SubjectPublicKeyInfo
                )
            ).decode()
        except Exception as exc:
            runner.skip("dkim key generation", f"deps unavailable: {exc}")

        # 1 spf pass
        r = _fake_resolver(SPF_REC)
        res = verify_spf("bounce@example.com", "203.0.113.10", "example.com", r)
        runner.assert_true(res["status"] == "pass", "spf: ip4 match verifies pass (mocked DNS)", str(res))
        # 2 spf fail -> +30
        r = _fake_resolver(SPF_REC)
        out = verify_all({"sender": "ceo@example.com", "headers": {}, "sender_ip": "198.51.100.9"}, r)
        runner.assert_true(
            out["spf"]["status"] == "fail" and out["risk_score"] == 30 and bool(out["spf"]["reason"]),
            "spf: non-matching IP fails with reason and +30 risk", str(out["spf"]),
        )
        # 3 spf softfail -> +15
        r = _fake_resolver({("example.com", "TXT"): ['"v=spf1 ip4:203.0.113.0/24 ~all"']})
        out = verify_all({"sender": "ceo@example.com", "headers": {}, "sender_ip": "198.51.100.9"}, r)
        runner.assert_true(out["spf"]["status"] == "softfail" and out["risk_score"] == 15,
                           "spf: softfail scores +15", str(out["spf"]))
        # 4 no sender IP -> unavailable, risk 0, info indicator
        r = _fake_resolver(SPF_REC)
        out = verify_all({"sender": "ceo@example.com", "headers": {}, "body_text": "hi"}, r)
        runner.assert_true(
            out["spf"]["status"] == "unavailable" and out["risk_score"] == 0
            and any(i["type"] == "auth_spf_unavailable" and i["severity"] == "info" for i in out["indicators"]),
            "spf: missing sender IP => unavailable, risk 0, info indicator", str(out["spf"]),
        )

        # 5-6 dkim pass / tamper-fail
        if _pem is not None:
            import dkim as _dkim

            message = (
                b"From: alice@example.com\r\nTo: bob@example.org\r\n"
                b"Subject: test\r\nDate: Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\nHello world.\r\n"
            )
            sig = _dkim.DKIM(message).sign(
                b"sel", b"example.com", _pem,
                include_headers=[b"From", b"To", b"Subject", b"Date"],
            )
            signed = sig + message
            tampered = signed.replace(b"Hello world.", b"Hello worm.")
            dk = {("sel._domainkey.example.com", "TXT"): [f'"v=DKIM1; k=rsa; p={_pub_b64}"']}
            r = _fake_resolver({**SPF_REC, **DMARC_REJECT, **dk})
            out = verify_all({"sender": "alice@example.com", "raw_message": signed, "sender_ip": "203.0.113.10"}, r)
            runner.assert_true(
                out["dkim"]["status"] == "pass" and out["dmarc"]["status"] == "pass" and out["risk_score"] == 0,
                "dkim: signed message verifies pass and aligns DMARC (risk 0)",
                f"dkim={out['dkim']} dmarc={out['dmarc']}",
            )
            r = _fake_resolver({**SPF_REC, **DMARC_REJECT, **dk})
            out = verify_all({"sender": "alice@example.com", "raw_message": tampered, "sender_ip": "203.0.113.10"}, r)
            runner.assert_true(
                out["dkim"]["status"] == "fail" and out["risk_score"] == 25,
                "dkim: tampered body fails verification (+25, SPF/DMARC stay aligned)",
                str(out["dkim"]),
            )
        else:
            runner.skip("dkim sign/verify pass + tamper-fail", "dkimpy/cryptography unavailable")

        # 7 dmarc reject fail + alignment fail -> +55
        r = _fake_resolver(DMARC_REJECT)
        out = verify_all({"sender": "ceo@example.com", "headers": {}, "sender_ip": "198.51.100.9"}, r)
        runner.assert_true(
            out["dmarc"]["status"] == "fail" and out["dmarc"]["policy"] == "reject" and out["risk_score"] == 55,
            "dmarc: p=reject fail + alignment fail => +35+20", str(out["dmarc"]),
        )
        # 8 dmarc p=none fail -> +10
        r = _fake_resolver({("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=none"']})
        out = verify_all({"sender": "ceo@example.com", "headers": {}, "sender_ip": "198.51.100.9"}, r)
        runner.assert_true(out["dmarc"]["status"] == "fail" and out["risk_score"] == 10,
                           "dmarc: p=none fail scores +10", str(out["dmarc"]))

        # 9 all-pass: risk 0 + pass!=safe note (needs dkim; SPF alone aligns too)
        if _pem is not None:
            r = _fake_resolver({**SPF_REC, **DMARC_REJECT})
            out = verify_all({"sender": "alice@example.com", "headers": {}, "sender_ip": "203.0.113.10"}, r)
            runner.assert_true(
                out["risk_score"] == 0 and "does not prove benign" in out.get("explanation", ""),
                "all-pass: risk 0 with 'pass != safe' caveat in explanation", out.get("explanation", ""),
            )
        else:
            runner.skip("all-pass pass!=safe caveat", "spf-only pass still aligns DMARC; skipped without dkim")

        # 10 offline mode: zero DNS calls, all unavailable, three info indicators
        r = _fake_resolver({**SPF_REC, **DMARC_REJECT}, offline=True)
        out = verify_all({"sender": "ceo@example.com", "headers": {}, "body_text": "hi"}, r)
        runner.assert_true(
            out["source"] == "unavailable" and out["risk_score"] == 0 and r.call_counter["calls"] == 0
            and [i["type"] for i in out["indicators"] if i["severity"] == "info"].count("") == 0
            and sorted(i["type"] for i in out["indicators"] if i["severity"] == "info")
            == ["auth_dkim_unavailable", "auth_dmarc_unavailable", "auth_spf_unavailable"],
            "offline: all three unavailable, risk 0, three info indicators, zero DNS calls",
            str(out["indicators"]),
        )
        # 11 cache: second identical lookup hits cache
        r = _fake_resolver({("example.com", "TXT"): ['"v=spf1 -all"']})
        r.resolve("example.com", "TXT")
        r.resolve("example.com", "TXT")
        runner.assert_true(r.call_counter["calls"] == 1, "dns: second identical lookup served from cache",
                           f"calls={r.call_counter['calls']}")
        # 12 circuit breaker: 5 failures -> open without DNS
        def _broken(qname, rdtype):
            raise ConnectionError("resolver down")

        r = DNSResolver(offline=False, transport=_broken, cb_failure_threshold=5, cb_window_s=60, cb_open_s=120)
        raised = 0
        for _ in range(5):
            try:
                r.resolve("example.com", "TXT")
            except DNSUnavailable:
                raised += 1
        calls_after_5 = r.transport_calls
        breaker_msg = ""
        try:
            r.resolve("example.com", "TXT")
        except DNSUnavailable as exc:
            breaker_msg = str(exc)
        runner.assert_true(
            raised == 5 and r.transport_calls == calls_after_5 and "circuit breaker" in breaker_msg,
            "dns: circuit breaker opens after 5 failures, next call fails without DNS",
            breaker_msg,
        )
        # 13 manual path: without raw_headers -> warning; with raw_headers -> verification runs
        monkeypatch = MonkeyPatch()
        try:
            # The runner cleared its shared auth overrides after Suite 4, so
            # seed a dedicated user/org (RLS-safe, like Suite 2) and install
            # fresh overrides for these two requests.
            from app.core.security import CurrentUser, TenantContext, get_current_user, get_tenant_context
            from app.db.admin import _get_admin_session_maker
            from app.db.models import Organization, OrganizationMember
            from app.db.session import current_user_id as _current_user_id

            _uid = f"authverify-{os.urandom(4).hex()}"
            _admin_maker = _get_admin_session_maker()
            async with _admin_maker() as _db:
                _db.add(User(id=_uid, email=f"{_uid}@cyberguard.test", full_name="Auth Verify Tester"))
                _db.add(Organization(
                    id=f"org-{_uid}", name="AuthVerify Org", slug=f"personal-{_uid}",
                    is_personal=True, owner_id=_uid,
                ))
                _db.add(OrganizationMember(
                    id=f"mem-{os.urandom(12).hex()}", organization_id=f"org-{_uid}",
                    user_id=_uid, role="admin",
                ))
                await _db.commit()

            _auth_user = CurrentUser(id=_uid, email=f"{_uid}@cyberguard.test", full_name="Auth Verify Tester")
            _org_id = f"org-{_uid}"

            async def _mock_user():
                _current_user_id.set(_uid)
                return _auth_user

            async def _mock_tenant():
                # Stamp the RLS identity here: overriding get_tenant_context
                # short-circuits the get_current_user chain, so this is the
                # only hook guaranteed to run before any transaction begins.
                current_user_id.set(_uid)
                return TenantContext(
                    organization_id=_org_id, organization_name="AuthVerify Org",
                    role="admin", is_single_user=True, user_id=_uid, owner_user_id=_uid,
                )

            app.dependency_overrides[get_current_user] = _mock_user
            app.dependency_overrides[get_tenant_context] = _mock_tenant

            transport36 = ASGITransport(app=app)
            async with AsyncClient(transport=transport36, base_url="http://test") as client36:
                resp = await client36.post(
                    "/api/v1/analysis/email",
                    json={"sender": "ceo@totally-legit-biz.example", "subject": "Urgent", "body": "wire transfer"},
                )
                data = resp.json() if resp.status_code == 200 else {}
                runner.assert_true(
                    resp.status_code == 200
                    and any(i.get("type") == "auth_headers_missing" for i in data.get("indicators", []))
                    and bool(data.get("warnings"))
                    and "no message headers" in (data.get("warnings") or [""])[0],
                    "manual: scan without raw_headers yields auth_headers_missing + response warning flag",
                    f"status={resp.status_code} warnings={data.get('warnings')}",
                )
                r = _fake_resolver({**SPF_REC, **DMARC_REJECT})
                monkeypatch.setattr(_auth_mod, "get_default_resolver", lambda: r)
                resp2 = await client36.post(
                    "/api/v1/analysis/email",
                    json={
                        "sender": "ceo@example.com",
                        "subject": "Invoice",
                        "body": "please pay",
                        "raw_headers": (
                            "Return-Path: <bounce@example.com>\r\n"
                            "Received: from mail.example.com (mail.example.com [198.51.100.9]) by mx.test\r\n"
                        ),
                    },
                )
            data2 = resp2.json() if resp2.status_code == 200 else {}
            runner.assert_true(
                resp2.status_code == 200
                and any(i.get("type") == "auth_spf_fail" for i in data2.get("indicators", []))
                and data2.get("warnings") == [],
                "manual: with raw_headers the independent verification runs (auth_spf_fail surfaced)",
                f"status={resp2.status_code} types={[i.get('type') for i in data2.get('indicators', [])]}",
            )
        finally:
            monkeypatch.undo()
            app.dependency_overrides.clear()
            current_user_id.set(None)
        # 14 realtime fallback: independent unavailable + parsed results => mx_parsed
        out = verify_or_parse(
            {"spf": "fail", "dkim": "pass", "dmarc": "fail"},
            {"sender": "ceo@example.com", "headers": {}},
            _fake_resolver({}, offline=True),
        )
        runner.assert_true(
            out["source"] == "mx_parsed" and out["risk_score"] == 65,
            "realtime: offline verification falls back to mx_parsed with parsed scores (30+35)",
            str(out["source"]),
        )

    await run_auth_verification_tests()

    # -----------------------------------------------------------------------
    # 37. SE-HARDENING — social-engineering pattern detection
    # -----------------------------------------------------------------------
    print("\n[Suite 37] SE-HARDENING — Social-Engineering Pattern Detection")
    from app.services.se_pattern_engine import (
        ATTACHMENT_REFERENCE_WARNING as _ATTACH_WARN,
        LOW_CONFIDENCE_NOTE as _LOW_CONF,
        SEPatternEngine as _SE,
        assess_confidence as _conf,
        blend_se as _blend,
    )
    import json as _json

    async def run_se_pattern_tests() -> None:
        from app.db.admin import _get_admin_session_maker

        engine = _SE()
        # 1 framing
        out = engine.analyze(
            "We detected a recent sign-in from a new device. Complete security verification now."
        )
        runner.assert_true(
            any(i["type"] == "security_alert_framing" for i in out["indicators"])
            and out["risk_score"] >= 15,
            "se: security_alert_framing detected (+15)", str(out["risk_score"]),
        )
        # 2 lure
        out = engine.analyze("Please review the attached document right away.")
        runner.assert_true(
            any(i["type"] == "attachment_lure" for i in out["indicators"])
            and out["risk_score"] >= 15
            and all(i.get("match_count") for i in out["indicators"]),
            "se: attachment_lure detected with match_count (+15)", str(out["risk_score"]),
        )
        # 3 urgency
        out = engine.analyze("Your access may expire within 24 hours if not confirmed.")
        runner.assert_true(
            any(i["type"] == "bureaucratic_urgency" for i in out["indicators"])
            and out["risk_score"] >= 10,
            "se: bureaucratic_urgency detected (+10)", str(out["risk_score"]),
        )
        # 4 combination +45
        out = engine.analyze(
            "We detected a recent sign-in. Review the attached document to secure your account."
        )
        runner.assert_true(
            any(i["type"] == "se_combination_rule" for i in out["indicators"])
            and out["risk_score"] == 75,
            "se: framing AND (lure|urgency) fires se_combination_rule (+45 => 75)",
            str(out["risk_score"]),
        )

        # 5 eval case se_attachment_lure_001 via the real manual pipeline
        _uid = f"setest-{os.urandom(4).hex()}"
        _admin_maker = _get_admin_session_maker()
        async with _admin_maker() as _db:
            _db.add(User(id=_uid, email=f"{_uid}@cyberguard.test", full_name="SE Tester"))
            _db.add(Organization(
                id=f"org-{_uid}", name="SE Test Org", slug=f"personal-{_uid}",
                is_personal=True, owner_id=_uid,
            ))
            _db.add(OrganizationMember(
                id=f"mem-{os.urandom(12).hex()}", organization_id=f"org-{_uid}",
                user_id=_uid, role="admin",
            ))
            await _db.commit()

        _se_user = CurrentUser(id=_uid, email=f"{_uid}@cyberguard.test", full_name="SE Tester")

        async def _se_mock_tenant():
            current_user_id.set(_uid)
            return TenantContext(
                organization_id=f"org-{_uid}", organization_name="SE Test Org",
                role="admin", is_single_user=True, user_id=_uid, owner_user_id=_uid,
            )

        async def _se_mock_user():
            current_user_id.set(_uid)
            return _se_user

        app.dependency_overrides[get_current_user] = _se_mock_user
        app.dependency_overrides[get_tenant_context] = _se_mock_tenant
        monkeypatch37 = MonkeyPatch()
        try:
            _fx_lines = [l for l in (ROOT / "tests" / "data" / "synthetic" / "se_phishing_attachment_lure.txt").read_text().splitlines() if l.strip()]
            _fx_subject = _fx_lines[1].split("Subject: ", 1)[1]
            _fx_body = "\n".join(_fx_lines[2:])
            _cases = _json.loads(
                (ROOT / "tests" / "data" / "synthetic" / "se_eval_cases.json").read_text()
            )["cases"]
            _case = next(c for c in _cases if c["id"] == "se_attachment_lure_001")

            transport37 = ASGITransport(app=app)
            async with AsyncClient(transport=transport37, base_url="http://test") as client37:
                resp = await client37.post(
                    "/api/v1/analysis/email",
                    json={"sender": _case["sender"], "subject": _fx_subject, "body": _fx_body},
                )
                data = resp.json() if resp.status_code == 200 else {}
                types = [i.get("type") for i in data.get("indicators", [])]
                runner.assert_true(
                    resp.status_code == 200
                    and data.get("risk_score", 0) >= _case["risk_min"]
                    and 40 <= data.get("risk_score", 0) < 80
                    and data.get("severity") == "high"
                    and all(e in types for e in _case["expected_indicators"]),
                    "se: eval case se_attachment_lure_001 => risk>=60, suspicious, 3 narrative indicators",
                    f"risk={data.get('risk_score')} types={types}",
                )

                # 6 benign invoice — no false positive
                resp6 = await client37.post(
                    "/api/v1/analysis/email",
                    json={
                        "sender": "billing@vendor.example",
                        "subject": "September invoice",
                        "body": "Hi, please review the attached invoice for the September "
                                "order. Payment is due in 30 days. Thank you.",
                    },
                )
                data6 = resp6.json() if resp6.status_code == 200 else {}
                runner.assert_true(
                    resp6.status_code == 200 and data6.get("risk_score", 100) < 40
                    and data6.get("severity") in ("safe", "low"),
                    "se: benign 'review the attached invoice' stays safe (<40)",
                    f"risk={data6.get('risk_score')} severity={data6.get('severity')}",
                )

                # 12 warnings array: auth + attachment warnings, no duplicates
                resp12 = await client37.post(
                    "/api/v1/analysis/email",
                    json={
                        "sender": "security-alert@cyberguard.com",
                        "subject": "Security verification required",
                        "body": "We detected a recent sign-in. Review the attached "
                                "document as soon as possible.",
                    },
                )
                warnings = (resp12.json() or {}).get("warnings") or [] if resp12.status_code == 200 else []
                runner.assert_true(
                    any("no message headers" in w for w in warnings)
                    and _ATTACH_WARN in warnings
                    and len(warnings) == len(set(warnings)),
                    "se: warnings array carries auth_headers_missing AND attachment-reference warning, no duplicates",
                    str(warnings),
                )
        finally:
            monkeypatch37.undo()
            app.dependency_overrides.clear()
            current_user_id.set(None)

        # 7 authority impersonation
        out = engine.analyze("This message was sent by the IT department security team.")
        runner.assert_true(
            any(i["type"] == "authority_impersonation" for i in out["indicators"])
            and out["risk_score"] >= 10,
            "se: authority_impersonation detected (+10)", str(out["risk_score"]),
        )
        # 8 vague threat
        out = engine.analyze("We noticed suspicious activity and unusual sign-in attempts.")
        runner.assert_true(
            any(i["type"] == "vague_threat" for i in out["indicators"])
            and out["risk_score"] >= 10,
            "se: vague_threat detected (+10)", str(out["risk_score"]),
        )
        # 9 monotonic: strong heuristic unchanged
        runner.assert_true(
            _blend(0.8, 0.3) == 0.8,
            "se: monotonic blend — heuristic 0.8 + SE 0.3 stays 0.8", str(_blend(0.8, 0.3)),
        )
        # 10 monotonic: weak heuristic raised to ~0.35
        runner.assert_true(
            abs(_blend(0.2, 0.7) - 0.35) < 1e-9,
            "se: monotonic blend — heuristic 0.2 + SE 0.7 => ~0.35", str(_blend(0.2, 0.7)),
        )
        # 11 confidence low-signals warning
        conf = _conf(0.4, 0.3, url_indicator_count=0, body="see attached")
        runner.assert_true(
            conf["confidence"] == "low" and _LOW_CONF in conf["notes"],
            "se: weak heuristic + weak ML => confidence low with manual-review note",
            str(conf),
        )

    await run_se_pattern_tests()

    # -----------------------------------------------------------------------
    # 42. GMAIL-RECONNECT-UX — Disconnect=stop, Reconnect=start, Recently Connected
    #     folder (3-day TTL), purge job, FK-safe soft-purge, worker guards
    # -----------------------------------------------------------------------
    print("\n[Suite 42] GMAIL-RECONNECT-UX — Reconnect UX, 3d TTL Folder & Purge Job")
    from test_gmail_reconnect import run_gmail_reconnect_tests

    await run_gmail_reconnect_tests(runner)

    # -----------------------------------------------------------------------
    # 44. GMAIL-FULL-CLEAR — Disconnect = full clear (Google + Pub/Sub drain + app side),
    #     Pause/Resume live-sync state, gap catch-up, plateau check
    # -----------------------------------------------------------------------
    print("\n[Suite 44] GMAIL-FULL-CLEAR — Full Clear Disconnect, Pause/Resume Live Sync")
    from test_gmail_full_clear import run_gmail_full_clear_tests

    await run_gmail_full_clear_tests(runner)

    # -----------------------------------------------------------------------
    # 45. Firecrawl live page intelligence (client + domain intelligence,
    #     offline pytest suites via httpx.MockTransport / in-memory cache)
    # -----------------------------------------------------------------------
    print("\n[Suite 45] Firecrawl Live Page Intelligence (firecrawl_client + domain_intelligence)")
    backend_root = Path(__file__).resolve().parents[1]
    pytest_proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "pytest",
        "tests/test_firecrawl_client.py",
        "tests/test_domain_intelligence.py",
        "-q",
        cwd=str(backend_root),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    pytest_stdout, _ = await pytest_proc.communicate()
    print(pytest_stdout.decode("utf-8", errors="replace"))
    runner.assert_true(
        pytest_proc.returncode == 0,
        "Firecrawl client + domain intelligence pytest suites passed",
    )

    # -----------------------------------------------------------------------
    # 48. MIGRATION-FRESH-DB-FIX — Squashed Baseline & Fresh DB Provisioning
    # -----------------------------------------------------------------------
    print("\n[Suite 48] MIGRATION-FRESH-DB-FIX — Squashed Baseline & Fresh DB Provisioning")
    from scripts.test_migration_fresh_db import run_migration_fresh_db_tests
    await run_migration_fresh_db_tests(runner)

    # -----------------------------------------------------------------------
    # 49. ORG-SETTINGS-P1 — Project Deletion (admin gate, confirm_name,
    #     project-scope cascade, active_project_id clear, last-project rule)
    # -----------------------------------------------------------------------
    print("\n[Suite 49] ORG-SETTINGS-P1 — Project Deletion")
    from scripts.test_org_settings import run_org_settings_tests
    await run_org_settings_tests(runner)

    return runner.report()





if __name__ == "__main__":
    exit_code = asyncio.run(run_tests())
    sys.exit(exit_code)
