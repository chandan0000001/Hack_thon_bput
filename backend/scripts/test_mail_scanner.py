"""Phase 3 suite: mailbox scanning, normalization & verbose results.

Covers:
- Gmail MIME normalization: raw Gmail API payload → NormalizedMessage
  (base64url bodies, plain vs HTML parts, headers, attachments metadata)
- scanning pipeline: known-bad message triggers phishing/url engines,
  HIGH/CRITICAL overall severity, populated indicators
- honest deferral: provider_operation_status is exactly "deferred_to_phase_4"
  for enforcement recommendations, and no_action_required for clean mail
- clean message stays safe (no fabricated indicators)
- API isolation: user A cannot scan/analyze user B's connector (404)
- scan endpoint honors RLS-owner filter with mocked Gmail transport
"""

import asyncio
import base64
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.core.security import get_current_user  # noqa: E402
from app.db.session import current_user_id  # noqa: E402
from _rls import as_user, create_user_admin  # noqa: E402
from app.main import app  # noqa: E402


class TestRunner:
    """Minimal runner matching scripts/run_all_tests.py conventions."""

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
        total = self.passed + self.failed
        print("\n" + "=" * 60)
        print(f"TEST RESULTS: {self.passed}/{total} passed")
        if self.failed == 0:
            print("\033[32mALL MAIL SCANNER TESTS PASSED SUCCESSFULLY!\033[0m")
        else:
            print(f"\033[31m{self.failed} TESTS FAILED!\033[0m")
        print("=" * 60 + "\n")
        return 0 if self.failed == 0 else 1


def _b64url(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def _gmail_payload(message_id: str) -> dict:
    """Raw Gmail API-shaped message (multipart, base64url bodies)."""
    return {
        "id": message_id,
        "threadId": "thread-1",
        "labelIds": ["INBOX", "UNREAD"],
        "internalDate": "1726100000000",
        "payload": {
            "mimeType": "multipart/alternative",
            "headers": [
                {"name": "From", "value": "PayPal Support <security@paypa1-secure.tk>"},
                {"name": "To", "value": "victim@example.com, cfo@example.com"},
                {"name": "Subject", "value": "URGENT: verify your account within 24 hours"},
                {"name": "Date", "value": "Wed, 11 Sep 2024 10:00:00 +0000"},
            ],
            "parts": [
                {
                    "mimeType": "text/plain",
                    "body": {
                        "data": _b64url(
                            "Dear customer,\n\nYour account is compromised! Visit "
                            "http://192.168.10.5/verify-login.php immediately to "
                            "confirm your password and billing details.\n\n- PayPal Support"
                        )
                    },
                },
                {
                    "mimeType": "text/html",
                    "body": {
                        "data": _b64url(
                            '<p>Click <a href="http://192.168.10.5/verify-login.php">here</a> to verify.</p>'
                        )
                    },
                },
                {
                    "mimeType": "application/pdf",
                    "filename": "invoice.pdf",
                    "body": {"size": 10240, "attachmentId": "att-1"},
                },
            ],
        },
    }


def _user(uid: str):
    return SimpleNamespace(id=uid, email=f"{uid}@cyberguard.test", full_name="Scan Tester", username=None, account_type="user")


async def run_mail_scanner_tests(runner: TestRunner) -> None:
    # ------------------------------------------------------------------
    # 12.1 Normalization: raw Gmail payload → NormalizedMessage
    # ------------------------------------------------------------------
    print("\n[Suite 12.1] Gmail MIME normalization")
    from app.schemas.email import NormalizedMessage

    from app.services.email_providers.gmail import gmail_provider

    message = gmail_provider._normalize("msg-1", _gmail_payload("msg-1"))
    runner.assert_true(isinstance(message, NormalizedMessage), "Payload maps to NormalizedMessage")
    runner.assert_true(message.provider_message_id == "msg-1", "Provider message id preserved")
    runner.assert_true(message.sender == "PayPal Support <security@paypa1-secure.tk>", "From header decoded")
    runner.assert_true(
        message.recipients == ["victim@example.com", "cfo@example.com"],
        "Recipients split and decoded",
        f"recipients={message.recipients}",
    )
    runner.assert_true("URGENT" in message.subject, "Subject decoded")
    runner.assert_true(
        message.body_text is not None and "verify-login.php" in message.body_text,
        "base64url text/plain body decoded",
    )
    runner.assert_true(
        message.body_html is not None and "verify-login.php" in message.body_html,
        "base64url text/html body decoded separately",
    )
    runner.assert_true(message.is_read is False, "UNREAD label mapped to is_read=False")
    runner.assert_true(
        len(message.attachments_meta) == 1
        and message.attachments_meta[0]["filename"] == "invoice.pdf"
        and message.attachments_meta[0]["mime_type"] == "application/pdf",
        "Attachment captured as metadata (no binary)",
    )
    runner.assert_true(message.received_at is not None, "internalDate mapped to received_at")

    # ------------------------------------------------------------------
    # 12.2 Scanning pipeline: known-bad message
    # ------------------------------------------------------------------
    print("\n[Suite 12.2] Scanning pipeline (known-bad message)")
    from app.services.mail_scanner import scan_message

    result = await scan_message(message)
    engines = {a.engine for a in result.feature_analyses}
    runner.assert_true("phishing_detector" in engines, "phishing_detector ran")
    runner.assert_true("url_detector" in engines, "url_detector ran")
    runner.assert_true("impersonation_detector" in engines, "impersonation_detector ran")
    url_analysis = next(a for a in result.feature_analyses if a.engine == "url_detector")
    runner.assert_true(len(url_analysis.indicators) > 0, "url_detector indicators populated")
    runner.assert_true(
        any(i.name == "ip_host" for i in url_analysis.indicators),
        "Raw-IP URL evidence captured",
    )
    runner.assert_true(
        result.overall_severity in ("high", "critical"),
        f"Overall severity HIGH/CRITICAL (got {result.overall_severity})",
    )
    runner.assert_true(result.overall_score >= 0.4, f"Overall score elevated ({result.overall_score})")
    runner.assert_true(len(result.overall_explanation) > 100, "Overall explanation is verbose")
    runner.assert_true(
        all(len(a.explanation) > 30 for a in result.feature_analyses),
        "Every engine provides a verbose explanation",
    )

    # ------------------------------------------------------------------
    # 12.3 Honest deferral + clean-message handling
    # ------------------------------------------------------------------
    print("\n[Suite 12.3] Honest Phase-4 deferral")
    runner.assert_true(
        result.recommended_action in ("quarantine", "block"),
        f"Critical message recommends an enforce tier (got {result.recommended_action})",
    )
    runner.assert_true(
        result.provider_operation_status == "deferred_to_phase_4",
        "Provider operation status is exactly deferred_to_phase_4",
    )
    runner.assert_true(
        result.provider_operation_detail is not None
        and "Phase 4" in (result.provider_operation_detail or ""),
        "Deferral detail explains the phase boundary",
    )

    clean = NormalizedMessage(
        provider_message_id="msg-clean",
        provider="gmail",
        sender="colleague@company.com",
        recipients=["me@company.com"],
        subject="Lunch tomorrow?",
        body_text="Want to grab lunch at the usual place tomorrow at noon?",
    )
    clean_result = await scan_message(clean)
    runner.assert_true(
        clean_result.overall_severity in ("safe", "low"),
        f"Benign mail stays safe/low (got {clean_result.overall_severity})",
    )
    runner.assert_true(
        clean_result.recommended_action == "pass",
        f"Benign mail recommends pass (got {clean_result.recommended_action})",
    )
    runner.assert_true(
        clean_result.provider_operation_status == "no_action_required",
        "Benign mail honestly reports no action required",
    )

    # ------------------------------------------------------------------
    # 12.4 API isolation + RLS-owner scanning path
    # ------------------------------------------------------------------
    print("\n[Suite 12.4] Scan API isolation (owner filter + RLS)")
    from sqlalchemy import select

    from app.db.models import EmailConnectorAccount
    from app.db.session import async_session_maker

    user_a_id = f"scan-a-{uuid.uuid4().hex[:8]}"
    user_b_id = f"scan-b-{uuid.uuid4().hex[:8]}"
    conn_a_id = f"scan-conn-a-{uuid.uuid4().hex[:6]}"
    conn_b_id = f"scan-conn-b-{uuid.uuid4().hex[:6]}"

    from cryptography.fernet import Fernet

    settings = get_settings = None  # noqa: F841 - readability no-op
    from app.core.config import get_settings

    settings = get_settings()
    _backup_key = settings.CONNECTOR_TOKEN_KEY
    settings.CONNECTOR_TOKEN_KEY = Fernet.generate_key().decode()

    from app.core.crypto import encrypt_secret

    await create_user_admin(id=user_a_id, email=f"{user_a_id}@gmail.com", is_single_user=True)
    await create_user_admin(id=user_b_id, email=f"{user_b_id}@gmail.com", is_single_user=True)

    async with as_user(user_a_id), async_session_maker() as db:
        db.add(
            EmailConnectorAccount(
                id=conn_a_id,
                owner_user_id=user_a_id,
                provider="gmail",
                provider_email=f"{user_a_id}@gmail.com",
                status="connected",
                access_token_enc=encrypt_secret("ya29-scan-test-access"),
                refresh_token_enc=encrypt_secret("1//scan-test-refresh"),
                access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
        )
        await db.commit()

    async with as_user(user_b_id), async_session_maker() as db:
        db.add(
            EmailConnectorAccount(
                id=conn_b_id,
                owner_user_id=user_b_id,
                provider="gmail",
                provider_email=f"{user_b_id}@gmail.com",
                status="connected",
                access_token_enc=encrypt_secret("ya29-scan-test-access-b"),
                refresh_token_enc=encrypt_secret("1//scan-test-refresh-b"),
                access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            )
        )
        await db.commit()

    # Mock Gmail transport: list + get_message return our fake inbox.
    from app.services.email_providers import gmail as gmail_module

    async def _fake_list(access_token: str, max_results: int = 50) -> list[dict]:
        return [{"id": "msg-1", "thread_id": "t1"}]

    async def _fake_get(access_token: str, message_id: str) -> NormalizedMessage:
        return gmail_provider._normalize(message_id, _gmail_payload(message_id))

    # Phase 4: the scan route now runs enforcement; stub the provider writes.
    async def _fake_quarantine(access_token: str, message_id: str, label: str) -> dict:
        return {"id": message_id}

    async def _fake_rule(access_token: str, sender_email: str, target_label: str) -> dict:
        return {"id": "filter-mock"}

    async def _fake_label_stub(access_token: str) -> str:
        return "Label_Q"

    _orig_list = gmail_provider.list_messages
    _orig_get = gmail_provider.get_message
    _orig_quarantine = gmail_provider.quarantine_message
    _orig_label = gmail_provider.ensure_quarantine_label
    _orig_rule = gmail_provider.create_sender_rule
    gmail_provider.list_messages = _fake_list
    gmail_provider.get_message = _fake_get
    gmail_provider.quarantine_message = _fake_quarantine
    gmail_provider.ensure_quarantine_label = _fake_label_stub
    gmail_provider.create_sender_rule = _fake_rule

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    try:
        def _override(uid):
            async def _fn():
                current_user_id.set(uid)  # RLS identity, as in production
                return _user(uid)

            return _fn

        app.dependency_overrides[get_current_user] = _override(user_a_id)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
            res = await client.post(f"/api/v1/connectors/{conn_a_id}/scan", json={"scan_recent": 5})
            runner.assert_true(res.status_code == 200, "Scan of own connector returns 200", f"status={res.status_code}")
            results = res.json()
            runner.assert_true(len(results) == 1, "Scan returns one result per message")
            runner.assert_true(
                results[0]["provider_operation_status"] == "success",
                "Scan API reports the real provider enforcement outcome (quarantined)",
                f"status={results[0]['provider_operation_status']} detail={results[0]['provider_operation_detail']}",
            )
            runner.assert_true(
                results[0]["overall_severity"] in ("high", "critical"),
                "Scan API verdict is HIGH/CRITICAL for the phishing fixture",
            )

            res_analysis = await client.get(f"/api/v1/connectors/{conn_a_id}/messages/msg-1/analysis")
            runner.assert_true(res_analysis.status_code == 200, "Analysis endpoint returns 200", f"status={res_analysis.status_code}")
            analysis = res_analysis.json()
            runner.assert_true(
                "scan" in analysis and "message" in analysis and analysis["message"]["body_text"],
                "Analysis returns full ScanResult + message body",
            )

            res_b_scan = await client.post(f"/api/v1/connectors/{conn_b_id}/scan", json={"scan_recent": 5})
            runner.assert_true(res_b_scan.status_code == 404, "User A cannot scan user B's connector (404)", f"status={res_b_scan.status_code}")
            res_b_analysis = await client.get(f"/api/v1/connectors/{conn_b_id}/messages/msg-1/analysis")
            runner.assert_true(res_b_analysis.status_code == 404, "User A cannot analyze user B's messages (404)")

        app.dependency_overrides[get_current_user] = _override(user_b_id)
        async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=60) as client:
            res_b_own = await client.post(f"/api/v1/connectors/{conn_b_id}/scan", json={"scan_recent": 5})
            runner.assert_true(res_b_own.status_code == 200, "Owner can scan their own connector")
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        gmail_provider.list_messages = _orig_list
        gmail_provider.get_message = _orig_get
        gmail_provider.quarantine_message = _orig_quarantine
        gmail_provider.ensure_quarantine_label = _orig_label
        gmail_provider.create_sender_rule = _orig_rule
        settings.CONNECTOR_TOKEN_KEY = _backup_key

    # 12.5 Frontend build is verified in the delivery pipeline (tsc + vite build).


async def _standalone() -> int:
    runner = TestRunner()
    print("\n📨 STARTING CYBERGUARD MAIL SCANNER TEST SUITE\n" + "=" * 60)
    await run_mail_scanner_tests(runner)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
