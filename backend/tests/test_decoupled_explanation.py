"""Unit and integration tests for decoupled threat response (LLM-DECUPLE-T1).

Verifies that all analysis endpoints return core threat data immediately
(risk_score, severity, indicators, recommended_actions) with explanation: null,
without blocking synchronously on the LLM.
"""

import time
import pytest


@pytest.mark.asyncio
async def test_email_analysis_decoupled_explanation(client):
    """POST /analysis/email returns core data instantly with explanation=None."""
    start = time.perf_counter()
    resp = await client.post(
        "/api/v1/analysis/email",
        json={
            "sender": "attacker@paypal-spoofed.com",
            "subject": "Urgent: Verify your credentials",
            "body": "Your account has been locked. Verify immediately at http://192.168.1.1/login",
        },
    )
    duration = time.perf_counter() - start

    assert resp.status_code == 200
    data = resp.json()

    # Core threat response unblocked
    assert "risk_score" in data and isinstance(data["risk_score"], int)
    assert data["risk_score"] > 50
    assert data["severity"] in ("medium", "high", "critical")
    assert "indicators" in data and len(data["indicators"]) > 0
    assert "recommended_actions" in data and len(data["recommended_actions"]) > 0
    assert data["explanation"] is None

    # Verify fast execution (well under synchronous LLM timeout)
    assert duration < 3.0


@pytest.mark.asyncio
async def test_url_analysis_decoupled_explanation(client):
    """POST /analysis/url returns core data instantly with explanation=None."""
    start = time.perf_counter()
    resp = await client.post(
        "/api/v1/analysis/url",
        json={"url": "http://185.220.101.7/admin/login.php"},
    )
    duration = time.perf_counter() - start

    assert resp.status_code == 200
    data = resp.json()

    assert "risk_score" in data and isinstance(data["risk_score"], int)
    assert data["severity"] in ("medium", "high", "critical")
    assert "indicators" in data and len(data["indicators"]) > 0
    assert "recommended_actions" in data and len(data["recommended_actions"]) > 0
    assert data["explanation"] is None
    assert duration < 3.0


@pytest.mark.asyncio
async def test_impersonation_and_identity_fraud_decoupled(client):
    """POST /analysis/impersonation and /identity-fraud return immediately."""
    for path in ("/api/v1/analysis/impersonation", "/api/v1/analysis/identity-fraud"):
        start = time.perf_counter()
        resp = await client.post(
            path,
            json={
                "claimed_identity": "CEO John Doe",
                "message": "Urgent request: Purchase $500 gift cards immediately and send codes.",
            },
        )
        duration = time.perf_counter() - start

        assert resp.status_code == 200, f"{path} failed: {resp.text}"
        data = resp.json()

        assert "risk_score" in data
        assert "severity" in data
        assert "indicators" in data
        assert "recommended_actions" in data
        assert data["explanation"] is None
        assert duration < 3.0


@pytest.mark.asyncio
async def test_account_takeover_decoupled(client):
    """POST /analysis/account-takeover returns immediately with explanation=None."""
    start = time.perf_counter()
    resp = await client.post(
        "/api/v1/analysis/account-takeover",
        json={
            "events": [
                {"user": "alice", "ip": "1.1.1.1", "location": "US", "status": "failed", "timestamp": "2026-10-01T00:00:00Z"},
                {"user": "alice", "ip": "1.1.1.1", "location": "US", "status": "failed", "timestamp": "2026-10-01T00:00:01Z"},
                {"user": "alice", "ip": "2.2.2.2", "location": "RU", "status": "success", "timestamp": "2026-10-01T00:02:00Z"},
            ]
        },
    )
    duration = time.perf_counter() - start

    assert resp.status_code == 200
    data = resp.json()

    assert "risk_score" in data
    assert "severity" in data
    assert "indicators" in data
    assert "recommended_actions" in data
    assert data["explanation"] is None
    assert duration < 3.0


@pytest.mark.asyncio
async def test_network_decoupled(client):
    """POST /analysis/network returns immediately with explanation=None."""
    start = time.perf_counter()
    resp = await client.post(
        "/api/v1/analysis/network",
        json={
            "flows": [
                {"sourceIp": "192.168.1.50", "destIp": "10.0.0.1", "port": 4444, "bytesOut": 50000000, "protocol": "TCP"}
            ]
        },
    )
    duration = time.perf_counter() - start

    assert resp.status_code == 200
    data = resp.json()

    assert "risk_score" in data
    assert "severity" in data
    assert "indicators" in data
    assert "recommended_actions" in data
    assert data["explanation"] is None
    assert duration < 3.0


def test_generate_heuristic_fallback_explanation_format():
    """generate_heuristic_fallback_explanation builds structured fallback text."""
    from app.ai.llm_client import generate_heuristic_fallback_explanation

    exp = generate_heuristic_fallback_explanation(
        score=88,
        indicators=[
            {"type": "domain", "description": "Spoofed PayPal domain paypal-secure.co"},
            {"type": "keyword", "description": "High urgency language detected"},
        ],
        mitre_tags=[{"id": "T1566.002", "name": "Spearphishing Link"}],
        recommended_actions=["Quarantine email", "Block sender domain"],
        module="phishing",
    )

    assert "LLM timed out. Heuristic analysis: Risk score 88 driven by" in exp
    assert "Spoofed PayPal domain" in exp
    assert "MITRE tags: T1566.002 (Spearphishing Link)" in exp
    assert "Recommended action: Quarantine email, Block sender domain" in exp


@pytest.mark.asyncio
async def test_bg_explanation_timeout_with_mock_sleep():
    """Background task times out slow LLM (mock 20s) within timeout and saves heuristic fallback."""
    import asyncio
    from unittest.mock import patch
    import uuid
    from app.api.routes_analysis import _bg_generate_explanation
    from app.db.session import async_session_maker
    from app.db.models import Alert
    from sqlalchemy import select

    test_alert_id = f"test-timeout-alert-{uuid.uuid4()}"
    async with async_session_maker() as session:
        session.add(
            Alert(
                id=test_alert_id,
                title="Test Phishing Timeout",
                module="phishing",
                severity="high",
                risk_score=85,
                status="new",
                explanation=None,
                indicators=[{"type": "domain", "description": "Typosquat domain"}],
                recommended_actions=[],
                mitre=[],
            )
        )
        await session.commit()

    async def mock_slow_llm(*args, **kwargs):
        await asyncio.sleep(20.0)
        return {"explanation": "Normal LLM explanation"}

    start = time.perf_counter()
    with patch("app.api.routes_analysis.call_openrouter", side_effect=mock_slow_llm):
        # Run with short timeout to test timeout branch execution quickly
        await _bg_generate_explanation(
            alert_id=test_alert_id,
            system_prompt="sys",
            user_prompt="user",
            module="phishing",
            indicators=[{"type": "domain", "description": "Typosquat domain"}],
            raw_data={"sender": "attacker@evil.com"},
            risk_score=85,
            timeout=0.15,
        )
    elapsed = time.perf_counter() - start

    # Finished well before the 20-second sleep
    assert elapsed < 1.0

    async with async_session_maker() as session:
        res = await session.execute(select(Alert).where(Alert.id == test_alert_id))
        alert = res.scalar_one_or_none()
        assert alert is not None
        assert alert.explanation is not None
        assert alert.explanation.startswith("LLM timed out. Heuristic analysis:")
        assert "Risk score 85" in alert.explanation
        assert "Typosquat domain" in alert.explanation


@pytest.mark.asyncio
async def test_bg_explanation_timeout_error_fallback_persistence():
    """Direct TimeoutError triggers fallback and persists MITRE tags to DB."""
    import asyncio
    from unittest.mock import patch
    import uuid
    from app.api.routes_analysis import _bg_generate_explanation
    from app.db.session import async_session_maker
    from app.db.models import Alert
    from sqlalchemy import select

    test_alert_id = f"test-timeout-err-{uuid.uuid4()}"
    async with async_session_maker() as session:
        session.add(
            Alert(
                id=test_alert_id,
                title="Direct Timeout Test",
                module="account_takeover",
                severity="critical",
                risk_score=92,
                status="new",
                explanation=None,
                indicators=[{"type": "ip", "description": "Impossible travel login"}],
                recommended_actions=[],
                mitre=[],
            )
        )
        await session.commit()

    with patch("app.api.routes_analysis.call_openrouter", side_effect=asyncio.TimeoutError()):
        await _bg_generate_explanation(
            alert_id=test_alert_id,
            system_prompt="sys",
            user_prompt="user",
            module="account_takeover",
            indicators=[{"type": "ip", "description": "Impossible travel login"}],
            raw_data={"user": "admin"},
            risk_score=92,
            timeout=15.0,
        )

    async with async_session_maker() as session:
        res = await session.execute(select(Alert).where(Alert.id == test_alert_id))
        alert = res.scalar_one_or_none()
        assert alert is not None
        assert alert.explanation is not None
        assert "LLM timed out. Heuristic analysis:" in alert.explanation
        assert "Impossible travel login" in alert.explanation
        assert alert.mitre and len(alert.mitre) > 0


@pytest.mark.asyncio
async def test_pipeline_integration_with_slow_llm(client):
    """Pipeline returns 200 immediately, and background task saves fallback explanation."""
    import asyncio
    from unittest.mock import patch

    async def mock_sleep_llm(*args, **kwargs):
        await asyncio.sleep(20.0)

    # Patch call_openrouter to sleep 20s and wrap wait_for to short timeout
    with patch("app.api.routes_analysis.call_openrouter", side_effect=mock_sleep_llm), \
         patch("app.api.routes_analysis._bg_generate_explanation.__defaults__", (None, None, 0.1)):
        start = time.perf_counter()
        resp = await client.post(
            "/api/v1/analysis/email",
            json={
                "sender": "urgent-update@irs-gov-verify.com",
                "subject": "Tax Refund Pending Action",
                "body": "Your tax refund is ready. Click http://10.0.0.1/tax to claim.",
            },
        )
        duration = time.perf_counter() - start

        # Endpoint unblocked
        assert resp.status_code == 200
        data = resp.json()
        assert data["explanation"] is None
        assert duration < 2.0

        alert_id = data["id"]
        # Allow background task to complete timeout fallback
        await asyncio.sleep(0.3)

        alert_resp = await client.get(f"/api/v1/alerts/{alert_id}")
        assert alert_resp.status_code == 200
        alert_data = alert_resp.json()
        assert alert_data["explanation"] is not None
        assert "LLM timed out. Heuristic analysis:" in alert_data["explanation"]

