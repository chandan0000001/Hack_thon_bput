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
