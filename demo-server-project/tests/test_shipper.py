"""Shipper tests (S4): retry-on-5xx/transport, no-retry-on-4xx,
store-every-attempt, endpoint/auth contract, key never stored."""

import httpx
import pytest

from demo_server.config import load_config
from demo_server.shipper import GatewayShipper
from demo_server.store import TRANSPORT_ERROR, ResponseStore

SECRET = "cg_org_test_master_key_abc123"
ENV = {
    "CYBERGUARD_PROJECT_SLUG": "demo-proj",
    "CYBERGUARD_MASTER_KEY": SECRET,
    "STORE_PATH": "",  # unused; store is injected
}
EXPECTED_PATH = "/api/v1/p/demo-proj/gateway"


def make_shipper(tmp_path, handler, seen_requests, max_retries=3):
    def recording_handler(request: httpx.Request) -> httpx.Response:
        seen_requests.append(request)
        return handler(request)

    config = load_config({**ENV, "SHIP_MAX_RETRIES": str(max_retries)})
    store = ResponseStore(tmp_path / "responses.db")
    client = httpx.Client(transport=httpx.MockTransport(recording_handler), timeout=5)
    sleeps: list[float] = []
    shipper = GatewayShipper(config, store, client=client, sleeper=sleeps.append)
    return shipper, store, sleeps


def test_success_single_attempt_no_retry(tmp_path):
    seen = []

    def handler(request):
        return httpx.Response(200, json={"event_id": "e1", "risk_score": 90, "severity": "critical"})

    shipper, store, sleeps = make_shipper(tmp_path, handler, seen)
    result = shipper.ship("analyze_network", {"flows": []})

    assert result.ok and result.attempts == 1 and result.status == "200"
    assert result.response["severity"] == "critical"
    assert sleeps == []
    assert len(seen) == 1
    req = seen[0]
    assert req.url.path == EXPECTED_PATH
    assert req.headers["Authorization"] == f"Bearer {SECRET}"
    body = req.read()
    assert b'"action": "analyze_network"' in body or b'"action":"analyze_network"' in body

    rows = store.query()
    assert len(rows) == 1 and rows[0]["status"] == "200"
    shipper.close()


def test_4xx_never_retried(tmp_path):
    seen = []

    def handler(request):
        return httpx.Response(403, json={"detail": "Viewer keys cannot perform analysis actions"})

    shipper, store, sleeps = make_shipper(tmp_path, handler, seen)
    result = shipper.ship("analyze_network", {"flows": []})

    assert not result.ok
    assert result.attempts == 1 and result.status == "403"
    assert sleeps == [] and len(seen) == 1
    rows = store.query()
    assert len(rows) == 1 and rows[0]["status"] == "403"
    shipper.close()


def test_5xx_retried_until_success(tmp_path):
    seen = []
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] <= 2:
            return httpx.Response(503, json={"detail": "unavailable"})
        return httpx.Response(200, json={"event_id": "e2", "risk_score": 15, "severity": "low"})

    shipper, store, sleeps = make_shipper(tmp_path, handler, seen)
    result = shipper.ship("analyze_ato", {"events": []})

    assert result.ok and result.attempts == 3
    assert result.attempt_statuses == ["503", "503", "200"]
    # exponential backoff 0.5, 1
    assert sleeps == [0.5, 1.0]
    rows = store.query()
    assert len(rows) == 3  # every attempt stored
    assert [r["status"] for r in reversed(rows)] == ["503", "503", "200"]
    assert all(r["error"] == "HTTP 503" for r in rows if r["status"] == "503")
    shipper.close()


def test_5xx_retries_capped_at_max(tmp_path):
    seen = []

    def handler(request):
        return httpx.Response(500, text="boom")

    shipper, store, sleeps = make_shipper(tmp_path, handler, seen, max_retries=3)
    result = shipper.ship("analyze_log", {"level": "error"})

    assert not result.ok and result.attempts == 4  # 1 + 3 retries
    assert result.status == "500"
    assert result.attempt_statuses == ["500", "500", "500", "500"]
    assert len(store.query()) == 4
    assert sleeps == [0.5, 1.0, 2.0]
    shipper.close()


def test_transport_error_retried_and_stored(tmp_path):
    seen = []

    def handler(request):
        raise httpx.ConnectError("connection refused", request=request)

    shipper, store, sleeps = make_shipper(tmp_path, handler, seen, max_retries=2)
    result = shipper.ship("analyze_network", {"flows": []})

    assert not result.ok
    assert result.status is None
    assert result.attempts == 3  # 1 + 2 retries
    assert result.attempt_statuses == [TRANSPORT_ERROR] * 3
    assert "ConnectError" in result.error
    rows = store.query()
    assert len(rows) == 3
    assert all(r["status"] == TRANSPORT_ERROR for r in rows)
    assert all("ConnectError" in r["error"] for r in rows)
    assert all(r["response_json"] is None for r in rows)
    shipper.close()


def test_no_key_material_ever_lands_in_store(tmp_path):
    """S3/S4 invariant: db file + WAL never contain the Bearer key."""
    seen = []

    def handler(request):
        return httpx.Response(200, json={"event_id": "e3", "risk_score": 15, "severity": "low"})

    shipper, store, _ = make_shipper(tmp_path, handler, seen)
    result = shipper.ship("analyze_network", {"flows": [{"source_ip": "10.0.0.1"}]})
    assert result.ok
    shipper.close()

    db_path = tmp_path / "responses.db"
    for candidate in (db_path, tmp_path / "responses.db-wal", tmp_path / "responses.db-shm"):
        if candidate.exists():
            assert SECRET.encode() not in candidate.read_bytes()


def test_non_json_response_body_stored_as_text(tmp_path):
    seen = []

    def handler(request):
        return httpx.Response(200, content=b"<html>not json</html>", headers={"content-type": "text/html"})

    shipper, store, _ = make_shipper(tmp_path, handler, seen)
    result = shipper.ship("analyze_log", {})
    assert result.ok
    rows = store.query()
    assert "not json" in (rows[0]["response_json"] or "")
    shipper.close()
