"""Service endpoint tests (T3): health, traffic start/status/stop, metrics,
replay, responses — via FastAPI TestClient with a MockTransport shipper."""

import time

import httpx
import pytest
from fastapi.testclient import TestClient

from demo_server.config import load_config
from demo_server.scenarios import ScenarioBook
from demo_server.service import create_app
from demo_server.shipper import GatewayShipper
from demo_server.store import ResponseStore

SECRET = "cg_org_service_test_key"
ENV = {"CYBERGUARD_PROJECT_SLUG": "svc-proj", "CYBERGUARD_MASTER_KEY": SECRET}


@pytest.fixture()
def client_and_store(tmp_path):
    config = load_config(ENV)
    store = ResponseStore(tmp_path / "responses.db")
    shipper = GatewayShipper(
        config, store,
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(
                    200, json={"event_id": f"evt-{time.time_ns()}", "risk_score": 90, "severity": "critical"}
                )
            ),
            timeout=5,
        ),
        sleeper=lambda _s: None,
    )
    app = create_app(config, store=store, shipper=shipper, book=ScenarioBook(rng=__import__("random").Random(7)))
    yield TestClient(app), store
    shipper.close()


def test_health_and_responses(client_and_store):
    client, store = client_and_store
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["service"] == "demo-server"
    assert body["project_slug"] == "svc-proj"

    store.append("analyze_network", {}, "200", {"severity": "low"}, 9)
    r = client.get("/responses", params={"limit": 5})
    assert r.status_code == 200
    assert r.json()["count"] == 1
    assert r.json()["rows"][0]["action"] == "analyze_network"

    r = client.get("/responses", params={"min_status": 500})
    assert r.json()["count"] == 0


def test_traffic_start_status_stop_lifecycle(client_and_store):
    client, _store = client_and_store
    r = client.post("/traffic/start", json={"rate": 600, "duration": 0.02, "mix": "net=100"})
    assert r.status_code == 200
    job_id = r.json()["job_id"]
    assert r.json()["state"] == "running"

    # poll to completion (~12 ships at 0.1s interval)
    deadline = time.monotonic() + 15
    status = {}
    while time.monotonic() < deadline:
        status = client.get("/traffic/status", params={"job_id": job_id}).json()
        if status["state"] == "stopped":
            break
        time.sleep(0.1)
    assert status["state"] == "stopped", status
    assert status["events_shipped"] == 12  # 600/min * 0.02 min
    assert status["success_rate"] == 1.0
    assert status["last_event_ts"]
    assert set(status["by_action"]) == {"analyze_network"}

    # stop is idempotent even after natural completion
    r = client.post("/traffic/stop", json={"job_id": job_id})
    assert r.status_code == 200 and r.json()["stopped"] is True

    # unknown job -> 404
    assert client.get("/traffic/status", params={"job_id": "nope"}).status_code == 404
    assert client.post("/traffic/stop", json={"job_id": "nope"}).status_code == 404


def test_traffic_stop_interrupts_run(client_and_store):
    client, _store = client_and_store
    r = client.post("/traffic/start", json={"rate": 60, "duration": 10, "mix": "benign=100"})
    job_id = r.json()["job_id"]
    time.sleep(0.8)  # a few ships at ~1s interval
    r = client.post("/traffic/stop", json={"job_id": job_id})
    assert r.status_code == 200

    deadline = time.monotonic() + 10
    status = {}
    while time.monotonic() < deadline:
        status = client.get("/traffic/status", params={"job_id": job_id}).json()
        if status["state"] == "stopped":
            break
        time.sleep(0.1)
    assert status["state"] == "stopped"
    shipped = status["events_shipped"]
    assert 1 <= shipped < 60  # stopped well before the 10-min schedule
    time.sleep(1.5)  # grace: no further sends scheduled
    after = client.get("/traffic/status", params={"job_id": job_id}).json()
    assert after["events_shipped"] <= shipped + 1  # at most the in-flight send


def test_metrics_and_replay_endpoints(client_and_store):
    client, store = client_and_store
    store.append("analyze_network", {"action": "analyze_network", "data": {"flows": [{}]}},
                 "200", {"event_id": "old-1", "severity": "critical"}, 12)
    store.append("analyze_ato", {"action": "analyze_ato", "data": {"events": [{}]}},
                 "200", {"event_id": "old-2", "severity": "high"}, 22)

    m = client.get("/traffic/metrics").json()
    assert m["total"] == 2
    assert m["by_action"] == {"analyze_network": 1, "analyze_ato": 1}
    assert m["by_severity"]["critical"] == 1 and m["by_severity"]["high"] == 1
    assert m["latency_ms"]["p50"] == 12.0
    assert m["success_rate"] == 1.0

    r = client.post("/traffic/replay", json={"from_ts": "2000-01-01T00:00", "to_ts": "2100-01-01T00:00"})
    assert r.status_code == 200
    stats = r.json()
    assert stats["replayed"] == 2
    assert stats["succeeded"] == 2
    assert stats["old_event_ids"] == ["old-1", "old-2"]
    assert all(new != old for old, new in zip(stats["old_event_ids"], stats["new_event_ids"]))

    # invalid window -> 400
    r = client.post("/traffic/replay", json={"from_ts": "2100-01-01", "to_ts": "2000-01-01"})
    assert r.status_code == 400
    assert "after to_ts" in r.json()["detail"]
