"""Replay tests (T5): re-ships stored 200 rows via mock transport."""

import httpx

from demo_server.config import load_config
from demo_server.replay import ReplayError, normalize_ts, replay
from demo_server.shipper import GatewayShipper
from demo_server.store import ResponseStore

ENV = {"CYBERGUARD_PROJECT_SLUG": "replay-proj", "CYBERGUARD_MASTER_KEY": "cg_org_replay_key"}


def make_shipper(tmp_path, handler):
    config = load_config(ENV)
    store = ResponseStore(tmp_path / "responses.db")
    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=5)
    shipper = GatewayShipper(config, store, client=client, sleeper=lambda _s: None)
    return shipper, store


def seed_calls(store: ResponseStore):
    store.append("analyze_network", {"action": "analyze_network", "data": {"flows": [{"id": 1}]}},
                 "200", {"event_id": "old-event-1", "risk_score": 90, "severity": "critical"}, 10)
    store.append("analyze_ato", {"action": "analyze_ato", "data": {"events": [{"id": 2}]}},
                 "200", {"event_id": "old-event-2", "risk_score": 75, "severity": "high"}, 11)
    store.append("analyze_ato", {"action": "analyze_ato", "data": {"events": []}},
                 "403", {"detail": "forbidden"}, 5, "HTTP 403")  # must NOT be replayed


def test_replay_reships_window_with_new_event_ids(tmp_path):
    seen_actions = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        body = json.loads(request.read())
        seen_actions.append(body["action"])
        return httpx.Response(200, json={"event_id": f"new-event-{len(seen_actions)}", "risk_score": 90})

    shipper, store = make_shipper(tmp_path, handler)
    seed_calls(store)
    before = store.counts()["total"]

    stats = replay(shipper, store, "2000-01-01T00:00", "2100-01-01T00:00")

    assert stats["replayed"] == 2  # 403 row skipped
    assert stats["succeeded"] == 2 and stats["success_rate"] == 1.0
    assert stats["old_event_ids"] == ["old-event-1", "old-event-2"]
    assert stats["new_event_ids"] == ["new-event-1", "new-event-2"]  # fresh ids from gateway
    assert seen_actions == ["analyze_network", "analyze_ato"]
    assert store.counts()["total"] == before + 2  # each replay = new store row
    shipper.close()


def test_replay_window_validation_and_empty(tmp_path):
    def handler(request):
        return httpx.Response(200, json={"event_id": "x"})

    shipper, store = make_shipper(tmp_path, handler)
    seed_calls(store)

    try:
        replay(shipper, store, "2100-01-01", "2000-01-01")
        raise AssertionError("expected ReplayError")
    except ReplayError as exc:
        assert "after to_ts" in str(exc)

    empty = replay(shipper, store, "2000-01-01T00:00", "2000-01-02T00:00")
    assert empty["replayed"] == 0 and empty["success_rate"] == 0.0

    assert normalize_ts("2026-09-26T10:30", "from") == "2026-09-26 10:30:00"
    assert normalize_ts("2026-09-26", "to") == "2026-09-26 00:00:00"
    shipper.close()
