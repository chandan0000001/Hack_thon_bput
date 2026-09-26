"""Metrics tests (T4): SQL aggregates over the store."""

from demo_server.metrics import compute
from demo_server.store import TRANSPORT_ERROR, ResponseStore


def seed(store: ResponseStore):
    store.append("analyze_network", {}, "200", {"severity": "critical"}, 20)
    store.append("analyze_network", {}, "200", {"severity": "low"}, 40)
    store.append("analyze_ato", {}, "200", {"severity": "high"}, 10)
    store.append("analyze_ato", {}, "200", {"severity": "high"}, 30)
    store.append("analyze_ato", {}, "403", None, 5, "HTTP 403")
    store.append("analyze_log", {}, "503", None, 8, "HTTP 503")
    store.append("analyze_log", {}, TRANSPORT_ERROR, None, 2, "ConnectError")


def test_by_action_and_status_buckets(tmp_path):
    store = ResponseStore(tmp_path / "m.db")
    seed(store)
    m = compute(store)
    assert m["window"] == "last_60m"
    assert m["total"] == 7
    assert m["by_action"] == {"analyze_network": 2, "analyze_ato": 3, "analyze_log": 2}
    assert m["by_status"] == {"200": 4, "4xx": 1, "5xx": 1, "transport_error": 1}
    assert m["success_rate"] == round(4 / 7, 4)
    store.close()


def test_by_severity_and_latency_percentiles(tmp_path):
    store = ResponseStore(tmp_path / "m.db")
    seed(store)
    m = compute(store)
    assert m["by_severity"] == {"critical": 1, "high": 2, "medium": 0, "low": 1}
    # latency_ms is recorded for every attempt (7 rows): [2, 5, 8, 10, 20, 30, 40]
    assert m["latency_ms"]["p50"] == 10.0  # nearest-rank: 4th of 7
    assert m["latency_ms"]["p95"] == 40.0  # nearest-rank: 7th of 7
    store.close()


def test_metrics_empty_store(tmp_path):
    store = ResponseStore(tmp_path / "m.db")
    m = compute(store)
    assert m["total"] == 0
    assert m["success_rate"] == 0.0
    assert m["by_action"] == {}
    assert m["by_severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assert m["latency_ms"] == {"p50": None, "p95": None}
    store.close()
