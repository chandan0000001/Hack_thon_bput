"""Response store tests (S3): append/query/counts.

(Secret hygiene — "no key material ever lands in the store" — is asserted
end-to-end in test_shipper.py, which is the only component that knows the
key and the only one that must keep it out.)
"""

from demo_server.store import TRANSPORT_ERROR, ResponseStore


def test_append_and_query_roundtrip(tmp_path):
    store = ResponseStore(tmp_path / "responses.db")
    store.append("analyze_network", {"action": "analyze_network", "data": {"flows": []}}, "200", {"risk_score": 15}, 42)
    store.append("analyze_ato", {"action": "analyze_ato", "data": {}}, TRANSPORT_ERROR, None, 5, "ConnectError: refused")

    rows = store.query()
    assert len(rows) == 2
    assert rows[0]["action"] == "analyze_ato"  # most recent first
    assert rows[0]["status"] == TRANSPORT_ERROR
    assert rows[0]["error"].startswith("ConnectError")
    assert rows[1]["status"] == "200"
    assert rows[1]["latency_ms"] == 42
    store.close()


def test_query_filters(tmp_path):
    store = ResponseStore(tmp_path / "responses.db")
    store.append("analyze_network", {}, "200", {})
    store.append("analyze_network", {}, "503", {}, error="HTTP 503")
    store.append("analyze_ato", {}, TRANSPORT_ERROR, None, 1, "ConnectError")
    store.close()
    store = ResponseStore(tmp_path / "responses.db")

    assert len(store.query(action="analyze_network")) == 2
    assert all(r["action"] == "analyze_network" for r in store.query(action="analyze_network"))

    # min_status is an inclusive lower bound on numeric HTTP status;
    # transport_error rows (no numeric status) are excluded
    assert [r["status"] for r in store.query(min_status=500)] == ["503"]
    assert [r["status"] for r in store.query(min_status=200)] == ["503", "200"]
    assert len(store.query(min_status=100)) == 2
    assert len(store.query(min_status=200, action="analyze_ato")) == 0
    assert len(store.query(limit=1)) == 1
    store.close()


def test_counts(tmp_path):
    store = ResponseStore(tmp_path / "responses.db")
    for status in ("200", "200", "403", "503", TRANSPORT_ERROR):
        store.append("analyze_log", {}, status)
    counts = store.counts()
    assert counts == {"200": 2, "403": 1, "503": 1, TRANSPORT_ERROR: 1, "total": 5}
    store.close()
