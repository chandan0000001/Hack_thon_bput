"""HTTP API evaluation: sampled /analysis/* requests with latency stats."""

import time

import pytest

from tests.conftest import scale_n
from tests.datakit import synthetic_emails, synthetic_urls, synthetic_auth_events, synthetic_network_flows
from tests.datakit import synthetic_impersonation

pytestmark = [pytest.mark.http]


def _percentiles(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    values = sorted(values)
    def pct(p):
        idx = min(len(values) - 1, int(len(values) * p / 100))
        return values[idx]
    return {"n": len(values), "p50": pct(50), "p95": pct(95), "p99": pct(99)}


@pytest.mark.http
async def test_eval_http_analysis_endpoints(request, client, eval_report):
    """Sampled requests across /analysis/* via the ASGI client; asserts 200 +
    schema + severity present; records latency percentiles."""
    n = min(60, scale_n(request, 60))
    latencies: dict[str, list[float]] = {}
    counts: dict[str, int] = {}

    async def timed(endpoint, json_body):
        start = time.perf_counter()
        response = await client.post(endpoint, json=json_body)
        elapsed_ms = (time.perf_counter() - start) * 1000
        latencies.setdefault(endpoint, []).append(elapsed_ms)
        counts[endpoint] = counts.get(endpoint, 0) + 1
        return response

    emails = synthetic_emails(n // 3 + 1, seed=61)
    urls = synthetic_urls(n // 3 + 1, seed=63)
    auths = synthetic_auth_events(n // 3 + 1, seed=65)[: n // 3 + 1]
    flows = synthetic_network_flows(n // 3 + 1, seed=67)[: n // 3 + 1]

    ok = 0
    total = 0
    for row in emails[: n // 3]:
        p = row["payload"]
        r = await timed("/api/v1/analysis/email", {
            "sender": p["sender"], "subject": p["subject"], "body": p["body"],
        })
        total += 1
        assert r.status_code == 200, f"email analysis failed: {r.status_code} {r.text[:200]}"
        data = r.json()
        assert "severity" in data and "risk_score" in data and "explanation" in data
        ok += 1

    for row in urls[: n // 3]:
        r = await timed("/api/v1/analysis/url", {"url": row["payload"]})
        total += 1
        assert r.status_code == 200, f"url analysis failed: {r.status_code} {r.text[:200]}"
        data = r.json()
        assert "severity" in data
        ok += 1

    # Verify long URL (> 255 chars) does not violate DB varchar(255) constraint
    long_test_url = "https://example.com/login?token=" + "a" * 300
    r_long = await timed("/api/v1/analysis/url", {"url": long_test_url})
    total += 1
    assert r_long.status_code == 200, f"long url analysis failed: {r_long.status_code} {r_long.text[:200]}"
    data_long = r_long.json()
    assert len(data_long["title"]) <= 255
    ok += 1

    for row in auths[: n // 6]:
        r = await timed("/api/v1/analysis/account-takeover", {"events": row["payload"]})
        total += 1
        assert r.status_code == 200
        assert "severity" in r.json()
        ok += 1

    for row in flows[: n // 6]:
        r = await timed("/api/v1/analysis/network", {"flows": row["payload"], "api_logs": []})
        total += 1
        assert r.status_code == 200
        assert "severity" in r.json()
        ok += 1

    stats = {endpoint: _percentiles(vals) for endpoint, vals in latencies.items()}
    for endpoint, s in stats.items():
        eval_report.http[endpoint] = s

    eval_report.record_property("http_analysis_requests", requests=total, ok=ok)
    assert ok == total, f"{total - ok}/{total} analysis requests failed"
