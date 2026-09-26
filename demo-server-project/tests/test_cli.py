"""CLI tests (S5): ship-once with mock transport, responses, counts."""

import json

import httpx
import pytest

import demo_server.__main__ as cli_main
from demo_server.__main__ import main
from demo_server.config import load_config
from demo_server.shipper import GatewayShipper
from demo_server.store import ResponseStore

SECRET = "cg_org_cli_test_key"
ENV = {"CYBERGUARD_PROJECT_SLUG": "cli-proj", "CYBERGUARD_MASTER_KEY": SECRET}


def payload_file(tmp_path, payloads):
    path = tmp_path / "payloads.json"
    path.write_text(json.dumps(payloads), encoding="utf-8")
    return str(path)


def patched_components(monkeypatch, tmp_path, handler):
    """Redirect build_components to a shipper on a mock transport."""
    config = load_config({**ENV, "STORE_PATH": str(tmp_path / "responses.db")})
    store = ResponseStore(tmp_path / "responses.db")
    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=5)
    shipper = GatewayShipper(config, store, client=client, sleeper=lambda _s: None)
    monkeypatch.setattr(cli_main, "build_components", lambda env=None: (config, store, shipper))
    return config, store, shipper


def test_ship_once_success_table(tmp_path, monkeypatch, capsys):
    def handler(request):
        return httpx.Response(200, json={"event_id": "e1", "risk_score": 90, "severity": "critical", "verdict": "pending_review"})

    patched_components(monkeypatch, tmp_path, handler)
    path = payload_file(
        tmp_path,
        [{"name": "net-critical", "action": "analyze_network", "data": {"flows": []}}],
    )
    code = main(["ship-once", "--file", path])
    out = capsys.readouterr().out

    assert code == 0
    assert "analyze_network" in out and "200" in out and "critical" in out
    # key never printed
    assert SECRET not in out


def test_ship_once_mixed_results_exit_code(tmp_path, monkeypatch, capsys):
    def handler(request):
        body = json.loads(request.read())
        if body["action"] == "analyze_ato":
            return httpx.Response(403, json={"detail": "Viewer keys cannot perform analysis actions"})
        return httpx.Response(200, json={"event_id": "e2", "risk_score": 15, "severity": "low", "verdict": "pending_review"})

    patched_components(monkeypatch, tmp_path, handler)
    path = payload_file(
        tmp_path,
        [
            {"action": "analyze_network", "data": {"flows": []}},
            {"action": "analyze_ato", "data": {"events": []}},
        ],
    )
    code = main(["ship-once", "--file", path])
    out = capsys.readouterr().out

    assert code == 1  # one payload failed
    assert "403" in out and "200" in out


def test_ship_once_missing_file_errors(tmp_path, monkeypatch, capsys):
    patched_components(monkeypatch, tmp_path, lambda request: httpx.Response(200, json={}))
    with pytest.raises(OSError):
        main(["ship-once", "--file", str(tmp_path / "nope.json")])


def test_responses_and_counts(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CYBERGUARD_PROJECT_SLUG", "cli-proj")
    monkeypatch.setenv("CYBERGUARD_MASTER_KEY", SECRET)
    monkeypatch.setenv("STORE_PATH", str(tmp_path / "responses.db"))

    store = ResponseStore(tmp_path / "responses.db")
    store.append("analyze_network", {}, "200", {"risk_score": 90})
    store.append("analyze_ato", {}, "503", None, 1, "HTTP 503")
    store.close()

    assert main(["responses", "--limit", "10"]) == 0
    out = capsys.readouterr().out
    assert "analyze_network" in out and "analyze_ato" in out

    assert main(["responses", "--action", "analyze_ato", "--min-status", "200"]) == 0
    out = capsys.readouterr().out
    assert "analyze_ato" in out and "analyze_network" not in out

    assert main(["counts"]) == 0
    out = capsys.readouterr().out
    assert "total attempts: 2" in out and "status 200: 1" in out


def test_config_error_exits_2(capsys):
    code = main(["counts"])  # no env vars set -> fail fast
    assert code == 2
    err = capsys.readouterr().err
    assert "configuration error" in err
