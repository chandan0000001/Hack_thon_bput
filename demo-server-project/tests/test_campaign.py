"""Tests for attack campaign runner, registry, and CLI (SIM-1)."""

import json
import httpx
import pytest

import demo_server.__main__ as cli_main
from demo_server.__main__ import main
from demo_server.campaign import (
    CAMPAIGNS,
    Campaign,
    CampaignStage,
    format_campaign_table,
    get_campaign,
    run_campaign,
)
from demo_server.config import load_config
from demo_server.shipper import GatewayShipper
from demo_server.store import ResponseStore

SECRET = "cg_org_campaign_test_key"
ENV = {"CYBERGUARD_PROJECT_SLUG": "camp-proj", "CYBERGUARD_MASTER_KEY": SECRET}


def patched_components(monkeypatch, tmp_path, handler):
    """Wire components with a mock transport."""
    config = load_config({**ENV, "STORE_PATH": str(tmp_path / "responses.db")})
    store = ResponseStore(tmp_path / "responses.db")
    client = httpx.Client(transport=httpx.MockTransport(handler), timeout=5)
    shipper = GatewayShipper(config, store, client=client, sleeper=lambda _s: None)
    monkeypatch.setattr(cli_main, "build_components", lambda env=None: (config, store, shipper))
    return config, store, shipper


def test_01_campaign_registry():
    """1. Campaign registry contains cred_stuffing, exfil_spike, and c2_beacon_wave."""
    assert "cred_stuffing" in CAMPAIGNS
    assert "exfil_spike" in CAMPAIGNS
    assert "c2_beacon_wave" in CAMPAIGNS

    for name in ["cred_stuffing", "exfil_spike", "c2_beacon_wave"]:
        camp = get_campaign(name)
        assert len(camp.stages) >= 3
        assert all(isinstance(s, CampaignStage) for s in camp.stages)


def test_02_unknown_campaign_raises():
    """2. Unknown campaign raises KeyError."""
    with pytest.raises(KeyError, match="Unknown campaign 'non_existent'"):
        get_campaign("non_existent")


def test_03_cred_stuffing_payloads():
    """3. Cred stuffing campaign builds correct payloads and parameterizes attacker IP."""
    camp = get_campaign("cred_stuffing")
    stages = camp.stages

    # Default IP
    p1 = stages[0].build_payload(None)
    assert "events" in p1 and len(p1["events"]) >= 3
    assert p1["events"][0]["ip"] == "198.51.100.44"

    # Custom IP
    custom_ip = "192.168.10.99"
    p2 = stages[1].build_payload(custom_ip)
    assert p2["events"][1]["ip"] == custom_ip


def test_04_exfil_spike_payloads():
    """4. Exfiltration spike campaign builds flows and api_logs with custom IP."""
    camp = get_campaign("exfil_spike")
    custom_ip = "203.0.113.88"

    p1 = camp.stages[0].build_payload(custom_ip)
    assert p1["flows"][0]["dest_ip"] == custom_ip
    assert p1["flows"][0]["port"] == 4444

    p2 = camp.stages[1].build_payload(custom_ip)
    assert p2["flows"][0]["bytes_out"] > 10_000_000

    p3 = camp.stages[2].build_payload(custom_ip)
    assert p3["api_logs"][0]["source_ip"] == custom_ip


def test_05_c2_beacon_wave_payloads():
    """5. C2 beacon wave stages cover multiple ports with parameterized attacker IP."""
    camp = get_campaign("c2_beacon_wave")
    target_ip = "198.51.100.23"

    p1 = camp.stages[0].build_payload(target_ip)
    assert p1["flows"][0]["port"] == 4444 and p1["flows"][0]["dest_ip"] == target_ip

    p2 = camp.stages[1].build_payload(target_ip)
    assert p2["flows"][0]["port"] == 8888 and p2["flows"][0]["dest_ip"] == target_ip

    p3 = camp.stages[2].build_payload(target_ip)
    assert p3["flows"][0]["port"] == 1337 and p3["flows"][0]["dest_ip"] == target_ip


def test_06_timescale_and_delay_scaling(tmp_path):
    """6. Timescale parameter correctly scales stage delays."""
    delays_called = []

    def mock_sleeper(s):
        delays_called.append(s)

    config = load_config({**ENV, "STORE_PATH": str(tmp_path / "responses.db")})
    store = ResponseStore(tmp_path / "responses.db")

    def handler(request):
        return httpx.Response(200, json={"event_id": "e_test", "severity": "critical", "verdict": "pending_review"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    shipper = GatewayShipper(config, store, client=client, sleeper=lambda _s: None)

    camp = get_campaign("c2_beacon_wave")
    summary = run_campaign(shipper, camp, timescale=0.5, sleeper=mock_sleeper)

    assert summary.total_stages == 3
    assert len(delays_called) == 2  # Stage 2 and Stage 3 delays
    # Stage delay is 0.5 * 0.5 = 0.25
    for d in delays_called:
        assert d == pytest.approx(0.25, abs=0.01)


def test_07_run_campaign_severity_match(tmp_path):
    """7. Campaign run tracks severity matches from gateway responses."""
    config = load_config({**ENV, "STORE_PATH": str(tmp_path / "responses.db")})
    store = ResponseStore(tmp_path / "responses.db")

    def handler(request):
        body = json.loads(request.read())
        action = body.get("action")
        # Return expected severity matching the stage
        sev = "critical" if "network" in action else "high"
        return httpx.Response(200, json={"event_id": "e_ok", "severity": sev, "verdict": "pending_review", "risk_score": 90})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    shipper = GatewayShipper(config, store, client=client, sleeper=lambda _s: None)

    camp = get_campaign("c2_beacon_wave")
    summary = run_campaign(shipper, camp, timescale=1.0, sleeper=lambda _s: None)

    assert summary.succeeded == 3
    assert summary.failed == 0
    assert summary.all_matched_expected_severity is True
    table = format_campaign_table(summary)
    assert "ALL MATCHED" in table
    assert "c2_beacon_wave" in table


def test_08_run_campaign_auto_block_verdict(tmp_path):
    """8. Closed-loop auto-enforcement detects blocked_permanently and blocked_indicator_matched."""
    config = load_config({**ENV, "STORE_PATH": str(tmp_path / "responses.db")})
    store = ResponseStore(tmp_path / "responses.db")

    def handler(request):
        return httpx.Response(
            200,
            json={
                "event_id": "e_blocked",
                "severity": "critical",
                "verdict": "blocked_permanently",
                "blocked_indicator_matched": True,
                "matched_indicators": [{"type": "ip", "value": "198.51.100.23"}],
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    shipper = GatewayShipper(config, store, client=client, sleeper=lambda _s: None)

    camp = get_campaign("c2_beacon_wave")
    summary = run_campaign(shipper, camp, attacker_ip="198.51.100.23", sleeper=lambda _s: None)

    assert summary.auto_blocked_count == 3
    assert summary.all_auto_blocked is True
    table = format_campaign_table(summary)
    assert "CLOSED-LOOP PROOF" in table
    assert "TRUE" in table


def test_09_cli_campaign_list(capsys):
    """9. CLI campaign list prints all available campaigns and stages."""
    code = main(["campaign", "list"])
    out = capsys.readouterr().out
    assert code == 0
    assert "cred_stuffing" in out
    assert "exfil_spike" in out
    assert "c2_beacon_wave" in out


def test_10_cli_campaign_run_and_report(tmp_path, monkeypatch, capsys):
    """10. CLI campaign run and report execute cleanly through mock transport."""
    def handler(request):
        return httpx.Response(
            200,
            json={
                "event_id": "e_cli",
                "severity": "critical",
                "verdict": "blocked_permanently",
                "blocked_indicator_matched": True,
            },
        )

    patched_components(monkeypatch, tmp_path, handler)

    # 1. Run campaign
    code_run = main(["campaign", "run", "--name", "c2_beacon_wave", "--timescale", "0.1", "--attacker-ip", "10.99.99.99"])
    out_run = capsys.readouterr().out
    assert code_run == 0
    assert "CLOSED-LOOP PROOF" in out_run

    # 2. View report
    code_rep = main(["campaign", "report", "--limit", "5"])
    out_rep = capsys.readouterr().out
    assert code_rep == 0
    assert "blocked_permanently" in out_rep
    assert "TRUE" in out_rep
