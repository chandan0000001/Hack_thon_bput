"""Attack Campaign runner and reporting (SIM-1).

Executes realistic multi-stage threat scenarios (credential stuffing,
data exfiltration spikes, C2 beacon waves) against the CyberGuard gateway.
Supports timescale acceleration, attacker IP overrides, and reports
stage-by-stage severity matches and closed-loop auto-enforcement verdicts.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .shipper import GatewayShipper, ShipResult


@dataclass
class CampaignStage:
    name: str
    action: str
    expected_severity: str
    delay_s: float
    payload_builder: Callable[[str | None], dict[str, Any]]
    description: str = ""

    def build_payload(self, attacker_ip: str | None = None) -> dict[str, Any]:
        return self.payload_builder(attacker_ip)


@dataclass
class StageResult:
    stage_name: str
    action: str
    attempts: int
    status: str
    severity: str
    expected_severity: str
    verdict: str
    risk_score: int | None
    blocked_matched: bool
    latency_ms: int | None
    error: str | None
    ok: bool


@dataclass
class CampaignSummary:
    campaign_name: str
    attacker_ip: str | None
    timescale: float
    total_stages: int
    succeeded: int
    failed: int
    auto_blocked_count: int
    elapsed_s: float
    results: list[StageResult] = field(default_factory=list)

    @property
    def all_matched_expected_severity(self) -> bool:
        return all(r.severity.lower() == r.expected_severity.lower() for r in self.results if r.ok)

    @property
    def all_auto_blocked(self) -> bool:
        return len(self.results) > 0 and all(
            r.verdict == "blocked_permanently" and r.blocked_matched for r in self.results if r.ok
        )


# --- Payload Builders ---

def _build_cred_stuffing_burst(attacker_ip: str | None) -> dict[str, Any]:
    ip = attacker_ip or "198.51.100.44"
    return {
        "events": [
            {"user": "victim.user", "status": "failed", "timestamp": "2026-09-27T03:00:01Z", "ip": ip, "location": "Moscow", "device": "python-requests/2.28"},
            {"user": "victim.user", "status": "failed", "timestamp": "2026-09-27T03:00:04Z", "ip": ip, "location": "Moscow", "device": "python-requests/2.28"},
            {"user": "victim.user", "status": "failed", "timestamp": "2026-09-27T03:00:08Z", "ip": ip, "location": "Moscow", "device": "python-requests/2.28"},
            {"user": "victim.user", "status": "failed", "timestamp": "2026-09-27T03:00:12Z", "ip": ip, "location": "Moscow", "device": "python-requests/2.28"},
        ]
    }


def _build_cred_stuffing_impossible(attacker_ip: str | None) -> dict[str, Any]:
    ip = attacker_ip or "198.51.100.44"
    return {
        "events": [
            {"user": "d.mehta", "status": "success", "timestamp": "2026-09-27T03:00:00Z", "ip": "94.134.160.8", "location": "Berlin", "device": "macbook-pro"},
            {"user": "d.mehta", "status": "success", "timestamp": "2026-09-27T03:25:00Z", "ip": ip, "location": "Sydney", "device": "win-kiosk"},
        ]
    }


def _build_cred_stuffing_success(attacker_ip: str | None) -> dict[str, Any]:
    ip = attacker_ip or "198.51.100.44"
    return {
        "events": [
            {"user": "a.okafor", "status": "failed", "timestamp": "2026-09-27T03:10:01Z", "ip": ip, "location": "Amsterdam", "device": "python-requests/2.31"},
            {"user": "a.okafor", "status": "failed", "timestamp": "2026-09-27T03:10:05Z", "ip": ip, "location": "Amsterdam", "device": "python-requests/2.31"},
            {"user": "a.okafor", "status": "success", "timestamp": "2026-09-27T03:10:10Z", "ip": ip, "location": "Amsterdam", "device": "python-requests/2.31"},
        ]
    }


def _build_exfil_spike_probe(attacker_ip: str | None) -> dict[str, Any]:
    ip = attacker_ip or "198.51.100.99"
    return {
        "flows": [
            {"source_ip": "10.0.1.10", "dest_ip": ip, "port": 4444, "bytes_out": 4096, "protocol": "TCP", "duration_s": 120}
        ]
    }


def _build_exfil_spike_volume(attacker_ip: str | None) -> dict[str, Any]:
    ip = attacker_ip or "198.51.100.99"
    return {
        "flows": [
            {"source_ip": "10.0.2.20", "dest_ip": ip, "port": 8443, "bytes_out": 22500000, "protocol": "TCP", "duration_s": 600}
        ]
    }


def _build_exfil_spike_api(attacker_ip: str | None) -> dict[str, Any]:
    ip = attacker_ip or "198.51.100.99"
    return {
        "api_logs": [
            {"source_ip": ip, "endpoint": "/api/v1/telemetry", "status": 200}
            for _ in range(60)
        ]
    }


def _build_c2_beacon_wave_1(attacker_ip: str | None) -> dict[str, Any]:
    ip = attacker_ip or "198.51.100.23"
    return {
        "flows": [
            {"source_ip": "10.0.9.11", "dest_ip": ip, "port": 4444, "bytes_out": 2048, "protocol": "TCP", "duration_s": 60}
        ]
    }


def _build_c2_beacon_wave_2(attacker_ip: str | None) -> dict[str, Any]:
    ip = attacker_ip or "198.51.100.23"
    return {
        "flows": [
            {"source_ip": "10.0.9.12", "dest_ip": ip, "port": 8888, "bytes_out": 4096, "protocol": "TCP", "duration_s": 90}
        ]
    }


def _build_c2_beacon_wave_3(attacker_ip: str | None) -> dict[str, Any]:
    ip = attacker_ip or "198.51.100.23"
    return {
        "flows": [
            {"source_ip": "10.0.9.13", "dest_ip": ip, "port": 1337, "bytes_out": 8192, "protocol": "TCP", "duration_s": 120}
        ]
    }


# --- Campaign Definitions ---

@dataclass
class Campaign:
    name: str
    description: str
    stages: list[CampaignStage]


CAMPAIGNS: dict[str, Campaign] = {
    "cred_stuffing": Campaign(
        name="cred_stuffing",
        description="Multi-stage credential stuffing and account takeover sequence (failed burst, impossible travel, success after failures)",
        stages=[
            CampaignStage(
                name="stage1_failed_burst",
                action="analyze_ato",
                expected_severity="high",
                delay_s=0.5,
                payload_builder=_build_cred_stuffing_burst,
                description="Failed login burst against service account (brute force trigger)",
            ),
            CampaignStage(
                name="stage2_impossible_travel",
                action="analyze_ato",
                expected_severity="critical",
                delay_s=1.0,
                payload_builder=_build_cred_stuffing_impossible,
                description="Berlin -> Sydney impossible travel login anomaly (T1078 Valid Accounts)",
            ),
            CampaignStage(
                name="stage3_success_after_burst",
                action="analyze_ato",
                expected_severity="high",
                delay_s=0.5,
                payload_builder=_build_cred_stuffing_success,
                description="Scripted credential stuffing success after consecutive failures",
            ),
        ],
    ),
    "exfil_spike": Campaign(
        name="exfil_spike",
        description="Multi-stage attack lifecycle: C2 backdoor reconnaissance, 22MB+ exfiltration spike, and API abuse flood",
        stages=[
            CampaignStage(
                name="stage1_backdoor_probe",
                action="analyze_network",
                expected_severity="critical",
                delay_s=0.5,
                payload_builder=_build_exfil_spike_probe,
                description="C2 backdoor probe on suspicious port 4444",
            ),
            CampaignStage(
                name="stage2_volume_exfiltration",
                action="analyze_network",
                expected_severity="high",
                delay_s=1.0,
                payload_builder=_build_exfil_spike_volume,
                description="Massive outbound data exfiltration spike (22.5 MB, threshold 10 MB)",
            ),
            CampaignStage(
                name="stage3_api_rate_flood",
                action="analyze_network",
                expected_severity="high",
                delay_s=0.5,
                payload_builder=_build_exfil_spike_api,
                description="Automated API rate abuse burst (82 req/min, threshold 50)",
            ),
        ],
    ),
    "c2_beacon_wave": Campaign(
        name="c2_beacon_wave",
        description="Simulated command-and-control beacon wave across ports 4444, 8888, 1337 with parameterized attacker IP",
        stages=[
            CampaignStage(
                name="stage1_beacon_primary",
                action="analyze_network",
                expected_severity="critical",
                delay_s=0.5,
                payload_builder=_build_c2_beacon_wave_1,
                description="Primary C2 beacon flow on port 4444",
            ),
            CampaignStage(
                name="stage2_beacon_secondary",
                action="analyze_network",
                expected_severity="critical",
                delay_s=0.5,
                payload_builder=_build_c2_beacon_wave_2,
                description="Secondary C2 heartbeat flow on port 8888",
            ),
            CampaignStage(
                name="stage3_beacon_channel",
                action="analyze_network",
                expected_severity="critical",
                delay_s=0.5,
                payload_builder=_build_c2_beacon_wave_3,
                description="High-frequency staging channel beacon on port 1337",
            ),
        ],
    ),
}


def get_campaign(name: str) -> Campaign:
    if name not in CAMPAIGNS:
        valid = ", ".join(CAMPAIGNS.keys())
        raise KeyError(f"Unknown campaign '{name}'. Available: {valid}")
    return CAMPAIGNS[name]


def run_campaign(
    shipper: GatewayShipper,
    campaign: Campaign,
    timescale: float = 1.0,
    attacker_ip: str | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> CampaignSummary:
    """Execute each stage of a campaign with scaled delays and return summary."""
    t0 = time.monotonic()
    results: list[StageResult] = []
    auto_blocked_count = 0

    for i, stage in enumerate(campaign.stages):
        if i > 0 and stage.delay_s > 0:
            delay = stage.delay_s * timescale
            if delay > 0:
                sleeper(delay)

        t_stage = time.monotonic()
        payload = stage.build_payload(attacker_ip)
        ship_res = shipper.ship(stage.action, payload)
        stage_lat_ms = int((time.monotonic() - t_stage) * 1000)

        severity = ""
        verdict = ""
        risk_score = None
        blocked_matched = False

        if isinstance(ship_res.response, dict):
            severity = str(ship_res.response.get("severity", ""))
            verdict = str(ship_res.response.get("verdict", ""))
            risk_score = ship_res.response.get("risk_score")
            blocked_matched = bool(ship_res.response.get("blocked_indicator_matched", False))
            if blocked_matched or verdict == "blocked_permanently":
                auto_blocked_count += 1

        res = StageResult(
            stage_name=stage.name,
            action=stage.action,
            attempts=ship_res.attempts,
            status=ship_res.status or "transport_error",
            severity=severity,
            expected_severity=stage.expected_severity,
            verdict=verdict,
            risk_score=risk_score,
            blocked_matched=blocked_matched,
            latency_ms=stage_lat_ms,
            error=ship_res.error,
            ok=ship_res.ok,
        )
        results.append(res)


    elapsed = time.monotonic() - t0
    succeeded = sum(1 for r in results if r.ok)
    failed = sum(1 for r in results if not r.ok)

    return CampaignSummary(
        campaign_name=campaign.name,
        attacker_ip=attacker_ip,
        timescale=timescale,
        total_stages=len(campaign.stages),
        succeeded=succeeded,
        failed=failed,
        auto_blocked_count=auto_blocked_count,
        elapsed_s=elapsed,
        results=results,
    )


def format_campaign_table(summary: CampaignSummary) -> str:
    headers = ["STAGE", "ACTION", "STATUS", "SEVERITY", "EXP_SEV", "VERDICT", "BLOCKED_MATCH", "LAT_MS"]
    rows = []
    for r in summary.results:
        rows.append([
            r.stage_name,
            r.action,
            str(r.status),
            r.severity or "—",
            r.expected_severity,
            r.verdict or "—",
            "TRUE" if r.blocked_matched else "false",
            str(r.latency_ms) if r.latency_ms is not None else "—",
        ])

    widths = [max(len(h), *(len(row[i]) for row in rows)) if rows else len(h) for i, h in enumerate(headers)]
    lines = []
    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    lines.append(header_line)
    lines.append("-" * len(header_line))
    for row in rows:
        lines.append("  ".join(c.ljust(w) for c, w in zip(row, widths)))

    lines.append("")
    lines.append(f"Campaign      : {summary.campaign_name}")
    if summary.attacker_ip:
        lines.append(f"Attacker IP   : {summary.attacker_ip}")
    lines.append(f"Timescale     : {summary.timescale}")
    lines.append(f"Stages Shipped: {summary.total_stages} (Succeeded: {summary.succeeded}, Failed: {summary.failed})")
    lines.append(f"Auto-Blocked  : {summary.auto_blocked_count}/{summary.total_stages}")
    lines.append(f"Elapsed Time  : {summary.elapsed_s:.2f}s")
    sev_match = "ALL MATCHED" if summary.all_matched_expected_severity else "MISMATCH DETECTED"
    lines.append(f"Severity Match: {sev_match}")
    if summary.all_auto_blocked:
        lines.append("CLOSED-LOOP PROOF: ALL STAGES AUTO-BLOCKED BY REGISTERED INDICATOR")

    return "\n".join(lines)
