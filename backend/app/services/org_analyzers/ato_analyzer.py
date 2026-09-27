"""Account Takeover (ATO) Analyzer thin wrapper around account_takeover_detector."""

from typing import Any
from app.services.account_takeover_detector import analyze_auth_log_heuristics
from app.services.scoring_service import get_severity

_SEVERITY_WEIGHTS = {"critical": 90, "high": 75, "medium": 50, "low": 25}


def analyze(payload: dict[str, Any], ctx: dict[str, Any] | None = None) -> dict[str, Any]:
    """Uniform analyzer interface for account takeover heuristics."""
    data = payload.get("data", payload) if isinstance(payload, dict) else payload

    # Normalize events list
    events: list[dict[str, Any]] = []
    if isinstance(data, dict):
        if "events" in data and isinstance(data["events"], list):
            events = data["events"]
        elif "user" in data:
            events = [data]
        elif isinstance(payload, dict) and "events" in payload and isinstance(payload["events"], list):
            events = payload["events"]
    elif isinstance(data, list):
        events = data

    indicators = analyze_auth_log_heuristics(events) if events else []

    if not indicators:
        risk_score = 15
        severity = "low"
    else:
        worst_sev = "low"
        for ind in indicators:
            sev = str(ind.get("severity", "low")).lower()
            if _SEVERITY_WEIGHTS.get(sev, 0) > _SEVERITY_WEIGHTS.get(worst_sev, 0):
                worst_sev = sev
        risk_score = _SEVERITY_WEIGHTS.get(worst_sev, 25)
        severity = get_severity(risk_score)

    mitre: list[dict[str, str]] = []
    if indicators:
        mitre.append({"id": "T1110", "name": "Brute Force"})
        if any("impossible" in str(ind.get("type", "")) for ind in indicators):
            mitre.append({"id": "T1078", "name": "Valid Accounts"})

        target_ip = None
        for ev in reversed(events):
            if isinstance(ev, dict) and ev.get("ip"):
                target_ip = str(ev["ip"])
                break
        if target_ip and worst_sev in ("critical", "high"):
            indicators.insert(0, {
                "type": "ip",
                "value": target_ip,
                "severity": worst_sev,
                "description": f"Anomalous source IP {target_ip}",
            })

    return {
        "risk_score": risk_score,
        "severity": severity,
        "indicators": indicators,
        "mitre": mitre,
        "engine": "account_takeover_detector",
        "available": True,
    }

