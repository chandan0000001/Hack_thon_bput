"""Network Analyzer thin wrapper around network_threat_detector."""

from typing import Any
from app.services.network_threat_detector import analyze_network_heuristics
from app.services.scoring_service import get_severity

_SEVERITY_WEIGHTS = {"critical": 90, "high": 75, "medium": 50, "low": 25}


def analyze(payload: dict[str, Any], ctx: dict[str, Any] | None = None) -> dict[str, Any]:
    """Uniform analyzer interface for network flow and API abuse heuristics."""
    data = payload.get("data", payload) if isinstance(payload, dict) else payload

    flows: list[dict[str, Any]] = []
    api_logs: list[dict[str, Any]] = []

    if isinstance(data, dict):
        if "flows" in data and isinstance(data["flows"], list):
            flows = data["flows"]
        if "api_logs" in data and isinstance(data["api_logs"], list):
            api_logs = data["api_logs"]
        if not flows and not api_logs:
            if "source_ip" in data or "dest_ip" in data or "src_ip" in data or "dst_ip" in data:
                flows = [data]
            elif "endpoint" in data:
                api_logs = [data]
    elif isinstance(data, list):
        if data and isinstance(data[0], dict):
            if "endpoint" in data[0]:
                api_logs = data
            else:
                flows = data

    indicators = analyze_network_heuristics(flows=flows, api_logs=api_logs)

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
        mitre.append({"id": "T1071", "name": "Application Layer Protocol"})
        if any("exfiltration" in str(ind.get("type", "")) for ind in indicators):
            mitre.append({"id": "T1048", "name": "Exfiltration Over Alternative Protocol"})

        target_ip = None
        for f in flows:
            if isinstance(f, dict):
                tip = f.get("dest_ip") or f.get("dst_ip") or f.get("source_ip") or f.get("src_ip")
                if tip:
                    target_ip = str(tip)
                    break
        if not target_ip:
            for al in api_logs:
                if isinstance(al, dict) and al.get("source_ip"):
                    target_ip = str(al["source_ip"])
                    break
        if target_ip and worst_sev in ("critical", "high"):
            indicators.insert(0, {
                "type": "ip",
                "value": target_ip,
                "severity": worst_sev,
                "description": f"Threat indicator IP {target_ip}",
            })

    return {
        "risk_score": risk_score,
        "severity": severity,
        "indicators": indicators,
        "mitre": mitre,
        "engine": "network_threat_detector",
        "available": True,
    }

