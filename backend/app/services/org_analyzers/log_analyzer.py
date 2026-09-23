"""Log Analyzer thin wrapper around app.services.org_log_analyzer."""

from typing import Any
from app.services.org_log_analyzer import analyze_log


def analyze(payload: dict[str, Any], ctx: dict[str, Any] | None = None) -> dict[str, Any]:
    """Uniform analyzer interface for application, authentication, and network logs."""
    data = payload.get("data", payload) if isinstance(payload, dict) else payload
    res = analyze_log(data)

    return {
        "risk_score": int(res.get("risk_score", 15)),
        "severity": str(res.get("severity", "low")),
        "indicators": list(res.get("indicators", [])),
        "mitre": list(res.get("mitre_techniques", [])),
        "engine": "org_log_analyzer",
        "available": True,
    }
