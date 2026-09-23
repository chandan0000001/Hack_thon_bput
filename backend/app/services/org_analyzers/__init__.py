"""Organization Analyzers (ORG-REBUILD Level 2).

Thin wrappers around existing engines exposing the uniform interface:
    analyze(payload: dict[str, Any], ctx: dict[str, Any] | None = None) -> dict[str, Any]
Returning:
    {
        "risk_score": int,
        "severity": str,
        "indicators": list[dict],
        "mitre": list[dict],
        "engine": str,
        "available": bool,
    }
"""

from app.services.org_analyzers.log_analyzer import analyze as analyze_log
from app.services.org_analyzers.ato_analyzer import analyze as analyze_ato
from app.services.org_analyzers.network_analyzer import analyze as analyze_network

ANALYZERS = {
    "analyze_log": analyze_log,
    "analyze_ato": analyze_ato,
    "analyze_network": analyze_network,
}

__all__ = ["analyze_log", "analyze_ato", "analyze_network", "ANALYZERS"]
