"""Attachment risk scorer — converts scan indicators into a final verdict.

Phase 4: engines produce capped per-channel risk; this scorer owns the
single verdict decision for an attachment: total risk, forced-malicious
signals (identity lies, zip bombs, AV signatures), a severity band, and a
human-readable explanation built from the highest-severity indicators.
"""

from __future__ import annotations

from typing import Any, Optional

from app.services.scoring_service import SEVERITY_WEIGHTS

MALICIOUS_RISK = 80
SUSPICIOUS_RISK = 40
ELEVATED_RISK = 20

# Indicator types that condemn an attachment regardless of the summed score.
FORCED_MALICIOUS_TYPES = {
    "executable_disguise",       # MZ content posing as a document/image
    "zip_bomb_suspected",        # archive engineered to explode
    "malicious_clamav_signature",
    "clamav_signature",          # AV engine hit
}

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class AttachmentRiskScorer:
    """Final attachment verdict: score, severity, explanation."""

    def score(self, indicators: list[dict[str, Any]], total_risk: Optional[int] = None) -> dict:
        """Score an indicator list into {risk_score, verdict, severity, explanation, top_indicators}.

        total_risk: authoritative pre-capped sum from the engine pipeline
        (Levels 1-3). When omitted, the sum of each indicator's risk_score
        (or its severity weight) is used.
        """
        if total_risk is None:
            total_risk = 0
            for indicator in indicators:
                total_risk += int(
                    indicator.get("risk_score", SEVERITY_WEIGHTS.get(str(indicator.get("severity", "")).lower(), 0))
                )

        forced = any(
            str(i.get("severity", "")).lower() == "critical" or i.get("type") in FORCED_MALICIOUS_TYPES
            for i in indicators
        )

        if forced or total_risk >= MALICIOUS_RISK:
            verdict, severity = "malicious", "critical"
        elif total_risk >= SUSPICIOUS_RISK:
            verdict, severity = "suspicious", "high"
        elif total_risk >= ELEVATED_RISK:
            verdict, severity = "suspicious", "medium"
        else:
            verdict, severity = "safe", "low"

        top_indicators = self._top_indicators(indicators, limit=3)
        explanation = self._explain(verdict, total_risk, top_indicators)

        return {
            "risk_score": total_risk,
            "verdict": verdict,
            "severity": severity,
            "explanation": explanation,
            "top_indicators": top_indicators,
        }

    @staticmethod
    def _top_indicators(indicators: list[dict[str, Any]], limit: int = 3) -> list[dict[str, Any]]:
        """Highest-severity indicators first (stable within a band)."""
        return sorted(
            indicators,
            key=lambda i: _SEVERITY_RANK.get(str(i.get("severity", "info")).lower(), 0),
            reverse=True,
        )[:limit]

    @staticmethod
    def _explain(verdict: str, risk_score: int, top_indicators: list[dict[str, Any]]) -> str:
        if not top_indicators:
            return f"Attachment scored {risk_score}/100: no suspicious indicators found."
        evidence = "; ".join(
            f"{i.get('type')}"
            + (f" ({i['description']})" if i.get("description") else "")
            for i in top_indicators
        )
        return f"Attachment scored {risk_score}/100 ({verdict}). Strongest evidence: {evidence}."
