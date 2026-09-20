"""Explainable verdict builder — final email verdict including attachments.

Phase 4: after body engines AND attachment scanning have run, this builder
produces the single verdict users see: risk score, verdict, severity, and a
plain-language explanation that names how many attachments were flagged and
why. Attachment signals can raise an email's verdict but never lower it
(monotonic safety).
"""

from __future__ import annotations

from typing import Any

MALICIOUS_RISK = 80
SUSPICIOUS_RISK = 40


class VerdictBuilder:
    """Builds the final explainable verdict for a processed email."""

    def build_explainable_verdict(
        self,
        email_risk_score: int,
        email_indicators: list[dict[str, Any]],
        attachments_meta: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        """Combine email + attachment signals into {verdict, severity, risk_score, explanation}.

        email_risk_score is on the 0-100 scale (body engines' 0-1 float is
        converted by the caller before this point).
        """
        risk = int(round(email_risk_score or 0))

        if risk >= MALICIOUS_RISK:
            verdict = "malicious"
        elif risk >= SUSPICIOUS_RISK:
            verdict = "suspicious"
        else:
            verdict = "safe"

        if risk >= 80:
            severity = "critical"
        elif risk >= 60:
            severity = "high"
        elif risk >= 40:
            severity = "medium"
        else:
            severity = "low"

        explanation_parts: list[str] = []
        if email_indicators:
            explanation_parts.append(f"Email body: {len(email_indicators)} indicators detected")

        attachments_meta = attachments_meta or []
        malicious_attachments = [
            a for a in attachments_meta
            if (a.get("scan_results") or {}).get("verdict") == "malicious"
        ]
        suspicious_attachments = [
            a for a in attachments_meta
            if (a.get("scan_results") or {}).get("verdict") == "suspicious"
        ]
        if malicious_attachments:
            names = ", ".join(a.get("filename") or "unnamed" for a in malicious_attachments[:3])
            explanation_parts.append(
                f"{len(malicious_attachments)} malicious attachment(s) detected ({names})"
            )
        if suspicious_attachments:
            names = ", ".join(a.get("filename") or "unnamed" for a in suspicious_attachments[:3])
            explanation_parts.append(
                f"{len(suspicious_attachments)} suspicious attachment(s) detected ({names})"
            )

        if not explanation_parts:
            explanation_parts.append("No suspicious indicators found in body or attachments.")

        return {
            "verdict": verdict,
            "severity": severity,
            "risk_score": risk,
            "explanation": " ".join(explanation_parts),
        }
