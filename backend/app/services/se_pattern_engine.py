"""Social-engineering pattern engine (SE-HARDENING).

Detects the *narrative* of attachment-lure phishing — security-alert framing
combined with a reason to open an attachment or a deadline — independent of
any single keyword. This closes the screenshot-class false negative that
auth verification cannot: a manual/paste scan carries no SMTP headers, so
SPF/DKIM/DMARC have nothing to verify and the SE narrative is the only
signal left.

Scoring (0-100, capped):
- per pattern: high (framing, lure) +15 per match, medium +10 per match,
  with at most 2 matches per pattern counted toward the score (match_count
  still records every occurrence for the analyst);
- COMBINATION RULE: security_alert_framing AND (attachment_lure OR
  bureaucratic_urgency) → +45 (se_combination_rule, high) — the story beats
  any single phrase;
- the caller merges this risk monotonically:
  heuristic = max(heuristic, 0.7*heuristic + 0.3*se_risk) — SE can raise a
  verdict, never lower one (blend_se).

Confidence helper (D3): when both heuristic and ML are weak the result is
labelled low-confidence; when the heuristic is weak, there are no URL
indicators, and the body references attachments, the response says so
explicitly instead of returning a confidently-wrong "safe".
"""

from __future__ import annotations

import re
from typing import Any, Optional

ENGINE_NAME = "se_patterns"

ATTACHMENT_REFERENCE_WARNING = (
    "Email references attachments; attachment content not scanned in manual "
    "mode unless raw_headers supplied"
)
LOW_CONFIDENCE_NOTE = (
    "Low confidence: weak heuristic and ML signals. Manual review recommended."
)
ATTACHMENT_LURE_NOTE = (
    "attachment-lure pattern detected; verify attachment content separately."
)

_ATTACHMENT_REF_RE = re.compile(r"\battach(?:ed|ment)s?\b", re.IGNORECASE)


def references_attachment(text: str) -> bool:
    """True when the message text mentions an attachment at all."""
    return bool(_ATTACHMENT_REF_RE.search(text or ""))


def blend_se(heuristic: float, se_risk: float) -> float:
    """Monotonic SE merge on the 0-1 scale: SE can raise, never lower."""
    if se_risk <= 0:
        return heuristic
    return max(heuristic, 0.7 * heuristic + 0.3 * se_risk)


def assess_confidence(
    heuristic: float,
    ml: Optional[float],
    url_indicator_count: int,
    body: str,
) -> dict[str, Any]:
    """D3 confidence assessment.

    Returns {confidence: "low" | None, notes: [str]} — notes are appended to
    the explanation verbatim. ML=None (model unavailable) never produces the
    low-confidence label on its own: the rule requires BOTH signals weak."""
    notes: list[str] = []
    confidence: Optional[str] = None
    if heuristic < 0.5 and ml is not None and ml < 0.5:
        confidence = "low"
        notes.append(LOW_CONFIDENCE_NOTE)
    if heuristic < 0.3 and url_indicator_count == 0 and references_attachment(body):
        notes.append(ATTACHMENT_LURE_NOTE)
    return {"confidence": confidence, "notes": notes}


class SEPatternEngine:
    """Regex-narrative detector for attachment-lure social engineering."""

    ENGINE = ENGINE_NAME

    PATTERNS: dict[str, dict[str, Any]] = {
        "security_alert_framing": {
            "severity": "high",
            "points": 15,
            "description": "Security-alert framing: the message poses as an automated security notice",
            "regexes": [
                re.compile(r"we detected a (recent )?sign-in", re.IGNORECASE),
                re.compile(r"unrecognized (activity|device|location)", re.IGNORECASE),
                re.compile(r"account protection", re.IGNORECASE),
                re.compile(r"security verification", re.IGNORECASE),
                re.compile(r"authentication event", re.IGNORECASE),
            ],
        },
        "attachment_lure": {
            "severity": "high",
            "points": 15,
            "description": "Attachment lure: the reader is directed to open an attached document",
            "regexes": [
                re.compile(r"review the attached", re.IGNORECASE),
                re.compile(r"see attached document", re.IGNORECASE),
                re.compile(r"attached verification", re.IGNORECASE),
                re.compile(r"open the attachment", re.IGNORECASE),
            ],
        },
        "bureaucratic_urgency": {
            "severity": "medium",
            "points": 10,
            "description": "Bureaucratic urgency: a deadline or expedited action is imposed",
            "regexes": [
                re.compile(r"(may )?expire within \d+ hours", re.IGNORECASE),
                re.compile(r"as soon as possible", re.IGNORECASE),
                re.compile(r"may expire", re.IGNORECASE),
            ],
        },
        "authority_impersonation": {
            "severity": "medium",
            "points": 10,
            "description": "Authority impersonation: claims to speak for an account/security team",
            "regexes": [
                re.compile(r"(account|security|protection) team", re.IGNORECASE),
                re.compile(r"(IT|security) department", re.IGNORECASE),
            ],
        },
        "vague_threat": {
            "severity": "medium",
            "points": 10,
            "description": "Vague threat: unspecific consequences if the reader does not comply",
            "regexes": [
                re.compile(r"unrecognized activity", re.IGNORECASE),
                re.compile(r"suspicious activity", re.IGNORECASE),
                re.compile(r"unusual sign-in", re.IGNORECASE),
            ],
        },
    }

    COMBINATION_BONUS = 45
    MAX_MATCHES_SCORED_PER_PATTERN = 2

    def analyze(self, email_body: str, subject: str = "") -> dict[str, Any]:
        text = f"{subject or ''}\n{email_body or ''}"
        indicators: list[dict[str, Any]] = []
        match_counts: dict[str, int] = {}
        risk = 0

        for name, spec in self.PATTERNS.items():
            count = 0
            for rx in spec["regexes"]:
                count += len(rx.findall(text))
            match_counts[name] = count
            if count:
                risk += spec["points"] * min(count, self.MAX_MATCHES_SCORED_PER_PATTERN)
                indicators.append({
                    "type": name,
                    "severity": spec["severity"],
                    "weight": spec["points"],
                    "description": f"{spec['description']} ({count} match"
                                   + ("es" if count != 1 else "") + ")",
                    "match_count": count,
                })

        if match_counts.get("security_alert_framing") and (
            match_counts.get("attachment_lure") or match_counts.get("bureaucratic_urgency")
        ):
            risk += self.COMBINATION_BONUS
            indicators.append({
                "type": "se_combination_rule",
                "severity": "high",
                "weight": self.COMBINATION_BONUS,
                "description": "Security-alert framing combined with an attachment lure or "
                               "deadline urgency — classic attachment-lure phishing narrative",
                "match_count": 1,
            })

        return {
            "engine": self.ENGINE,
            "indicators": indicators,
            "risk_score": min(risk, 100),
            "match_counts": match_counts,
        }
