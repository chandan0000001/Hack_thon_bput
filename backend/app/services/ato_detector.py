"""SCENARIO-3: Organization-scoped account-takeover detection engine.

Three-signal fusion over an abnormal activity timeline compared against the
account's normal baseline profile:

  1. Rule engine   — hard thresholds (failed attempts, odd-hour logins,
                     password change, mass file access).
  2. Anomaly score — deviation from ``baseline_profile`` (country mismatch,
                     unrecognized device, off-baseline login hours).
  3. Threat intel  — source IP against the mock malicious-IP watchlist.

Fused output: ``risk_score`` (0-100), ``risk_level``, ``indicators`` and
``recommended_actions``. Pure heuristic logic — no ML/LLM calls, so the
module is deterministic and unit-testable in isolation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Hard rule thresholds (S1 signal 1).
FAILED_ATTEMPTS_THRESHOLD = 5
ODD_HOUR_START = 1  # 01:00
ODD_HOUR_END = 5  # exclusive; 01:00–04:59 counts as unusual
FILES_ACCESSED_THRESHOLD = 50

# Rule-engine weights.
W_FAILED_BURST = 20
W_ODD_HOUR_LOGIN = 12
W_PASSWORD_CHANGED = 18
W_MASS_FILE_ACCESS = 15

# Anomaly weights (S1 signal 2, vs baseline_profile).
W_COUNTRY_MISMATCH = 12
W_NEW_DEVICE = 8
W_OFF_BASELINE_HOURS = 7

# Threat-intel weight (S1 signal 3).
W_MALICIOUS_IP = 15

# Mock threat-intel watchlist (RFC 5737 documentation ranges + demo values;
# a real deployment would swap this for a feed lookup).
MOCK_MALICIOUS_IPS: frozenset[str] = frozenset(
    {
        "45.155.205.233",
        "185.220.101.7",
        "193.106.191.25",
        "91.219.236.18",
        "5.188.206.130",
    }
)

RISK_LEVELS: list[tuple[int, str]] = [
    (95, "critical"),
    (70, "high"),
    (40, "medium"),
    (0, "low"),
]

# ATO-UI-OVERHAUL: strict 3-tier enforcement bands (independent of the
# descriptive risk_level above — these decide what the platform DOES).
TIER_SAFE_MAX = 30  # score < 30  -> ALLOWED
TIER_MEDIUM_MAX = 75  # 30 <= score < 75 -> USER_NOTIFIED; >= 75 -> ACCOUNT_RESTRICTED


def classify_enforcement(score: int) -> dict[str, Any]:
    """Map a fused risk score to the enforced action tier.

    SAFE     (< 30):  ALLOWED — no notification.
    MEDIUM   (30-74): USER_NOTIFIED (mock notification).
    CRITICAL (>= 75): ACCOUNT_RESTRICTED (mock account lock recorded in
                      metadata) AND USER_NOTIFIED.
    """
    score = max(0, min(100, int(score)))
    if score < TIER_SAFE_MAX:
        return {
            "tier": "safe",
            "action_taken": "ALLOWED",
            "actions": ["ALLOWED"],
            "account_restricted": False,
            "notified": False,
        }
    if score < TIER_MEDIUM_MAX:
        return {
            "tier": "medium",
            "action_taken": "USER_NOTIFIED",
            "actions": ["USER_NOTIFIED"],
            "account_restricted": False,
            "notified": True,
        }
    return {
        "tier": "critical",
        "action_taken": "ACCOUNT_RESTRICTED",
        "actions": ["ACCOUNT_RESTRICTED", "USER_NOTIFIED"],
        "account_restricted": True,
        "notified": True,
    }

RECOMMENDED_RESPONSE_HIGH = [
    "Temporarily restrict the session/account.",
    "Force credential reset & ask for additional verification.",
    "Notify the security administrator.",
]
RECOMMENDED_RESPONSE_MEDIUM = [
    "Require step-up verification on the next login.",
    "Review the flagged session activity with the account owner.",
    "Keep the account under enhanced monitoring for 24h.",
]
RECOMMENDED_RESPONSE_LOW = [
    "No immediate action required; continue routine monitoring.",
]


def _parse_time(value: Any) -> datetime | None:
    """Accept ISO timestamps or bare 'HH:MM' clock strings."""
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if "T" in text or " " in text:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            return None
    try:
        hour, minute = text.split(":")[:2]
        return datetime(2000, 1, 1, int(hour), int(minute), tzinfo=timezone.utc)
    except (ValueError, IndexError):
        return None


def _hour_minute(value: Any) -> tuple[int, int] | None:
    parsed = _parse_time(value)
    return (parsed.hour, parsed.minute) if parsed else None


def _is_odd_hour(value: Any) -> bool:
    hm = _hour_minute(value)
    return hm is not None and ODD_HOUR_START <= hm[0] < ODD_HOUR_END


def _parse_window(bound: Any) -> tuple[int, int] | None:
    hm = _hour_minute(bound)
    return hm


def _within_typical_hours(value: Any, start: Any, end: Any) -> bool | None:
    hm = _hour_minute(value)
    window_start = _parse_window(start)
    window_end = _parse_window(end)
    if hm is None or window_start is None or window_end is None:
        return None
    return window_start <= hm < window_end


def _format_clock(value: Any) -> str:
    hm = _hour_minute(value)
    if hm is None:
        return str(value)
    hour, minute = hm
    suffix = "AM" if hour < 12 else "PM"
    display = hour % 12 or 12
    return f"{display:02d}:{minute:02d} {suffix}"


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class AccountTakeoverDetector:
    """Fuses rule-engine, anomaly and threat-intel signals into one verdict."""

    def analyze(
        self,
        baseline_profile: dict[str, Any] | None,
        suspicious_events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        baseline = baseline_profile or {}
        events = suspicious_events or []

        score = 0
        indicators: list[dict[str, str]] = []
        timeline: list[dict[str, Any]] = []

        baseline_country = str(baseline.get("home_country", "")).strip().lower()
        known_devices = {str(d).strip().lower() for d in baseline.get("known_devices") or []}
        known_ips = {str(ip).strip() for ip in baseline.get("known_ips") or []}
        window_start = baseline.get("typical_login_start")
        window_end = baseline.get("typical_login_end")

        successful_logins = [
            e
            for e in events
            if str(e.get("event_type", "")).strip().lower()
            in ("login_success", "successful_login", "login")
        ]
        password_changed = any(
            str(e.get("event_type", "")).strip().lower()
            in ("password_change", "password_changed")
            or e.get("password_changed") is True
            for e in events
        )

        # Each indicator type contributes to the fused score exactly once —
        # two logins from the same rogue country are one anomaly, not two.
        seen: set[str] = set()

        def _fire(kind: str, weight: int, indicator: dict[str, str]) -> bool:
            nonlocal score
            if kind in seen:
                return False
            seen.add(kind)
            score += weight
            indicators.append(indicator)
            return True

        for event in events:
            etype = str(event.get("event_type", "")).strip().lower()
            timestamp = event.get("timestamp")
            clock = _format_clock(timestamp)
            source_ip = str(event.get("source_ip", "")).strip()
            country = str(event.get("country", "")).strip().lower()
            device_id = str(event.get("device_id", "")).strip()
            flagged: list[str] = []
            event_score = 0

            failed_attempts = _as_int(event.get("failed_attempts"))
            files_accessed = _as_int(event.get("files_accessed"))
            success_like = etype in ("login_success", "successful_login", "login")

            # --- Signal 1: rule engine (hard thresholds) -------------
            if failed_attempts is not None and failed_attempts >= FAILED_ATTEMPTS_THRESHOLD:
                if _fire(
                    "failed_login_burst",
                    W_FAILED_BURST,
                    {
                        "type": "failed_login_burst",
                        "severity": "high",
                        "description": f"Multiple failed login attempts ({failed_attempts})",
                        "signal": "rule_engine",
                    },
                ):
                    flagged.append("failed_login_burst")
                    event_score += W_FAILED_BURST

            if success_like and _is_odd_hour(timestamp):
                if _fire(
                    "odd_hour_login",
                    W_ODD_HOUR_LOGIN,
                    {
                        "type": "odd_hour_login",
                        "severity": "high",
                        "description": f"Login at unusual time ({clock})",
                        "signal": "rule_engine",
                    },
                ):
                    flagged.append("odd_hour_login")
                    event_score += W_ODD_HOUR_LOGIN

            if etype in ("password_change", "password_changed"):
                if _fire(
                    "password_changed",
                    W_PASSWORD_CHANGED,
                    {
                        "type": "password_changed",
                        "severity": "high",
                        "description": "Password changed shortly after login",
                        "signal": "rule_engine",
                    },
                ):
                    flagged.append("password_changed")
                    event_score += W_PASSWORD_CHANGED

            if files_accessed is not None and files_accessed > FILES_ACCESSED_THRESHOLD:
                if _fire(
                    "mass_data_access",
                    W_MASS_FILE_ACCESS,
                    {
                        "type": "mass_data_access",
                        "severity": "high",
                        "description": (
                            f"Unusual volume of data access ({files_accessed} files)"
                        ),
                        "signal": "rule_engine",
                    },
                ):
                    flagged.append("mass_data_access")
                    event_score += W_MASS_FILE_ACCESS

            # --- Signal 2: anomaly detection vs baseline -------------
            if baseline_country and country and country != baseline_country:
                if _fire(
                    "country_mismatch",
                    W_COUNTRY_MISMATCH,
                    {
                        "type": "country_mismatch",
                        "severity": "high",
                        "description": (
                            f"Unrecognised device & IP (Country mismatch: "
                            f"{country.upper()} vs baseline {baseline_country.upper()})"
                        ),
                        "signal": "anomaly",
                    },
                ):
                    flagged.append("country_mismatch")
                    event_score += W_COUNTRY_MISMATCH

            if device_id and known_devices and device_id.lower() not in known_devices:
                if _fire(
                    "unrecognized_device",
                    W_NEW_DEVICE,
                    {
                        "type": "unrecognized_device",
                        "severity": "medium",
                        "description": f"Login from a device never seen on this account ({device_id})",
                        "signal": "anomaly",
                    },
                ):
                    flagged.append("unrecognized_device")
                    event_score += W_NEW_DEVICE

            in_window = (
                _within_typical_hours(timestamp, window_start, window_end)
                if success_like
                else None
            )
            if in_window is False:
                if _fire(
                    "off_baseline_hours",
                    W_OFF_BASELINE_HOURS,
                    {
                        "type": "off_baseline_hours",
                        "severity": "medium",
                        "description": (
                            f"Login outside the usual window "
                            f"({_format_clock(window_start)}–{_format_clock(window_end)})"
                        ),
                        "signal": "anomaly",
                    },
                ):
                    flagged.append("off_baseline_hours")
                    event_score += W_OFF_BASELINE_HOURS

            if device_id and not known_devices and source_ip and source_ip not in known_ips:
                # No device baseline to compare against; still note IP novelty
                # as a low-severity anomaly.
                flagged.append("unfamiliar_ip")

            # --- Signal 3: threat intel ------------------------------
            if source_ip and source_ip in MOCK_MALICIOUS_IPS:
                if _fire(
                    "malicious_ip",
                    W_MALICIOUS_IP,
                    {
                        "type": "malicious_ip",
                        "severity": "critical",
                        "description": (
                            f"Source IP {source_ip} is on the malicious-IP watchlist"
                        ),
                        "signal": "threat_intel",
                    },
                ):
                    flagged.append("malicious_ip")
                    event_score += W_MALICIOUS_IP

            timeline.append(
                {
                    **event,
                    "flagged": flagged,
                    "event_score": event_score,
                }
            )

        # A password change flag carried on a non-password event type
        # (e.g. password_changed: true on a login) still counts once.
        if password_changed and "password_changed" not in seen:
            score += W_PASSWORD_CHANGED
            indicators.append(
                {
                    "type": "password_changed",
                    "severity": "high",
                    "description": "Password changed shortly after login",
                    "signal": "rule_engine",
                }
            )

        risk_score = max(0, min(100, score))
        risk_level = next(level for floor, level in RISK_LEVELS if risk_score >= floor)
        verdict = (
            "account_takeover_detected" if risk_level in ("high", "critical") else "no_takeover_detected"
        )

        return {
            "verdict": verdict,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "indicators": indicators,
            "recommended_actions": self.recommended_actions(risk_level),
            "timeline": timeline,
            "threat_intel": {
                "watchlist_size": len(MOCK_MALICIOUS_IPS),
                "hits": sorted(
                    {
                        str(e.get("source_ip")).strip()
                        for e in events
                        if str(e.get("source_ip", "")).strip() in MOCK_MALICIOUS_IPS
                    }
                ),
            },
        }

    @staticmethod
    def recommended_actions(risk_level: str) -> list[str]:
        if risk_level in ("high", "critical"):
            return list(RECOMMENDED_RESPONSE_HIGH)
        if risk_level == "medium":
            return list(RECOMMENDED_RESPONSE_MEDIUM)
        return list(RECOMMENDED_RESPONSE_LOW)
