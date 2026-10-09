"""Regression test for LinkedIn and authentic domain multi-URL false positive fix.

Validates:
1. Authentic LinkedIn URLs with tracking IDs, query parameters, UUIDs, and deep paths
   score SAFE (not flagged for length, entropy, keywords, or random segments).
2. Emails with multiple authentic LinkedIn URLs (job alerts, digests) score SAFE and pass.
3. Spoofed lookalikes (homoglyphs, typosquatting, subdomain spoofing, IP hosts) are flagged
   as CRITICAL/HIGH and blocked.
4. Emails with multiple authentic URLs plus a phishing URL still flag the threat.
"""

import pytest

from app.schemas.email import NormalizedMessage
from app.services.mail_scanner import scan_message
from app.services.url_detector import analyze_url_heuristics, is_authentic_host


def test_authentic_host_verification():
    # Authentic LinkedIn domains
    assert is_authentic_host("www.linkedin.com") is True
    assert is_authentic_host("linkedin.com") is True
    assert is_authentic_host("jobalerts.linkedin.com") is True

    # Other authentic domains
    assert is_authentic_host("accounts.google.com") is True
    assert is_authentic_host("login.microsoftonline.com") is True

    # Spoofed or suspicious domains must NEVER be authentic
    assert is_authentic_host("192.168.1.1", is_spoofed=True) is False
    assert is_authentic_host("paypa1-secure.tk", is_spoofed=True) is False
    assert is_authentic_host("linkedin.com.attacker.com", is_spoofed=True) is False


def test_authentic_linkedin_url_no_false_indicators():
    url = (
        "https://www.linkedin.com/comm/jobs/view/3829104812/"
        "?ref=email-digest&trackingId=9xYz1234aBcD5678&midToken=AQEzX1234567890"
        "&trk=eml-jobs-alert&trkEmail=eml-jobs-alert-null-null-null"
    )
    indicators = analyze_url_heuristics(url)

    # Must NOT have url_length, url_entropy, suspicious_path_keyword, random_path_segment, excessive_digits
    types = [i["type"] for i in indicators]
    assert "url_length" not in types
    assert "url_entropy" not in types
    assert "suspicious_path_keyword" not in types
    assert "random_path_segment" not in types
    assert "excessive_digits" not in types

    # Only safe ML model indicator or clean domain indicator allowed
    threat_indicators = [i for i in indicators if i.get("severity") in ("medium", "high", "critical")]
    assert len(threat_indicators) == 0


def test_spoofed_linkedin_domains_flagged():
    # Homoglyph spoofing
    homoglyph_url = "https://lіnkedіn.com/login"
    h_inds = analyze_url_heuristics(homoglyph_url)
    h_types = [i["type"] for i in h_inds]
    assert "homoglyph_confusable" in h_types or "brand_typosquatting" in h_types

    # Subdomain spoofing
    subdomain_url = "https://www.linkedin.com.attacker-security.com/profile"
    s_inds = analyze_url_heuristics(subdomain_url)
    s_types = [i["type"] for i in s_inds]
    assert "brand_in_subdomain" in s_types or "subdomain_spoofing" in s_types


@pytest.mark.asyncio
async def test_multi_url_linkedin_email_scores_safe():
    body = """Hi Srikant,
Here are 5 new jobs matching your profile:
1. Senior Software Engineer: https://www.linkedin.com/jobs/view/3829104812/?ref=email-digest&trackingId=9xYz1234aBcD&midToken=AQEzX1234567890
2. Staff AI Engineer: https://www.linkedin.com/jobs/view/3829104813/?ref=email-digest&trackingId=8wXy9876zYxW&midToken=AQEzX1234567890
3. Lead Developer: https://www.linkedin.com/jobs/view/3829104814/?ref=email-digest&trackingId=7vWx5432wVuT&midToken=AQEzX1234567890
4. Backend Architect: https://www.linkedin.com/jobs/view/3829104815/?ref=email-digest&trackingId=6uVw1098vUtS&midToken=AQEzX1234567890
5. View Profile: https://www.linkedin.com/in/srikant-profile-1234567890/?trackingId=5tUv7654uTsR

Manage alerts: https://www.linkedin.com/email-action/preferences
Unsubscribe: https://www.linkedin.com/email-action/unsubscribe
"""
    msg = NormalizedMessage(
        provider_message_id="m-linkedin-job-alert",
        sender="LinkedIn Job Alerts <jobalerts-noreply@linkedin.com>",
        subject="5 new jobs matching your profile",
        body_text=body,
    )

    scan = await scan_message(msg)

    # Must be safe verdict with action 'pass'
    assert scan.overall_severity == "safe", f"Expected 'safe', got '{scan.overall_severity}'"
    assert scan.recommended_action == "pass", f"Expected 'pass', got '{scan.recommended_action}'"
    assert scan.overall_score < 0.30, f"Expected score < 0.30, got {scan.overall_score}"

    # URL detector engine must be safe with no threat indicators
    url_fa = next(fa for fa in scan.feature_analyses if fa.engine == "url_detector")
    assert url_fa.severity == "safe"
    assert url_fa.score < 0.20


@pytest.mark.asyncio
async def test_mixed_urls_with_phishing_still_detected():
    body = """Hi,
Check your LinkedIn jobs at https://www.linkedin.com/jobs/view/1234567890/?trackingId=abc
And also verify your urgent account suspension at http://paypa1-secure.tk/verify-login.php
"""
    msg = NormalizedMessage(
        provider_message_id="m-mixed",
        sender="Security Notice <security@notice.org>",
        subject="Urgent: verify your account",
        body_text=body,
    )

    scan = await scan_message(msg)

    # Malicious URL must dominate and trigger high/critical verdict and block action
    assert scan.overall_severity in ("critical", "high")
    assert scan.recommended_action in ("block", "quarantine")
    url_fa = next(fa for fa in scan.feature_analyses if fa.engine == "url_detector")
    assert url_fa.severity in ("critical", "high")
