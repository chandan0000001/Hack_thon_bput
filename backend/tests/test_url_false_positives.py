"""Regression tests for format-based URL token classification and contextual scoring (URL-FP-FIX-V2).

Validates that legitimate tokenized URLs with high entropy (JWT, UUID, Base64, Hex)
are classified as SAFE/LOW on clean domains using custom, non-standard paths, while
malicious URLs (typosquatting, IP address, subdomain spoofing) are flagged as WARN/BLOCK.
Confirms ZERO hardcoded path or parameter names.
"""

from __future__ import annotations

import re
import pytest

from app.services.scoring_service import (
    STRONG_MALICIOUS_INDICATOR_TYPES,
    URL_ACTION_ALLOW,
    URL_ACTION_BLOCK,
    URL_ACTION_WARN,
    get_url_decision,
)
from app.services.url_analyzer import (
    adjust_indicators_for_tokens,
    analyze_url,
    check_domain_threats,
)
from app.services.url_token_classifier import (
    classify_token_format,
    is_base64_token,
    is_domain_clean,
    is_hex_token,
    is_jwt_token,
    is_uuid_token,
    analyze_url_structure,
)


class TestMathematicalTokenClassifier:
    """T1: Verify mathematical regex & structural classification without hardcoded paths/params."""

    def test_jwt_detection(self):
        valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHvdPOv"
        assert is_jwt_token(valid_jwt) is True
        assert classify_token_format(valid_jwt) == "jwt"

        invalid_jwt_2_parts = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        assert is_jwt_token(invalid_jwt_2_parts) is False

        plain_text = "not-a-jwt-token"
        assert is_jwt_token(plain_text) is False

    def test_uuid_detection(self):
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert is_uuid_token(valid_uuid) is True
        assert classify_token_format(valid_uuid) == "uuid"

        # Uppercase UUID
        valid_uuid_upper = "550E8400-E29B-41D4-A716-446655440000"
        assert is_uuid_token(valid_uuid_upper) is True

        # Malformed UUID (wrong group length)
        invalid_uuid = "550e8400-e29b-41d4-a716-44665544000"
        assert is_uuid_token(invalid_uuid) is False

    def test_base64_detection(self):
        valid_b64 = "aGVsbG8gd29ybGQxMjM0NTY3ODkwMTIzNA=="
        assert is_base64_token(valid_b64) is True
        assert classify_token_format(valid_b64) == "base64"

        # Base64URL with hyphen and underscore
        valid_b64url = "aGVsbG8td29ybGRfMTIzNDU2Nzg5MA"
        assert is_base64_token(valid_b64url) is True

        short_b64 = "YWJj"  # only 4 chars
        assert is_base64_token(short_b64) is False

    def test_hex_detection(self):
        valid_hex = "abcdef0123456789abcdef0123456789"  # 32 chars
        assert is_hex_token(valid_hex) is True
        assert classify_token_format(valid_hex) == "hex"

        short_hex = "abcdef01"
        assert is_hex_token(short_hex) is False

    def test_no_hardcoded_path_or_param_names_in_classifier_source(self):
        """Proof: Ensure the classifier file does NOT check hardcoded names like verify, login, reset, auth."""
        import inspect
        from app.services import url_token_classifier

        source = inspect.getsource(url_token_classifier)
        forbidden_keywords = ["'verify'", '"verify"', "'login'", '"login"', "'reset'", '"reset"', "'auth'", '"auth"']
        for kw in forbidden_keywords:
            assert kw not in source, f"Forbidden hardcoded routing keyword found in url_token_classifier.py: {kw}"

    def test_analyze_url_structure_locations(self):
        # Custom query parameter 'a'
        res1 = analyze_url_structure("https://clean-domain.com/x/y/z?a=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHvdPOv")
        assert res1["has_structured_token"] is True
        assert "query.a" in res1["token_locations"]
        assert res1["domain_is_clean"] is True

        # Path segment 2
        res2 = analyze_url_structure("https://clean-domain.com/action/550e8400-e29b-41d4-a716-446655440000")
        assert res2["has_structured_token"] is True
        assert "path.segment_2" in res2["token_locations"]
        assert res2["domain_is_clean"] is True

        # Custom query parameter 'sig'
        res3 = analyze_url_structure("https://clean-domain.com/api/v1/data?sig=aGVsbG8gd29ybGQxMjM0NTY3ODkwMTIzNA==")
        assert res3["has_structured_token"] is True
        assert "query.sig" in res3["token_locations"]
        assert res3["domain_is_clean"] is True


class TestDomainCleanlinessEvaluation:
    """T1: Evaluate whether domains pass typosquatting, homoglyph, and IP checks."""

    def test_clean_domain_passes(self):
        assert is_domain_clean("clean-domain.com") is True
        assert is_domain_clean("my-company-app.org") is True
        assert is_domain_clean("api.platform.internal.org") is True

    def test_ip_address_rejected(self):
        assert is_domain_clean("192.168.1.50") is False
        assert is_domain_clean("10.0.0.1") is False

    def test_typosquatting_rejected(self):
        assert is_domain_clean("micr0soft-domain.xyz") is False
        assert is_domain_clean("paypa1-security.com") is False

    def test_subdomain_spoofing_rejected(self):
        # clean-domain.com in subdomain before evil.net
        assert is_domain_clean("clean-domain.com.evil.net") is False
        assert is_domain_clean("paypal.com.attacker.org") is False

    def test_suspicious_tld_rejected(self):
        assert is_domain_clean("suspicious-service.xyz") is False
        assert is_domain_clean("random-site.top") is False


class TestCustomPathLegitimateUrls:
    """T5.1: Custom, non-standard legitimate URLs MUST return SAFE/LOW and ALLOW."""

    @pytest.mark.parametrize(
        "url,expected_token_loc",
        [
            (
                "https://clean-domain.com/x/y/z?a=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHvdPOv",
                "query.a",
            ),
            (
                "https://clean-domain.com/action/550e8400-e29b-41d4-a716-446655440000",
                "path.segment_2",
            ),
            (
                "https://clean-domain.com/api/v1/data?sig=aGVsbG8gd29ybGQxMjM0NTY3ODkwMTIzNA==",
                "query.sig",
            ),
            (
                "https://clean-domain.com/resource/abcdef0123456789abcdef0123456789",
                "path.segment_2",
            ),
            (
                "https://clean-domain.com/v2/items?custom_id=550e8400-e29b-41d4-a716-446655440000",
                "query.custom_id",
            ),
        ],
    )
    def test_legitimate_tokenized_urls_are_safe_allow(self, url, expected_token_loc):
        result = analyze_url(url)
        assert result["structure"]["has_structured_token"] is True
        assert result["structure"]["domain_is_clean"] is True
        assert expected_token_loc in result["structure"]["token_locations"]

        # Severity MUST be safe or low
        assert result["severity"] in ("safe", "low"), (
            f"Expected SAFE/LOW for legitimate URL, got {result['severity']} with hybrid score {result['hybrid_score']}"
        )
        # Action MUST be allow
        assert result["decision"]["action"] == URL_ACTION_ALLOW, (
            f"Expected ALLOW for legitimate URL, got action {result['decision']['action']}"
        )
        assert result["decision"]["verdict"] == "safe"


class TestCustomPathMaliciousUrls:
    """T5.2: Malicious URLs with tokens MUST return WARN/BLOCK."""

    @pytest.mark.parametrize(
        "url,malice_reason",
        [
            (
                "https://micr0soft-domain.xyz/x/y/z?a=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHvdPOv",
                "Typosquatting + suspicious TLD with JWT",
            ),
            (
                "http://192.168.1.50/auth?token=550e8400-e29b-41d4-a716-446655440000",
                "IP host + UUID",
            ),
            (
                "https://clean-domain.com.evil.net/action?sig=aGVsbG8gd29ybGQxMjM0NTY3ODkwMTIzNA==",
                "Subdomain spoofing with Base64 signature",
            ),
            (
                "http://10.0.0.1/verify?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHvdPOv",
                "IP host + JWT",
            ),
        ],
    )
    def test_malicious_tokenized_urls_are_warn_or_block(self, url, malice_reason):
        result = analyze_url(url)
        assert result["structure"]["has_structured_token"] is True
        assert result["structure"]["domain_is_clean"] is False

        # Severity MUST be medium, high, or critical (never safe/low)
        assert result["severity"] in ("medium", "high", "critical"), (
            f"Failed for {malice_reason}: expected WARN/BLOCK severity, got {result['severity']}"
        )
        # Decision MUST be warn or block (never allow)
        assert result["decision"]["action"] in (URL_ACTION_WARN, URL_ACTION_BLOCK), (
            f"Failed for {malice_reason}: expected WARN/BLOCK action, got {result['decision']['action']}"
        )


class TestContextualScoringAdjustment:
    """T2: Verify that query entropy and path length are heavily down-weighted on clean domains,

    while domain-level indicators maintain 100% weight.
    """

    def test_entropy_downweighted_on_clean_domain(self):
        raw_indicators = [
            {"type": "url_length", "severity": "medium", "value": "120"},
            {"type": "url_entropy", "severity": "medium", "value": "5.4"},
            {"type": "random_path_segment", "severity": "medium", "value": "random"},
        ]
        structure_clean = {
            "has_structured_token": True,
            "domain_is_clean": True,
            "token_locations": ["query.param"],
        }
        adjusted = adjust_indicators_for_tokens(raw_indicators, structure_clean)
        # Token-induced metric indicators should be suppressed from threat scoring
        indicator_types = [i["type"] for i in adjusted]
        assert "url_length" not in indicator_types
        assert "url_entropy" not in indicator_types
        assert "structured_token_clean_domain" in indicator_types

    def test_domain_indicators_remain_at_100_percent_weight(self):
        raw_indicators = [
            {"type": "suspicious_tld", "severity": "high", "value": "xyz"},
            {"type": "url_length", "severity": "medium", "value": "120"},
        ]
        structure_dirty = {
            "has_structured_token": True,
            "domain_is_clean": False,
            "token_locations": ["query.param"],
        }
        adjusted = adjust_indicators_for_tokens(raw_indicators, structure_dirty)
        # Not clean domain -> nothing suppressed!
        indicator_types = [i["type"] for i in adjusted]
        assert "suspicious_tld" in indicator_types
        assert "url_length" in indicator_types


class TestBlockingPolicyGuardrail:
    """T4: Cap severity at MEDIUM/LOW and prevent automatic BLOCK if only elevated

    indicators are entropy/length and structured token is present.
    """

    def test_guardrail_prevents_block_for_entropy_only(self):
        entropy_only_indicators = [
            {"type": "url_length", "severity": "high", "value": "150"},
            {"type": "url_entropy", "severity": "high", "value": "5.8"},
            {"type": "query_entropy", "severity": "high", "value": "5.9"},
        ]
        # Without independent strong malicious evidence, high/critical severity must be capped
        decision = get_url_decision(
            severity="high",
            ml_confidence=0.95,
            has_structured_token=True,
            indicators=entropy_only_indicators,
        )
        assert decision["action"] != URL_ACTION_BLOCK
        assert decision["action"] in (URL_ACTION_WARN, URL_ACTION_ALLOW)

    def test_block_allowed_when_strong_malicious_evidence_present(self):
        indicators_with_strong = [
            {"type": "url_length", "severity": "high", "value": "150"},
            {"type": "brand_typosquatting", "severity": "critical", "value": "micr0soft"},
        ]
        decision = get_url_decision(
            severity="critical",
            ml_confidence=0.95,
            has_structured_token=True,
            indicators=indicators_with_strong,
        )
        assert decision["action"] == URL_ACTION_BLOCK
        assert decision["verdict"] == "malicious"
