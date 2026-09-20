"""Suite 36 — AUTH-VERIFY: independent SPF/DKIM/DMARC verification.

14 checks, DNS fully mocked (no network I/O ever; the default offline harness
mode is overridden per-test with injected fake transports).

Covers: SPF pass/fail/softfail/no-IP, DKIM sign-then-verify pass +
tamper-fail, DMARC policy + alignment scoring, the pass!=safe caveat, offline
zero-DNS behavior, resolver cache, circuit breaker, manual-path header
warning, and the realtime mx_parsed fallback.
"""

import base64

import pytest

from app.services import auth_verifier
from app.services.dns_resolver import DNSResolver, DNSUnavailable
from app.services.auth_verifier import (
    manual_auth_section,
    verify_all,
    verify_or_parse,
    verify_spf,
)

PASS_SAFE_NOTE = "does not prove benign"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_resolver(records=None, offline=False, **kwargs):
    """DNSResolver with a dict-driven fake transport. records maps
    (qname, rdtype) -> list[str]; unknown names return []."""
    table = {(q.lower(), r): v for (q, r), v in (records or {}).items()}
    counter = {"calls": 0}

    def transport(qname, rdtype):
        counter["calls"] += 1
        return list(table.get((qname.lower().rstrip("."), rdtype.upper()), []))

    resolver = DNSResolver(offline=offline, transport=transport, **kwargs)
    resolver.call_counter = counter
    return resolver


SPF_RECORD_ONLY = {("example.com", "TXT"): ['"v=spf1 ip4:203.0.113.0/24 -all"']}
SPF_DOMAIN_RECORDS = {
    **SPF_RECORD_ONLY,
    ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject"'],
}


@pytest.fixture(scope="module")
def dkim_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    pub_b64 = base64.b64encode(
        key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode()
    return pem, pub_b64


def sign_message(pem, body=b"Hello world.\r\n"):
    import dkim

    message = (
        b"From: alice@example.com\r\nTo: bob@example.org\r\n"
        b"Subject: test\r\nDate: Sun, 20 Sep 2026 12:00:00 +0000\r\n\r\n" + body
    )
    sig = dkim.DKIM(message).sign(
        b"sel", b"example.com", pem,
        include_headers=[b"From", b"To", b"Subject", b"Date"],
    )
    return sig + message


def dkim_records(pub_b64):
    return {("sel._domainkey.example.com", "TXT"): [f'"v=DKIM1; k=rsa; p={pub_b64}"']}


# ---------------------------------------------------------------------------
# SPF (checks 1-4)
# ---------------------------------------------------------------------------

def test_36_01_spf_pass_ip4_match():
    r = make_resolver(SPF_DOMAIN_RECORDS)
    res = verify_spf("bounce@example.com", "203.0.113.10", "example.com", r)
    assert res["status"] == "pass"
    assert "ip4" in res["reason"]


def test_36_02_spf_fail_scores_30_with_reason():
    r = make_resolver(SPF_RECORD_ONLY)  # no DMARC record: isolate the SPF score
    out = verify_all(
        {"sender": "ceo@example.com", "headers": {}, "sender_ip": "198.51.100.9"}, r
    )
    assert out["spf"]["status"] == "fail"
    assert out["spf"]["reason"]
    assert out["risk_score"] == 30
    types = [i["type"] for i in out["indicators"]]
    assert "auth_spf_fail" in types


def test_36_03_spf_softfail_scores_15():
    r = make_resolver({("example.com", "TXT"): ['"v=spf1 ip4:203.0.113.0/24 ~all"']})
    out = verify_all(
        {"sender": "ceo@example.com", "headers": {}, "sender_ip": "198.51.100.9"}, r
    )
    assert out["spf"]["status"] == "softfail"
    assert out["risk_score"] == 15


def test_36_04_spf_without_sender_ip_unavailable():
    r = make_resolver(SPF_RECORD_ONLY)  # no DMARC record: keep risk at 0
    out = verify_all({"sender": "ceo@example.com", "headers": {}, "body_text": "hi"}, r)
    assert out["spf"]["status"] == "unavailable"
    assert out["risk_score"] == 0
    info = [i for i in out["indicators"] if i["type"] == "auth_spf_unavailable"]
    assert info and info[0]["severity"] == "info"


# ---------------------------------------------------------------------------
# DKIM (checks 5-6)
# ---------------------------------------------------------------------------

def test_36_05_dkim_pass_signed_then_verified(dkim_keypair):
    pem, pub_b64 = dkim_keypair
    signed = sign_message(pem)
    records = {**SPF_DOMAIN_RECORDS, **dkim_records(pub_b64)}
    r = make_resolver(records)
    out = verify_all(
        {
            "sender": "alice@example.com",
            "raw_message": signed,
            "sender_ip": "203.0.113.10",
        },
        r,
    )
    assert out["dkim"]["status"] == "pass"
    assert out["dmarc"]["status"] == "pass"  # aligned via DKIM (and SPF)
    assert out["risk_score"] == 0


def test_36_06_dkim_fail_after_tamper_scores_25(dkim_keypair):
    pem, pub_b64 = dkim_keypair
    signed = sign_message(pem)
    tampered = signed.replace(b"Hello world.", b"Hello worm.")
    records = {**SPF_DOMAIN_RECORDS, **dkim_records(pub_b64)}
    r = make_resolver(records)
    out = verify_all(
        {
            "sender": "alice@example.com",
            "raw_message": tampered,
            "sender_ip": "203.0.113.10",  # SPF passes + aligns, isolating DKIM
        },
        r,
    )
    assert out["dkim"]["status"] == "fail"
    assert out["risk_score"] == 25
    types = [i["type"] for i in out["indicators"]]
    assert "auth_dkim_fail" in types


# ---------------------------------------------------------------------------
# DMARC (checks 7-9)
# ---------------------------------------------------------------------------

def test_36_07_dmarc_reject_fail_plus_alignment_55():
    # No SPF record (sender_ip present but domain publishes nothing usable),
    # DKIM absent -> DMARC p=reject fails and nothing aligns: +35 +20.
    r = make_resolver({("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject"']})
    out = verify_all({"sender": "ceo@example.com", "headers": {}, "sender_ip": "198.51.100.9"}, r)
    assert out["dmarc"]["status"] == "fail"
    assert out["dmarc"]["policy"] == "reject"
    assert out["risk_score"] == 55
    types = [i["type"] for i in out["indicators"]]
    assert "auth_dmarc_fail" in types and "auth_alignment_fail" in types


def test_36_08_dmarc_p_none_fail_scores_10():
    r = make_resolver({("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=none"']})
    out = verify_all({"sender": "ceo@example.com", "headers": {}, "sender_ip": "198.51.100.9"}, r)
    assert out["dmarc"]["status"] == "fail"
    assert out["risk_score"] == 10


def test_36_09_all_pass_risk_0_with_pass_not_safe_note(dkim_keypair):
    pem, pub_b64 = dkim_keypair
    signed = sign_message(pem)
    r = make_resolver({**SPF_DOMAIN_RECORDS, **dkim_records(pub_b64)})
    out = verify_all(
        {
            "sender": "alice@example.com",
            "raw_message": signed,
            "sender_ip": "203.0.113.10",
        },
        r,
    )
    assert out["spf"]["status"] == "pass"
    assert out["dkim"]["status"] == "pass"
    assert out["dmarc"]["status"] == "pass"
    assert out["risk_score"] == 0
    assert PASS_SAFE_NOTE in out["explanation"]


# ---------------------------------------------------------------------------
# Resolver mechanics (checks 10-12)
# ---------------------------------------------------------------------------

def test_36_10_offline_mode_zero_dns_calls():
    r = make_resolver(SPF_DOMAIN_RECORDS, offline=True)
    out = verify_all({"sender": "ceo@example.com", "headers": {}, "body_text": "hi"}, r)
    assert out["source"] == "unavailable"
    assert out["risk_score"] == 0
    assert out["spf"]["status"] == "unavailable"
    assert out["dkim"]["status"] == "unavailable"
    assert out["dmarc"]["status"] == "unavailable"
    info_types = sorted(i["type"] for i in out["indicators"] if i["severity"] == "info")
    assert info_types == ["auth_dkim_unavailable", "auth_dmarc_unavailable", "auth_spf_unavailable"]
    assert r.call_counter["calls"] == 0  # zero DNS calls attempted


def test_36_11_resolver_cache_hits_on_second_lookup():
    r = make_resolver({("example.com", "TXT"): ['"v=spf1 -all"']})
    first = r.resolve("example.com", "TXT")
    second = r.resolve("example.com", "TXT")
    assert first == second == ['"v=spf1 -all"']
    assert r.call_counter["calls"] == 1  # second lookup served from cache


def test_36_12_circuit_breaker_opens_after_5_failures():
    def broken_transport(qname, rdtype):
        raise ConnectionError("resolver down")

    r = DNSResolver(
        offline=False,
        transport=broken_transport,
        cb_failure_threshold=5,
        cb_window_s=60,
        cb_open_s=120,
    )
    for _ in range(5):
        with pytest.raises(DNSUnavailable):
            r.resolve("example.com", "TXT")
    calls_after_5 = r.transport_calls
    with pytest.raises(DNSUnavailable) as excinfo:
        r.resolve("example.com", "TXT")
    assert "circuit breaker" in str(excinfo.value)
    assert r.transport_calls == calls_after_5  # no DNS call attempted


# ---------------------------------------------------------------------------
# Wiring (checks 13-14)
# ---------------------------------------------------------------------------

@pytest.mark.http
async def test_36_13_manual_path_without_raw_headers_warns_with_raw_headers_verifies(client, monkeypatch, dkim_keypair):
    _, pub_b64 = dkim_keypair

    # Without raw_headers: info indicator + warning flag, never a pass.
    resp = await client.post(
        "/api/v1/analysis/email",
        json={"sender": "ceo@totally-legit-biz.example", "subject": "Urgent", "body": "wire transfer"},
    )
    assert resp.status_code == 200
    body = resp.json()
    ind_types = [i.get("type") for i in body.get("indicators", [])]
    assert "auth_headers_missing" in ind_types
    assert body.get("warnings"), "expected manual-path warning flag on the response"
    assert "no message headers" in body["warnings"][0]

    # With raw_headers: independent verification runs against mocked DNS and
    # the spf fail indicator appears on the alert.
    records = {
        **{("example.com", "TXT"): ['"v=spf1 ip4:203.0.113.0/24 -all"']},
        **{("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=reject"']},
        **dkim_records(pub_b64),
    }
    fake = make_resolver(records)
    monkeypatch.setattr(auth_verifier, "get_default_resolver", lambda: fake)
    raw_headers = (
        "Return-Path: <bounce@example.com>\r\n"
        "Received: from mail.example.com (mail.example.com [198.51.100.9]) by mx.test\r\n"
    )
    resp2 = await client.post(
        "/api/v1/analysis/email",
        json={
            "sender": "ceo@example.com",
            "subject": "Invoice",
            "body": "please pay",
            "raw_headers": raw_headers,
        },
    )
    assert resp2.status_code == 200
    body2 = resp2.json()
    ind_types2 = [i.get("type") for i in body2.get("indicators", [])]
    assert "auth_spf_fail" in ind_types2
    assert body2.get("warnings") == []


def test_36_14_realtime_fallback_mx_parsed_when_independent_unavailable():
    r = make_resolver({}, offline=True)
    signals = {"spf": "fail", "dkim": "pass", "dmarc": "fail"}
    out = verify_or_parse(signals, {"sender": "ceo@example.com", "headers": {}}, r)
    assert out["source"] == "mx_parsed"
    assert out["risk_score"] == 65  # spf fail 30 + dmarc fail (policy unknown) 35
    types = [i["type"] for i in out["indicators"]]
    assert "spf_fail" in types and "dmarc_fail" in types
