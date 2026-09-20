"""Tests for ATTACH-SCAN Phase 4 — risk scoring, pipeline integration, explainable verdicts.

Covers AttachmentRiskScorer (thresholds, forced-malicious, explanation),
fetch_service metadata extraction (pending, no byte downloads),
analysis_service attachment scanning (per-attachment isolation, monotonic
risk aggregation), VerdictBuilder (explainable verdicts), and two
end-to-end pipeline runs against the database. Also exposes
run_attachment_integration_tests(runner) for run_all_tests Suite 34.
"""

from __future__ import annotations

import inspect
import uuid
from datetime import datetime, timezone
from typing import Any

import pytest

from app.services.attachment_risk_scorer import AttachmentRiskScorer
from app.services.attachment_scanner import AttachmentScanner, ScanResult
from app.services.gmail.analysis_service import (
    aggregate_attachment_risk,
    scan_email_attachments,
)
from app.services.gmail.fetch_service import extract_attachments_meta
from app.services.verdict_builder import VerdictBuilder

from test_attachment_scanner import FakeGmailClient  # shared fake (tests dir on sys.path)
from test_content_analysis import _content_pdf


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _ScriptedScanner:
    """Returns canned ScanResults, recording every call."""

    def __init__(self, results: list[ScanResult] | Exception):
        self.results = list(results) if not isinstance(results, Exception) else results
        self.calls: list[tuple] = []

    async def scan_attachment(self, gmail_client, message_id, attachment_id, filename, declared_mime, expected_size, **kwargs):
        self.calls.append((message_id, attachment_id, filename, declared_mime, expected_size))
        if isinstance(self.results, Exception):
            raise self.results
        return self.results.pop(0)


def _scan_result(status="completed", risk_score=0, verdict="safe", indicators=None, **kwargs) -> ScanResult:
    return ScanResult(status=status, risk_score=risk_score, verdict=verdict,
                      indicators=indicators or [], **kwargs)


def _attachment_meta(attachment_id="att-1", filename="invoice.pdf",
                     mime_type="application/pdf", size_bytes=1000) -> dict:
    return {
        "attachment_id": attachment_id,
        "filename": filename,
        "mime_type": mime_type,
        "size_bytes": size_bytes,
        "scan_status": "pending",
    }


# ---------------------------------------------------------------------------
# Shared checks (reused by pytest tests and run_all_tests Suite 34)
# ---------------------------------------------------------------------------

def _check_scorer_basic() -> tuple[bool, str]:
    indicators = [
        {"type": "mime_mismatch", "risk_score": 30, "severity": "medium"},
        {"type": "yara_match", "risk_score": 40, "severity": "medium"},
        {"type": "pdf_javascript", "risk_score": 10, "severity": "high"},
    ]
    result = AttachmentRiskScorer().score(indicators)
    ok = (
        result["risk_score"] == 80
        and result["verdict"] == "malicious"
        and result["severity"] == "critical"
        and len(result["top_indicators"]) == 3
    )
    return ok, f"result={result}"


def _check_scorer_forced_critical() -> tuple[bool, str]:
    scorer = AttachmentRiskScorer()
    low = scorer.score([{"type": "executable_disguise", "risk_score": 40, "severity": "high"}])
    sig = scorer.score([{"type": "clamav_signature", "risk_score": 90, "severity": "critical"}])
    ok = (
        low["verdict"] == "malicious" and low["severity"] == "critical" and low["risk_score"] == 40
        and sig["verdict"] == "malicious" and sig["severity"] == "critical"
    )
    return ok, f"disguise={low} clamav={sig}"


def _check_scorer_explanation() -> tuple[bool, str]:
    indicators = [
        {"type": "low_priority_thing", "risk_score": 5, "severity": "low"},
        {"type": "critical_thing", "risk_score": 50, "severity": "critical", "description": "very bad"},
        {"type": "high_thing", "risk_score": 15, "severity": "high"},
        {"type": "medium_thing", "risk_score": 10, "severity": "medium"},
    ]
    result = AttachmentRiskScorer().score(indicators)
    types = [i["type"] for i in result["top_indicators"]]
    explanation = result["explanation"]
    ok = (
        types[0] == "critical_thing"
        and "critical_thing" in explanation
        and "high_thing" in explanation
        and "very bad" in explanation
    )
    return ok, f"types={types} explanation={explanation}"


def _check_fetch_populates_meta() -> tuple[bool, str]:
    payload = {
        "parts": [
            {"filename": "invoice.pdf", "mimeType": "application/pdf",
             "body": {"attachmentId": "att-1", "size": 12345}},
            {"mimeType": "multipart/mixed", "parts": [
                {"filename": "memo.docx",
                 "mimeType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                 "body": {"attachmentId": "att-2", "size": 456}},
            ]},
            {"mimeType": "text/plain", "body": {"data": "aGVsbG8="}},  # body, not attachment
        ]
    }
    meta = extract_attachments_meta(payload)
    ok = (
        len(meta) == 2
        and all(a["scan_status"] == "pending" for a in meta)
        and meta[0]["attachment_id"] == "att-1"
        and meta[0]["size_bytes"] == 12345
        and meta[1]["filename"] == "memo.docx"
        and {"attachment_id", "filename", "mime_type", "size_bytes", "scan_status"} == set(meta[0].keys())
    )
    return ok, f"meta={meta}"


def _check_fetch_no_attachments() -> tuple[bool, str]:
    payload = {"parts": [{"mimeType": "text/plain", "body": {"data": "aGVsbG8="}}]}
    ok = extract_attachments_meta(payload) == [] and extract_attachments_meta({}) == []
    return ok, "no-attachment payload yielded empty list" if ok else "unexpected metadata"


async def _check_analysis_calls_scanner() -> tuple[bool, str]:
    meta = [_attachment_meta("att-1", "a.pdf"), _attachment_meta("att-2", "b.pdf", size_bytes=2000)]
    scanner = _ScriptedScanner([_scan_result(), _scan_result()])

    await scan_email_attachments(None, "tok", None, "msg-1", meta, scanner=scanner)
    ok = (
        len(scanner.calls) == 2
        and scanner.calls[0][:5] == ("msg-1", "att-1", "a.pdf", "application/pdf", 1000)
        and scanner.calls[1][1] == "att-2"
        and all(a["scan_status"] == "completed" for a in meta)
    )
    return ok, f"calls={scanner.calls}"


async def _check_analysis_aggregates_risk() -> tuple[bool, str]:
    meta = [_attachment_meta()]
    scanner = _ScriptedScanner([
        _scan_result(risk_score=85, verdict="malicious", severity="critical"),
    ])

    await scan_email_attachments(None, "tok", None, "msg-1", meta, scanner=scanner)
    final_risk, override, inds = aggregate_attachment_risk(20, meta)
    ok = final_risk == 85 and override == "malicious" and len(inds) == 0
    return ok, f"risk={final_risk} override={override}"


async def _check_analysis_no_downgrade() -> tuple[bool, str]:
    meta = [_attachment_meta()]
    scanner = _ScriptedScanner([_scan_result(risk_score=30, verdict="suspicious", severity="high")])

    await scan_email_attachments(None, "tok", None, "msg-1", meta, scanner=scanner)
    final_risk, override, _ = aggregate_attachment_risk(90, meta)
    ok = final_risk == 90 and override is None
    return ok, f"risk={final_risk} override={override}"


async def _run_e2e(db_session_maker, payload_bytes: bytes, filename: str) -> dict:
    """Insert user/account/processed_email, run the real analysis pipeline.

    Returns {verdict, severity, explanation, attachment_verdict, risk_score}.
    """
    from sqlalchemy import select

    from app.db.models import GmailAccount, ProcessedEmail, User
    from app.services.gmail import analysis_service as analysis_module

    stamp = uuid.uuid4().hex[:8]
    user_id = f"attach-e2e-{stamp}"
    message_id = f"msg-{stamp}"
    meta = [_attachment_meta("att-e2e-1", filename, size_bytes=len(payload_bytes))]

    # User row first (own commit), then account + processed email — mirrors
    # the Suite-27 seeding pattern and satisfies FK ordering on postgres.
    async with db_session_maker() as db:
        db.add(User(id=user_id, email=f"{user_id}@cyberguard.test", full_name="Attach E2E"))
        await db.commit()

    async with db_session_maker() as db:
        account = GmailAccount(owner_user_id=user_id, email=f"{user_id}@gmail.com", sync_status="active")
        account.set_access_token(f"mock-access-{stamp}")
        account.set_refresh_token(f"mock-refresh-{stamp}")
        db.add(account)
        await db.flush()
        processed = ProcessedEmail(
            owner_user_id=user_id,
            gmail_account_id=account.id,
            gmail_message_id=message_id,
            subject="Quarterly statement",
            sender="finance@example.com",
            received_at=datetime.now(timezone.utc),
            processing_status="fetched",
            attachments_meta=meta,
            signals={
                "normalized_email": {
                    "subject": "Quarterly statement",
                    "sender": "finance@example.com",
                    "body_text": "Please find the statement attached.",
                },
                "urls": [],
                "headers": {"From": "finance@example.com"},
            },
        )
        db.add(processed)
        await db.commit()
        processed_id = processed.id

    async with db_session_maker() as db:
        original = analysis_module._load_gmail_context

        async def _fake_context(_db, _processed):
            return FakeGmailClient([payload_bytes]), "mock-token", None

        analysis_module._load_gmail_context = _fake_context
        try:
            await analysis_module.process_email_analysis(db, processed_id)
        finally:
            analysis_module._load_gmail_context = original

        row = (await db.execute(select(ProcessedEmail).where(ProcessedEmail.id == processed_id))).scalar_one()
        return {
            "verdict": row.verdict,
            "severity": row.severity,
            "explanation": row.explanation or "",
            "risk_score": row.risk_score,
            "attachment": (row.attachments_meta or [{}])[0],
        }


async def _check_e2e_malicious(db_session_maker) -> tuple[bool, str]:
    malicious_pdf = _content_pdf(
        "Please enter your password immediately at http://203.0.113.5/verify/secure-login now"
    ) + b"\n/JavaScript (/JS app.alert(1))\n/OpenAction << /S /JavaScript >>\n/EmbeddedFile << /Name (d) >>"

    result = await _run_e2e(db_session_maker, malicious_pdf, "invoice.pdf")
    scan_results = result["attachment"].get("scan_results") or {}
    ok = (
        result["verdict"] == "malicious"
        and scan_results.get("verdict") == "malicious"
        and "malicious attachment" in result["explanation"].lower()
        and "invoice.pdf" in result["explanation"]
    )
    return ok, f"result={result['verdict']} attachment={scan_results.get('verdict')} explanation={result['explanation'][:120]}"


async def _check_e2e_safe(db_session_maker) -> tuple[bool, str]:
    benign_pdf = _content_pdf("Quarterly revenue grew 4 percent and the meeting is at 3pm.")
    result = await _run_e2e(db_session_maker, benign_pdf, "report.pdf")
    scan_results = result["attachment"].get("scan_results") or {}
    ok = (
        result["verdict"] == "safe"
        and scan_results.get("verdict") == "safe"
        and result["risk_score"] is not None
        and result["risk_score"] < 0.4
    )
    return ok, f"result={result['verdict']} attachment={scan_results.get('verdict')} risk={result['risk_score']}"


def _check_verdict_builder_explanation() -> tuple[bool, str]:
    builder = VerdictBuilder()
    email_indicators = [{"type": "a"}, {"type": "b"}, {"type": "c"}]
    attachments = [{"filename": "trojan.pdf", "scan_results": {"verdict": "malicious"}}]
    result = builder.build_explainable_verdict(85, email_indicators, attachments)
    ok = (
        result["verdict"] == "malicious"
        and result["severity"] == "critical"
        and "3 indicators" in result["explanation"]
        and "malicious attachment" in result["explanation"]
        and "trojan.pdf" in result["explanation"]
    )
    return ok, f"result={result}"


async def _check_scan_failure_recorded() -> tuple[bool, str]:
    meta = [_attachment_meta("att-1", "bad.pdf"), _attachment_meta("att-2", "ok.pdf")]
    scanner = _ScriptedScanner(RuntimeError("engine exploded"))

    await scan_email_attachments(None, "tok", None, "msg-1", meta, scanner=scanner)
    first, second = meta[0]["scan_results"] or {}, meta[1]["scan_results"] or {}
    ok = (
        meta[0]["scan_status"] == "failed"
        and "engine exploded" in str(first.get("error"))
        and meta[1]["scan_status"] == "failed"  # scripted scanner raises for all; loop continued
        and "engine exploded" in str(second.get("error"))
    )
    return ok, f"statuses={[m['scan_status'] for m in meta]} errors={[m.get('scan_results', {}).get('error') for m in meta]}"


async def _check_scan_failure_isolated() -> tuple[bool, str]:
    """A scanner that fails only on the FIRST attachment; the second still scans."""
    meta = [_attachment_meta("att-1", "bad.pdf"), _attachment_meta("att-2", "ok.pdf")]

    class _HalfBroken:
        async def scan_attachment(self, gmail_client, message_id, attachment_id, *args, **kwargs):
            if attachment_id == "att-1":
                raise RuntimeError("engine exploded")
            return _scan_result(risk_score=5, verdict="safe")

    await scan_email_attachments(None, "tok", None, "msg-1", meta, scanner=_HalfBroken())
    ok = (
        meta[0]["scan_status"] == "failed"
        and meta[1]["scan_status"] == "completed"
        and meta[1]["scan_results"]["verdict"] == "safe"
    )
    return ok, f"statuses={[m['scan_status'] for m in meta]}"


# ---------------------------------------------------------------------------
# Pytest tests
# ---------------------------------------------------------------------------

def test_attachment_risk_scorer_basic():
    ok, details = _check_scorer_basic()
    assert ok, details


def test_attachment_risk_scorer_critical_indicator():
    ok, details = _check_scorer_forced_critical()
    assert ok, details


def test_attachment_risk_scorer_explanation():
    ok, details = _check_scorer_explanation()
    assert ok, details


def test_fetch_service_populates_attachments_meta():
    ok, details = _check_fetch_populates_meta()
    assert ok, details


def test_fetch_service_no_attachments():
    ok, details = _check_fetch_no_attachments()
    assert ok, details


async def test_analysis_service_calls_scanner():
    ok, details = await _check_analysis_calls_scanner()
    assert ok, details


async def test_analysis_service_aggregates_risk():
    ok, details = await _check_analysis_aggregates_risk()
    assert ok, details


async def test_analysis_service_no_downgrade():
    ok, details = await _check_analysis_no_downgrade()
    assert ok, details


@pytest.mark.asyncio
async def test_end_to_end_malicious_attachment(initialized_db):
    from app.db.session import async_session_maker

    ok, details = await _check_e2e_malicious(async_session_maker)
    assert ok, details


@pytest.mark.asyncio
async def test_end_to_end_safe_attachment(initialized_db):
    from app.db.session import async_session_maker

    ok, details = await _check_e2e_safe(async_session_maker)
    assert ok, details


def test_verdict_builder_explanation():
    ok, details = _check_verdict_builder_explanation()
    assert ok, details


async def test_scan_failure_recorded():
    ok, details = await _check_scan_failure_recorded()
    assert ok, details


# ---------------------------------------------------------------------------
# run_all_tests.py Suite 34 entry point (12 assertions, same checks)
# ---------------------------------------------------------------------------

async def _await_check(check, *args):
    outcome = check(*args)
    if inspect.isawaitable(outcome):
        outcome = await outcome
    return outcome


async def run_attachment_integration_tests(runner) -> None:
    """Suite 34 — ATTACH-SCAN-4 risk scoring + pipeline integration."""
    from pytest import MonkeyPatch

    from app.db.admin import _get_admin_session_maker

    monkeypatch = MonkeyPatch()
    checks: list[tuple[str, Any]] = [
        ("scorer: 30+40+10 => risk 80, verdict malicious/critical", _check_scorer_basic),
        ("scorer: disguise/clamav indicators force malicious/critical", _check_scorer_forced_critical),
        ("scorer: explanation carries top-3 indicators by severity", _check_scorer_explanation),
        ("fetch: payload with 2 attachments yields pending metadata", _check_fetch_populates_meta),
        ("fetch: message without attachments yields empty list", _check_fetch_no_attachments),
        ("analysis: scan_attachment invoked once per attachment", _check_analysis_calls_scanner),
        ("analysis: attachment risk 85 over body 20 raises email to 85/malicious", _check_analysis_aggregates_risk),
        ("analysis: body risk 90 is not downgraded by attachment risk 30", _check_analysis_no_downgrade),
        ("e2e: malicious PDF attachment => email verdict malicious + explanation", _check_e2e_malicious),
        ("e2e: benign PDF attachment => verdict unchanged, attachment safe", _check_e2e_safe),
        ("verdict: explanation includes body indicators + malicious attachment", _check_verdict_builder_explanation),
        ("isolation: scanner crash records failed + error, loop continues", _check_scan_failure_isolated),
    ]

    admin_maker = _get_admin_session_maker()
    try:
        for name, check in checks:
            try:
                if check in (_check_e2e_malicious, _check_e2e_safe):
                    ok, details = await _await_check(check, admin_maker)
                else:
                    ok, details = await _await_check(check)
                runner.assert_true(ok, name, details)
            except Exception as exc:
                runner.assert_true(False, name, f"unexpected exception: {exc}")
    finally:
        monkeypatch.undo()
