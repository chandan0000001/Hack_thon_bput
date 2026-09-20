"""Tests for ATTACH-SCAN Phase 3 — content analysis layer.

Covers the PDF analyzer (structure indicators, corrupt handling, URL
harvest), Office analyzer (VBA/OLE, macro extensions, external objects,
hyperlinks), the URL extractor (deobfuscation + hand-off to the existing
url engine), the text phishing analyzer (shared vocabulary, cap), and the
Level-3 integration in AttachmentScanner (engine isolation, full pipeline).
Also exposes run_content_analysis_tests(runner) for run_all_tests Suite 33.
"""

from __future__ import annotations

import glob
import inspect
import os
import tempfile
import zipfile
from typing import Any

import pytest

from app.services import url_detector as url_engine
from app.services.attachment_scanner import AttachmentScanner
from app.services.attachment_text_analyzer import AttachmentTextAnalyzer
from app.services.attachment_url_extractor import AttachmentUrlExtractor
from app.services.office_analyzer import OfficeAnalyzer
from app.services.pdf_analyzer import PdfAnalyzer

from test_attachment_scanner import FakeGmailClient  # shared fake (tests dir on sys.path)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def _build_pdf(objects: dict[int, bytes]) -> bytes:
    """Assemble a structurally valid PDF with a correct xref table."""
    out = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + objects[num] + b"\nendobj\n"
    xref_pos = len(out)
    count = max(objects) + 1
    out += b"xref\n0 %d\n" % count
    out += b"0000000000 65535 f \n"
    for num in range(1, count):
        out += b"%010d 00000 n \n" % offsets[num]
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (count, xref_pos)
    return bytes(out)


def _content_pdf(visible_text: str, extra_page_dict: bytes = b"") -> bytes:
    """Single-page PDF whose visible text is extractable by pypdf."""
    content = ("BT /F1 12 Tf 72 720 Td (%s) Tj ET" % visible_text).encode("latin-1")
    return _build_pdf(
        {
            1: b"<< /Type /Catalog /Pages 2 0 R >>",
            2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R " + extra_page_dict + b">>",
            4: b"<< /Length %d >>\nstream\n%sendstream" % (len(content), content),
            5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        }
    )


def _pdf_with_uri_annotation(url: str) -> bytes:
    annot = b"<< /Type /Annot /Subtype /Link /Rect [0 0 100 20] /A << /S /URI /URI (%s) >> >>" % url.encode()
    content = b"BT /F1 12 Tf 72 720 Td (click here) Tj ET"
    return _build_pdf(
        {
            1: b"<< /Type /Catalog /Pages 2 0 R >>",
            2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] /Contents 5 0 R >>",
            4: annot,
            5: b"<< /Length %d >>\nstream\n%sendstream" % (len(content), content),
        }
    )


def _make_ooxml(members: dict[str, bytes]) -> bytes:
    buf = tempfile.NamedTemporaryFile(suffix=".ooxml", delete=False)
    buf.close()
    with zipfile.ZipFile(buf.name, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
    return buf.name  # caller unlinks


_RELS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"


def _rels_xml(relations: str) -> bytes:
    return ('<?xml version="1.0"?><Relationships xmlns="%s">%s</Relationships>' % (_RELS_NS, relations)).encode()


# ---------------------------------------------------------------------------
# Shared checks (reused by pytest tests and run_all_tests Suite 33)
# ---------------------------------------------------------------------------

def _check_pdf_javascript_indicator() -> tuple[bool, str]:
    path = os.path.join(tempfile.mkdtemp(prefix="cg_pdf3_"), "doc.pdf")
    with open(path, "wb") as f:
        f.write(b"%PDF-1.7\n/JavaScript (/JS app.alert(1))\n%%EOF")
    result = PdfAnalyzer().analyze(path, mime_type="application/pdf")
    types = [i["type"] for i in result["indicators"]]
    ok = "pdf_javascript" in types and result["risk_score"] >= 25
    return ok, f"types={types} risk={result['risk_score']}"


def _check_pdf_embedded_file() -> tuple[bool, str]:
    path = os.path.join(tempfile.mkdtemp(prefix="cg_pdf3_"), "doc.pdf")
    with open(path, "wb") as f:
        f.write(b"%PDF-1.7\n/EmbeddedFile << /Name (dropper) >>\n%%EOF")
    result = PdfAnalyzer().analyze(path, mime_type="application/pdf")
    types = [i["type"] for i in result["indicators"]]
    ok = "pdf_embedded_file" in types and result["risk_score"] >= 20
    return ok, f"types={types} risk={result['risk_score']}"


def _check_pdf_auto_action() -> tuple[bool, str]:
    path = os.path.join(tempfile.mkdtemp(prefix="cg_pdf3_"), "doc.pdf")
    with open(path, "wb") as f:
        f.write(b"%PDF-1.7\n/OpenAction << /S /JavaScript >>\n%%EOF")
    result = PdfAnalyzer().analyze(path, mime_type="application/pdf")
    types = [i["type"] for i in result["indicators"]]
    ok = "pdf_auto_action" in types and result["risk_score"] >= 25
    return ok, f"types={types} risk={result['risk_score']}"


def _check_pdf_corrupt_graceful() -> tuple[bool, str]:
    path = os.path.join(tempfile.mkdtemp(prefix="cg_pdf3_"), "garbage.pdf")
    with open(path, "wb") as f:
        f.write(b"\x00\x01this is not really a pdf at all\x02\x03")
    result = PdfAnalyzer().analyze(path, mime_type="application/pdf")
    types = [i["type"] for i in result["indicators"]]
    ok = "pdf_corrupt" in types and result["risk_score"] >= 15 and result["page_count"] == 0
    return ok, f"types={types} risk={result['risk_score']}"


def _check_pdf_url_extraction() -> tuple[bool, str]:
    url = "https://evil.example.com/verify-login"
    path = os.path.join(tempfile.mkdtemp(prefix="cg_pdf3_"), "annot.pdf")
    with open(path, "wb") as f:
        f.write(_pdf_with_uri_annotation(url))
    result = PdfAnalyzer().analyze(path, mime_type="application/pdf")
    ok = url in result["urls_found"]
    return ok, f"urls={result['urls_found']}"


def _check_office_macro_docm() -> tuple[bool, str]:
    path = _make_ooxml(
        {
            "[Content_Types].xml": _rels_xml(""),
            "word/document.xml": b"<w:document/>",
            "word/vbaProject.bin": b"\xd0\xcf\x11\xe0fake-vba-project",
        }
    )
    try:
        result = OfficeAnalyzer().analyze(path, mime_type="application/vnd.ms-word.document.macroEnabled.12",
                                          original_filename="evil.docm")
    finally:
        os.unlink(path)
    types = [i["type"] for i in result["indicators"]]
    ok = result["has_macros"] is True and "office_macro_present" in types and result["risk_score"] >= 30
    return ok, f"types={types} has_macros={result['has_macros']}"


def _check_office_macro_enabled_ext() -> tuple[bool, str]:
    path = _make_ooxml({"xl/workbook.xml": b"<workbook/>", "[Content_Types].xml": _rels_xml("")})
    try:
        result = OfficeAnalyzer().analyze(path, mime_type="application/vnd.ms-excel.sheet.macroEnabled.12",
                                          original_filename="sheet.xlsm")
    finally:
        os.unlink(path)
    types = [i["type"] for i in result["indicators"]]
    ok = "macro_enabled_extension" in types and result["risk_score"] >= 15
    return ok, f"types={types} risk={result['risk_score']}"


def _check_office_external_object() -> tuple[bool, str]:
    rels = _rels_xml(
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" '
        'Target="http://evil.example.com/payload.bin" TargetMode="External"/>'
    )
    path = _make_ooxml({"word/document.xml": b"<w:document/>", "word/_rels/document.xml.rels": rels})
    try:
        result = OfficeAnalyzer().analyze(path, mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                          original_filename="doc.docx")
    finally:
        os.unlink(path)
    types = [i["type"] for i in result["indicators"]]
    ok = "office_external_object" in types and result["risk_score"] >= 20
    return ok, f"types={types} risk={result['risk_score']}"


def _check_office_url_extraction() -> tuple[bool, str]:
    rels = _rels_xml(
        '<Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
        'Target="https://phishing.example.com/verify-login" TargetMode="External"/>'
    )
    path = _make_ooxml({"word/document.xml": b"<w:document/>", "word/_rels/document.xml.rels": rels})
    try:
        result = OfficeAnalyzer().analyze(path, mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                          original_filename="doc.docx")
    finally:
        os.unlink(path)
    ok = "https://phishing.example.com/verify-login" in result["urls_found"]
    return ok, f"urls={result['urls_found']}"


def _check_text_url_deobfuscation() -> tuple[bool, str]:
    extractor = AttachmentUrlExtractor()
    urls = extractor.extract_from_text("see hxxp://evil[.]com/path1 and (http://plain[.]example.org/a)")
    ok = "http://evil.com/path1" in urls and "http://plain.example.org/a" in urls
    return ok, f"urls={urls}"


def _check_url_handoff_reuses_existing(monkeypatch) -> tuple[bool, str]:
    calls: list[str] = []

    def _fake_engine(url: str) -> list[dict]:
        calls.append(url)
        return [{"type": "ip_host", "severity": "critical", "description": "raw IP host"}]

    monkeypatch.setattr(url_engine, "analyze_url_heuristics", _fake_engine)

    extractor = AttachmentUrlExtractor()
    results = extractor.hand_off(["http://203.0.113.5/verify/login"])
    ok = (
        calls == ["http://203.0.113.5/verify/login"]
        and len(results) == 1
        and results[0]["flagged"] is True
        and results[0]["existing_risk"] == 25  # scoring_service critical weight
    )
    return ok, f"calls={calls} results={results}"


def _check_text_phishing_keywords() -> tuple[bool, str]:
    analyzer = AttachmentTextAnalyzer()
    result = analyzer.analyze("Please enter your password immediately - your account will be terminated")
    types = [i["type"] for i in result["indicators"]]
    ok = (
        "attachment_credential_request" in types
        and "attachment_urgency" in types
        and result["risk_score"] > 0
    )
    return ok, f"types={types} risk={result['risk_score']}"


def _check_text_cap() -> tuple[bool, str]:
    path = os.path.join(tempfile.mkdtemp(prefix="cg_txt3_"), "big.txt")
    with open(path, "w") as f:
        f.write("a" * 300_000 + " verify your account")
    analyzer = AttachmentTextAnalyzer()
    text = analyzer.extract_text(path, "text/plain")
    result = analyzer.analyze(text)
    ok = len(text) <= 200_000 and result["char_count"] == len(text)
    return ok, f"len={len(text)} char_count={result['char_count']}"


async def _check_engine_isolation(monkeypatch) -> tuple[bool, str]:
    payload = _content_pdf("benign quarterly report")

    scanner = AttachmentScanner()

    def _boom(file_path, mime_type=None):
        raise RuntimeError("pdf analyzer exploded")

    monkeypatch.setattr(scanner.pdf, "analyze", _boom)

    result = await scanner.scan_attachment(
        FakeGmailClient([payload]), "msg-1", "att-1", "doc.pdf", "application/pdf", len(payload)
    )

    engine_errors = [i for i in result.indicators if i.get("type") == "engine_error"]
    ok = (
        result.status == "completed"
        and len(engine_errors) == 1
        and engine_errors[0].get("engine") == "pdf"
        and engine_errors[0].get("severity") == "info"
    )
    return ok, f"errors={engine_errors} status={result.status}"


async def _check_level3_full_pipeline() -> tuple[bool, str]:
    malicious = _content_pdf(
        "Please enter your password immediately - your account will be terminated "
        "at http://203.0.113.5/verify/secure-login now"
    )
    malicious += b"\n/OpenAction << /S /JavaScript >>\n/EmbeddedFile << /Name (d) >>"

    scanner = AttachmentScanner()
    result = await scanner.scan_attachment(
        FakeGmailClient([malicious]), "msg-1", "att-9", "statement.pdf", "application/pdf", len(malicious)
    )

    types = [i["type"] for i in result.indicators]
    ok = (
        result.status == "completed"
        and result.verdict in ("suspicious", "malicious")
        and result.risk_score >= 40
        and "pdf_javascript" in types
        and "attachment_url_flagged" in types
        and not os.path.exists(result.temp_path or "")
    )
    return ok, f"verdict={result.verdict} risk={result.risk_score} types={types}"


# ---------------------------------------------------------------------------
# Pytest tests
# ---------------------------------------------------------------------------

def test_pdf_javascript_indicator():
    ok, details = _check_pdf_javascript_indicator()
    assert ok, details


def test_pdf_embedded_file():
    ok, details = _check_pdf_embedded_file()
    assert ok, details


def test_pdf_auto_action():
    ok, details = _check_pdf_auto_action()
    assert ok, details


def test_pdf_corrupt_graceful():
    ok, details = _check_pdf_corrupt_graceful()
    assert ok, details


def test_pdf_url_extraction():
    ok, details = _check_pdf_url_extraction()
    assert ok, details


def test_office_macro_docm():
    ok, details = _check_office_macro_docm()
    assert ok, details


def test_office_macro_enabled_ext():
    ok, details = _check_office_macro_enabled_ext()
    assert ok, details


def test_office_external_object():
    ok, details = _check_office_external_object()
    assert ok, details


def test_office_url_extraction():
    ok, details = _check_office_url_extraction()
    assert ok, details


def test_text_url_deobfuscation():
    ok, details = _check_text_url_deobfuscation()
    assert ok, details


def test_url_handoff_reuses_existing(monkeypatch):
    ok, details = _check_url_handoff_reuses_existing(monkeypatch)
    assert ok, details


def test_text_phishing_keywords():
    ok, details = _check_text_phishing_keywords()
    assert ok, details


def test_text_cap():
    ok, details = _check_text_cap()
    assert ok, details


@pytest.mark.asyncio
async def test_engine_isolation(monkeypatch):
    ok, details = await _check_engine_isolation(monkeypatch)
    assert ok, details


@pytest.mark.asyncio
async def test_level3_full_pipeline():
    ok, details = await _check_level3_full_pipeline()
    assert ok, details


# ---------------------------------------------------------------------------
# run_all_tests.py Suite 33 entry point (15 assertions, same checks)
# ---------------------------------------------------------------------------

async def _await_check(check, *args):
    """Run a sync or async check uniformly (sync checks return tuples)."""
    outcome = check(*args)
    if inspect.isawaitable(outcome):
        outcome = await outcome
    return outcome


async def run_content_analysis_tests(runner) -> None:
    """Suite 33 — ATTACH-SCAN-3 content analysis layer."""
    from pytest import MonkeyPatch

    monkeypatch = MonkeyPatch()
    checks: list[tuple[str, Any]] = [
        ("pdf: /JavaScript yields pdf_javascript indicator (risk >= 25)", _check_pdf_javascript_indicator),
        ("pdf: /EmbeddedFile yields pdf_embedded_file indicator", _check_pdf_embedded_file),
        ("pdf: /OpenAction yields pdf_auto_action indicator", _check_pdf_auto_action),
        ("pdf: garbage bytes named .pdf degrade to pdf_corrupt, no crash", _check_pdf_corrupt_graceful),
        ("pdf: URI annotation URL harvested", _check_pdf_url_extraction),
        ("office: vbaProject.bin => has_macros + office_macro_present", _check_office_macro_docm),
        ("office: .xlsm extension flagged macro_enabled_extension", _check_office_macro_enabled_ext),
        ("office: external OLE relationship flagged office_external_object", _check_office_external_object),
        ("office: external hyperlink target harvested", _check_office_url_extraction),
        ("urls: hxxp/[.] deobfuscated to http://evil.com/path1", _check_text_url_deobfuscation),
        ("urls: hand_off invokes the existing url engine and returns flagged", _check_url_handoff_reuses_existing),
        ("text: credential+urgency phrases yield indicators with risk > 0", _check_text_phishing_keywords),
        ("text: extraction capped at 200k chars without crash", _check_text_cap),
        ("isolation: failing pdf engine records info indicator, scan completes", _check_engine_isolation),
        ("pipeline: malicious PDF aggregates content signals into verdict", _check_level3_full_pipeline),
    ]

    try:
        for name, check in checks:
            try:
                if check is _check_url_handoff_reuses_existing:
                    ok, details = await _await_check(check, monkeypatch)
                elif check is _check_engine_isolation:
                    ok, details = await _await_check(check, monkeypatch)
                else:
                    ok, details = await _await_check(check)
                runner.assert_true(ok, name, details)
            except Exception as exc:
                runner.assert_true(False, name, f"unexpected exception: {exc}")
    finally:
        monkeypatch.undo()
