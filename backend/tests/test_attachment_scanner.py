"""Tests for ATTACH-SCAN Phase 1 — memory-safe attachment scanning foundation.

Covers the streamer (temp file + sha256 + limits), the file validator
(magic bytes, MIME mismatch), and the Level-1 scanner pipeline. Also exposes
run_attachment_scanner_tests(runner) so scripts/run_all_tests.py can count
these as Suite 31.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from typing import Any

import pytest

from app.core.attachment_limits import MAX_ATTACHMENT_SIZE_BYTES, MEMORY_CRITICAL_THRESHOLD_MB
from app.core.errors import AttachmentTooLargeError, MemoryLimitExceededError
from app.services.attachment_scanner import AttachmentScanner
from app.services.attachment_streamer import AttachmentStreamer
from app.services.file_validator import FileValidator


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class FakeGmailClient:
    """Yields canned attachment chunks, mimicking GmailClient.stream_attachment."""

    def __init__(self, chunks: list[bytes]):
        self.chunks = chunks
        self.calls: list[dict[str, Any]] = []

    async def stream_attachment(self, message_id, attachment_id, chunk_size=65536, **kwargs):
        self.calls.append(
            {"message_id": message_id, "attachment_id": attachment_id, "chunk_size": chunk_size, **kwargs}
        )
        for chunk in self.chunks:
            yield chunk


class _FakeMemoryInfo:
    def __init__(self, rss_bytes: int):
        self.rss = rss_bytes


# ---------------------------------------------------------------------------
# Shared checks (reused by pytest tests and run_all_tests Suite 31)
# ---------------------------------------------------------------------------

async def _check_stream_to_temp_file() -> tuple[bool, str]:
    chunks = [b"hello ", b"attachment ", b"world"]
    client = FakeGmailClient(chunks)
    streamer = AttachmentStreamer()

    temp_path, sha256, size = await streamer.stream_to_temp_file(client, "msg-1", "att-1", sum(map(len, chunks)))
    expected_payload = b"".join(chunks)

    try:
        ok_hash = sha256 == hashlib.sha256(expected_payload).hexdigest() and len(sha256) == 64
        ok_size = size == len(expected_payload)
        ok_file = os.path.exists(temp_path)
        ok_mode = stat.S_IMODE(os.stat(temp_path).st_mode) == 0o600
        streamer.cleanup_temp_file(temp_path)
        cleaned = not os.path.exists(temp_path)
        return (
            ok_hash and ok_size and ok_file and ok_mode and cleaned,
            f"hash_ok={ok_hash} size_ok={ok_size} file_ok={ok_file} mode_600={ok_mode} cleaned={cleaned}",
        )
    finally:
        streamer.cleanup_temp_file(temp_path)


async def _check_oversized_rejected() -> tuple[bool, str]:
    client = FakeGmailClient([b"x"])
    streamer = AttachmentStreamer()
    try:
        await streamer.stream_to_temp_file(client, "msg-1", "att-1", MAX_ATTACHMENT_SIZE_BYTES + 1)
        return False, "AttachmentTooLargeError not raised for oversized expected_size"
    except AttachmentTooLargeError:
        return True, ""


def _check_detect_pdf(tmp_dir: str) -> tuple[bool, str]:
    path = os.path.join(tmp_dir, "invoice.pdf")
    with open(path, "wb") as f:
        f.write(b"%PDF-1.7\n%cyberguard-test\n")
    detected = FileValidator().detect_file_type(path)
    return detected == "application/pdf", f"detected={detected}"


def _check_mime_mismatch(tmp_dir: str) -> tuple[bool, str]:
    validator = FileValidator()
    path = os.path.join(tmp_dir, "invoice.pdf.exe")
    with open(path, "wb") as f:
        f.write(b"MZ\x90\x00" + b"\x00" * 12)

    detected = validator.detect_file_type(path)
    validation = validator.validate_mime_type("application/pdf", detected)
    ok = validation["mismatch"] is True and validation["risk_score"] > 0
    return ok, f"validation={validation}"


def _check_sha256_streaming(tmp_dir: str) -> tuple[bool, str]:
    payload = os.urandom(200_000)  # spans multiple 64 KB chunks
    path = os.path.join(tmp_dir, "blob.bin")
    with open(path, "wb") as f:
        f.write(payload)
    digest = FileValidator().calculate_sha256_streaming(path)
    expected = hashlib.sha256(payload).hexdigest()
    return digest == expected and len(digest) == 64, f"digest={digest[:16]}... expected={expected[:16]}..."


async def _check_scan_unsupported_type() -> tuple[bool, str]:
    client = FakeGmailClient([b"\x00\x01\x02binary-goo"])
    scanner = AttachmentScanner()
    result = await scanner.scan_attachment(
        client, "msg-1", "att-1", "payload.xyz", "application/octet-stream", 16
    )
    ok = result.status == "skipped" and result.verdict == "safe" and not os.path.exists(result.temp_path or "")
    return ok, f"status={result.status} verdict={result.verdict} error={result.error}"


async def _check_scan_basic_validation() -> tuple[bool, str]:
    payload = b"%PDF-1.4\nclean document"
    client = FakeGmailClient([payload[:8], payload[8:]])
    scanner = AttachmentScanner()
    result = await scanner.scan_attachment(
        client, "msg-1", "att-2", "report.pdf", "application/pdf", len(payload)
    )
    ok = (
        result.status == "completed"
        and result.sha256 == hashlib.sha256(payload).hexdigest()
        and result.detected_mime == "application/pdf"
        and result.mime_mismatch is False
        and result.risk_score == 0
        and not os.path.exists(result.temp_path or "")
    )
    return ok, f"result={result}"


async def _check_memory_monitoring(monkeypatch) -> tuple[bool, str]:
    import psutil as real_psutil

    import app.services.attachment_streamer as streamer_module

    # Growth measured from the current process baseline, so the fake RSS must
    # report the baseline on the streamer's first sample (its own baseline)
    # and baseline + growth afterwards.
    baseline_bytes = real_psutil.Process().memory_info().rss
    growth_bytes = (MEMORY_CRITICAL_THRESHOLD_MB + 256) * 1024 * 1024

    class _CountingProcess:
        def __init__(self):
            self.calls = 0

        def memory_info(self) -> _FakeMemoryInfo:
            self.calls += 1
            if self.calls == 1:
                return _FakeMemoryInfo(baseline_bytes)
            return _FakeMemoryInfo(baseline_bytes + growth_bytes)

    class _FakePsutil:
        @staticmethod
        def Process():
            return _CountingProcess()

    monkeypatch.setattr(streamer_module, "psutil", _FakePsutil)

    client = FakeGmailClient([b"a" * 1024])
    streamer = AttachmentStreamer()
    try:
        await streamer.stream_to_temp_file(client, "msg-1", "att-1", 1024)
        return False, "MemoryLimitExceededError not raised when scan memory growth exceeds threshold"
    except MemoryLimitExceededError:
        return True, ""


# ---------------------------------------------------------------------------
# Pytest tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_stream_to_temp_file():
    ok, details = await _check_stream_to_temp_file()
    assert ok, details


@pytest.mark.asyncio
async def test_oversized_attachment_rejected():
    ok, details = await _check_oversized_rejected()
    assert ok, details


def test_detect_pdf_magic_bytes(tmp_path):
    ok, details = _check_detect_pdf(str(tmp_path))
    assert ok, details


def test_mime_mismatch_detection(tmp_path):
    ok, details = _check_mime_mismatch(str(tmp_path))
    assert ok, details


def test_sha256_streaming(tmp_path):
    ok, details = _check_sha256_streaming(str(tmp_path))
    assert ok, details


@pytest.mark.asyncio
async def test_scan_unsupported_type():
    ok, details = await _check_scan_unsupported_type()
    assert ok, details


@pytest.mark.asyncio
async def test_scan_basic_validation():
    ok, details = await _check_scan_basic_validation()
    assert ok, details


@pytest.mark.asyncio
async def test_memory_monitoring(monkeypatch):
    ok, details = await _check_memory_monitoring(monkeypatch)
    assert ok, details


# ---------------------------------------------------------------------------
# run_all_tests.py Suite 31 entry point (8 assertions, same checks)
# ---------------------------------------------------------------------------

async def run_attachment_scanner_tests(runner) -> None:
    """Suite 31 — ATTACH-SCAN-1 attachment scanning foundation."""
    from pytest import MonkeyPatch

    monkeypatch = MonkeyPatch()
    checks = [
        ("streamer downloads to 0600 temp file with correct sha256 and cleans up", _check_stream_to_temp_file),
        ("oversized attachment rejected with AttachmentTooLargeError", _check_oversized_rejected),
        ("validator detects PDF magic bytes as application/pdf", lambda: _async_wrap(_check_detect_pdf(tempfile.mkdtemp(prefix="cg_pdf_")))),
        ("MIME mismatch (declared pdf / detected exe) flagged with risk score", lambda: _async_wrap(_check_mime_mismatch(tempfile.mkdtemp(prefix="cg_exe_")))),
        ("sha256 streaming hash matches across chunk boundaries", lambda: _async_wrap(_check_sha256_streaming(tempfile.mkdtemp(prefix="cg_sha_")))),
        ("unsupported attachment type is skipped as safe", _check_scan_unsupported_type),
        ("valid PDF completes Level-1 scan and temp file is deleted", _check_scan_basic_validation),
        ("scan aborts with MemoryLimitExceededError past memory threshold", lambda: _check_memory_monitoring(monkeypatch)),
    ]

    for name, check in checks:
        try:
            ok, details = await check()
            runner.assert_true(ok, name, details)
        except Exception as exc:
            runner.assert_true(False, name, f"unexpected exception: {exc}")
    monkeypatch.undo()  # the memory-fake must not leak into later suites


async def _async_wrap(value: tuple[bool, str]) -> tuple[bool, str]:
    return value
