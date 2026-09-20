"""Email fetch service for downloading, MIME parsing, normalizing, and enqueueing analysis."""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NonRetryableError
from app.core.limits import (
    FETCH_TIMEOUT_S,
    MAX_ATTACHMENT_META,
    MAX_BODY_CHARS,
    MAX_EMAIL_BYTES,
    MAX_MIME_PARTS,
    MAX_URLS,
)
from app.core.metrics import (
    email_fetch_jobs_total,
    gmail_api_errors_total,
    job_processing_duration_seconds,
)
from app.db.models import GmailAccount, ProcessedEmail
from app.queue.client import enqueue, make_email_analysis_job_id
from app.schemas.email import NormalizedMessage
from app.services.email_providers.gmail import gmail_provider
from app.services.gmail.client import (
    GmailAuthError,
    GmailClient,
    GmailRateLimitError,
    GmailServerError,
)
from app.services.idempotency_service import ensure_job, ensure_processed_email

logger = logging.getLogger("cyberguard.gmail.fetch")

_URL_PATTERN = re.compile(r"https?://[^\s<>\"'()\[\]{}]+", re.IGNORECASE)
_HTML_HREF_PATTERN = re.compile(r"href=[\"']([^\"']+)[\"']", re.IGNORECASE)


def sanitize_html_to_text(html: str) -> str:
    """Sanitize HTML body by stripping script/style tags, HTML markup, and normalizing whitespace."""
    if not html:
        return ""
    # Strip script and style blocks completely
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    # Strip remaining HTML tags
    text = re.sub(r"<[^>]+>", " ", text)
    # Normalize whitespace
    return re.sub(r"\s+", " ", text).strip()


def _has_plain_text_part(payload: dict) -> bool:
    if payload.get("mimeType") == "text/plain" and payload.get("body", {}).get("data"):
        return True
    for part in payload.get("parts", []) or []:
        if isinstance(part, dict) and _has_plain_text_part(part):
            return True
    return False


def extract_urls(
    body_text: Optional[str],
    body_html: Optional[str],
    max_urls: int = MAX_URLS,
) -> tuple[list[str], bool]:
    """Extract and deduplicate unique URLs from plain text and HTML sources."""
    candidates: list[str] = []
    for source in (body_text or "", body_html or ""):
        candidates.extend(_HTML_HREF_PATTERN.findall(source))
        candidates.extend(_URL_PATTERN.findall(source))

    seen: set[str] = set()
    urls: list[str] = []
    for url in candidates:
        cleaned = url.rstrip(").,;:'\"!?")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            urls.append(cleaned)

    truncated = len(urls) > max_urls
    return urls[:max_urls], truncated


def parse_auth_headers(headers: dict[str, str]) -> dict[str, Any]:
    """Extract authentication results (SPF, DKIM, DMARC) and headers for threat signals."""
    h_lower = {k.lower(): v for k, v in headers.items()}
    auth_results = h_lower.get("authentication-results", "")
    received_spf = h_lower.get("received-spf", "")
    return_path = h_lower.get("return-path", "")
    has_dkim = "dkim-signature" in h_lower

    spf: Optional[str] = None
    if "spf=" in auth_results.lower():
        m = re.search(r"spf=([a-z]+)", auth_results, re.IGNORECASE)
        if m:
            spf = m.group(1).lower()
    elif received_spf:
        first_token = received_spf.split()[0].lower() if received_spf.split() else ""
        if first_token in ("pass", "fail", "softfail", "neutral", "none"):
            spf = first_token

    dkim: Optional[str] = None
    if "dkim=" in auth_results.lower():
        m = re.search(r"dkim=([a-z]+)", auth_results, re.IGNORECASE)
        if m:
            dkim = m.group(1).lower()
    elif has_dkim:
        dkim = "present"

    dmarc: Optional[str] = None
    if "dmarc=" in auth_results.lower():
        m = re.search(r"dmarc=([a-z]+)", auth_results, re.IGNORECASE)
        if m:
            dmarc = m.group(1).lower()

    return {
        "return_path": return_path or None,
        "received_spf": received_spf or None,
        "has_dkim_signature": has_dkim,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "authentication_results": auth_results or None,
    }


def extract_attachments_meta(payload: dict, max_attachments: int = MAX_ATTACHMENT_META) -> list[dict]:
    """Collect attachment metadata from a Gmail payload WITHOUT downloading bytes.

    Walks MIME parts recursively (attachments can sit inside nested
    multipart containers). Each entry carries {attachment_id, filename,
    mime_type, size_bytes, scan_status: "pending"} — the analysis worker
    later streams the bytes and fills scan_results (ATTACH-SCAN Phase 4).
    """
    meta: list[dict] = []

    def _walk(part: dict) -> None:
        if len(meta) >= max_attachments:
            return
        body = part.get("body", {}) or {}
        filename = part.get("filename") or ""
        attachment_id = body.get("attachmentId")
        if filename or attachment_id:
            meta.append(
                {
                    "attachment_id": attachment_id,
                    "filename": filename,
                    "mime_type": part.get("mimeType") or "application/octet-stream",
                    "size_bytes": int(body.get("size") or 0),
                    "scan_status": "pending",
                }
            )
            return  # attachment parts have no sub-parts worth walking
        for sub in part.get("parts", []) or []:
            if isinstance(sub, dict):
                _walk(sub)

    root = payload or {}
    if root.get("filename") or (root.get("body", {}) or {}).get("attachmentId"):
        _walk(root)
    for part in root.get("parts", []) or []:
        if isinstance(part, dict):
            _walk(part)
    return meta


async def process_email_fetch(
    db: AsyncSession,
    account_id: str,
    message_id: str,
    client: Optional[GmailClient] = None,
    redis_pool: Optional[Any] = None,
) -> dict[str, Any]:
    """Fetch raw email from Gmail, parse MIME into NormalizedMessage, store, and enqueue analysis.

    1. Idempotency: ensure_processed_email. If already fetched/analyzing/analyzed/completed, skip.
    2. Transition processed_emails -> 'fetching'.
    3. Decrypt token and call GmailClient.get_message(format='full', timeout=FETCH_TIMEOUT_S).
    4. REUSE Phase-2/3 MIME parser (gmail_provider._normalize). Enforce limits.
    5. Security: strip HTML to sanitized text; store URLs as untrusted strings; metadata-only attachments.
    6. Capture auth headers (Return-Path, SPF, DKIM, DMARC) into signals.
    7. Update processed_emails: subject, sender, received_at, normalized_email, headers, urls, size; status -> 'fetched'.
    8. Enqueue email_analysis job with deterministic ID and payload {processed_email_id}.
    9. Error classification: 401 -> reauth_required; transient -> retry; NonRetryableError -> dead_letter.
    """
    start_time = time.perf_counter()

    stmt = select(GmailAccount).where(GmailAccount.id == account_id)
    account = (await db.execute(stmt)).scalar_one_or_none()
    if account is None:
        logger.warning("Gmail account %s not found for email fetch", account_id)
        return {"status": "not_found", "message_id": message_id}

    # 1. Ensure processed_email idempotency check
    processed_email = await ensure_processed_email(
        db,
        owner_user_id=account.owner_user_id,
        gmail_message_id=message_id,
        gmail_account_id=account.id,
    )

    if processed_email.processing_status in ("fetched", "analyzing", "analyzed", "completed"):
        logger.info(
            "Email %s already in status '%s'; skipping fetch",
            message_id,
            processed_email.processing_status,
        )
        return {
            "status": "skipped",
            "reason": f"already_{processed_email.processing_status}",
            "processed_email_id": processed_email.id,
        }

    # 2. Transition processed_emails -> fetching
    processed_email.processing_status = "fetching"
    processed_email.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(processed_email)

    # 3. Decrypt token and fetch message from Gmail
    access_token = account.get_access_token()
    refresh_token = account.get_refresh_token()
    gmail = client or GmailClient()

    try:
        raw_message = await gmail.get_message(
            access_token=access_token or "",
            message_id=message_id,
            format="full",
            timeout=FETCH_TIMEOUT_S,
            refresh_token=refresh_token,
        )
    except GmailAuthError:
        account.sync_status = "error"
        account.last_error = "reauth_required"
        account.updated_at = datetime.now(timezone.utc)
        await db.commit()
        duration = time.perf_counter() - start_time
        try:
            job_processing_duration_seconds.labels(job_type="email_fetch").observe(duration)
            email_fetch_jobs_total.labels(status="failed", failure_reason="auth").inc()
            gmail_api_errors_total.labels(error_type="auth").inc()
        except Exception:
            pass
        raise
    except GmailRateLimitError:
        duration = time.perf_counter() - start_time
        try:
            job_processing_duration_seconds.labels(job_type="email_fetch").observe(duration)
            email_fetch_jobs_total.labels(status="failed", failure_reason="rate_limit").inc()
            gmail_api_errors_total.labels(error_type="rate_limit").inc()
        except Exception:
            pass
        raise
    except GmailServerError:
        duration = time.perf_counter() - start_time
        try:
            job_processing_duration_seconds.labels(job_type="email_fetch").observe(duration)
            email_fetch_jobs_total.labels(status="failed", failure_reason="server").inc()
            gmail_api_errors_total.labels(error_type="server").inc()
        except Exception:
            pass
        raise

    # 4. Enforce Limits & Parse MIME using reused Phase-2/3 parser
    size_bytes = int(
        raw_message.get("sizeEstimate")
        or raw_message.get("size")
        or len(json.dumps(raw_message))
    )
    if size_bytes > MAX_EMAIL_BYTES:
        err = NonRetryableError(
            f"Email size {size_bytes} exceeds limit of {MAX_EMAIL_BYTES} bytes",
            reason="size_exceeded",
        )
        processed_email.processing_status = "failed"
        if processed_email.signals is None:
            processed_email.signals = {}
        processed_email.signals["error"] = err.reason
        processed_email.signals["failure_reason"] = err.reason
        processed_email.updated_at = datetime.now(timezone.utc)
        await db.commit()
        duration = time.perf_counter() - start_time
        try:
            job_processing_duration_seconds.labels(job_type="email_fetch").observe(duration)
            email_fetch_jobs_total.labels(status="failed", failure_reason=err.reason).inc()
        except Exception:
            pass
        raise err

    # Truncate parts if MIME parts exceed limit
    truncated_parts = False
    payload = raw_message.get("payload", {}) or {}
    if "parts" in payload and isinstance(payload["parts"], list):
        if len(payload["parts"]) > MAX_MIME_PARTS:
            payload["parts"] = payload["parts"][:MAX_MIME_PARTS]
            truncated_parts = True

    try:
        normalized: NormalizedMessage = gmail_provider._normalize(message_id, raw_message)
    except Exception as exc:
        logger.warning("Corrupted MIME payload for message %s: %s", message_id, exc)
        raise ValueError(f"Corrupted MIME parsing failure: {exc}") from exc

    # Truncate body if body chars exceed limit
    if normalized.body_text and len(normalized.body_text) > MAX_BODY_CHARS:
        normalized.body_text = normalized.body_text[:MAX_BODY_CHARS]
    if normalized.body_html and len(normalized.body_html) > MAX_BODY_CHARS:
        normalized.body_html = normalized.body_html[:MAX_BODY_CHARS]


    # 5. Security: HTML sanitization (no script/style execution) & attachment limits
    if normalized.body_html and not _has_plain_text_part(payload):
        normalized.body_text = sanitize_html_to_text(normalized.body_html)
    elif normalized.body_text and ("<script" in normalized.body_text.lower() or "<style" in normalized.body_text.lower()):
        normalized.body_text = sanitize_html_to_text(normalized.body_text)

    urls, truncated_urls = extract_urls(normalized.body_text, normalized.body_html, max_urls=MAX_URLS)
    attachments_meta = (normalized.attachments_meta or [])[:MAX_ATTACHMENT_META]

    # Phase 4: mission-schema attachment metadata (pending scan) persisted to
    # the processed_emails.attachments_meta column; bytes are NOT downloaded
    # here — the analysis worker streams them per attachment.
    scan_attachments_meta = extract_attachments_meta(payload)
    # Backfill from the provider walk when Gmail omits size/attachmentId on
    # one path but the other captured it (defensive; both read the same parts).
    provider_by_name = {
        (a.get("filename") or "", a.get("mime_type") or ""): a for a in attachments_meta
    }
    for entry in scan_attachments_meta:
        provider_entry = provider_by_name.get((entry["filename"], entry["mime_type"]))
        if provider_entry:
            entry["attachment_id"] = entry["attachment_id"] or provider_entry.get("attachment_id")
            entry["size_bytes"] = entry["size_bytes"] or int(provider_entry.get("size") or 0)

    # 6. Capture auth headers
    auth_signals = parse_auth_headers(normalized.headers)

    # 7. Update processed_emails record
    norm_dict = normalized.model_dump(mode="json") if hasattr(normalized, "model_dump") else normalized.dict()
    processed_email.subject = normalized.subject or ""
    processed_email.sender = normalized.sender or ""
    if normalized.received_at:
        processed_email.received_at = normalized.received_at

    signals_payload: dict[str, Any] = {
        "normalized_email": norm_dict,
        "headers": normalized.headers,
        "urls": urls,
        "size_bytes": size_bytes,
        "truncated_urls": truncated_urls,
        "truncated_parts": truncated_parts,
        "attachments_meta": attachments_meta,
        **auth_signals,
    }

    processed_email.signals = signals_payload
    processed_email.attachments_meta = scan_attachments_meta
    processed_email.processing_status = "fetched"
    processed_email.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(processed_email)

    # 8. Enqueue email_analysis job
    analysis_job_id = make_email_analysis_job_id(account.owner_user_id, message_id)
    analysis_payload = {"processed_email_id": str(processed_email.id)}

    await ensure_job(
        db,
        owner_user_id=account.owner_user_id,
        job_type="email_analysis",
        job_id=analysis_job_id,
        payload=analysis_payload,
    )

    try:
        await enqueue(
            "email_analysis",
            kwargs=analysis_payload,
            job_id=analysis_job_id,
        )
    except Exception as exc:
        logger.warning("Failed to enqueue email_analysis to Redis (job %s): %s", analysis_job_id, exc)

    logger.info(
        "Successfully fetched and normalized email %s (processed_email_id=%s, enqueued analysis job=%s)",
        message_id,
        processed_email.id,
        analysis_job_id,
    )
    duration = time.perf_counter() - start_time
    try:
        job_processing_duration_seconds.labels(job_type="email_fetch").observe(duration)
        email_fetch_jobs_total.labels(status="success", failure_reason="none").inc()
    except Exception:
        pass

    return {
        "status": "fetched",
        "processed_email_id": processed_email.id,
        "analysis_job_id": analysis_job_id,
        "urls_count": len(urls),
        "size_bytes": size_bytes,
    }
