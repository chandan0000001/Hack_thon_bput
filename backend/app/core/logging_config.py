"""Central logging: contextvars propagation, sensitive-data redaction, a unified
human-readable format (local time + client IP + job context), and modular
rotating log files under backend/logs/ (app/api/jobs/connectors/errors).
"""

from __future__ import annotations

import logging
import os
import re
from contextvars import ContextVar
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any, Optional

# Contextvars for distributed asynchronous tracing
current_correlation_id: ContextVar[Optional[str]] = ContextVar("current_correlation_id", default=None)
current_job_id: ContextVar[Optional[str]] = ContextVar("current_job_id", default=None)
current_job_type: ContextVar[Optional[str]] = ContextVar("current_job_type", default=None)
current_user_id: ContextVar[Optional[str]] = ContextVar("current_user_id", default=None)
current_worker_name: ContextVar[Optional[str]] = ContextVar("current_worker_name", default=None)
current_client_ip: ContextVar[Optional[str]] = ContextVar("current_client_ip", default=None)

# Regular expressions for redaction of sensitive credentials and message bodies
_SENSITIVE_PATTERNS = [
    # OAuth tokens
    (re.compile(r"ya29\.[a-zA-Z0-9_\-\.]+"), "[REDACTED_TOKEN]"),
    (re.compile(r"1//[a-zA-Z0-9_\-\.]+"), "[REDACTED_TOKEN]"),
    (re.compile(r"(Bearer\s+)[a-zA-Z0-9_\-\.]+"), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(access_token[\"']?\s*[:=]\s*[\"']?)[^\"'\s,]+", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(refresh_token[\"']?\s*[:=]\s*[\"']?)[^\"'\s,]+", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(password[\"']?\s*[:=]\s*[\"']?)[^\"'\s,]+", re.IGNORECASE), r"\1[REDACTED_SECRET]"),
    (re.compile(r"(client_secret[\"']?\s*[:=]\s*[\"']?)[^\"'\s,]+", re.IGNORECASE), r"\1[REDACTED_SECRET]"),
    # Email content & body payloads
    (re.compile(r"(body(?:_text|_html)?[\"']?\s*[:=]\s*[\"'])(?:\\.|[^\"'\\])*[\"']", re.IGNORECASE), r'\1[REDACTED_BODY]"'),
    (re.compile(r"(attachment_data|content_bytes|raw_content)[\"']?\s*[:=]\s*[\"'](?:\\.|[^\"'\\])*[\"']", re.IGNORECASE), r'\1: "[REDACTED_ATTACHMENT_DATA]"'),
]


def sanitize_sensitive_text(text_val: str) -> str:
    """Scrub sensitive credentials, OAuth tokens, and email body contents from text."""
    if not text_val or not isinstance(text_val, str):
        return str(text_val) if text_val is not None else ""
    cleaned = text_val
    for pattern, replacement in _SENSITIVE_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def set_log_context(
    correlation_id: Optional[str] = None,
    job_id: Optional[str] = None,
    job_type: Optional[str] = None,
    user_id: Optional[str] = None,
    worker_name: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> dict[str, Any]:
    """Set ambient logging context for the current async task execution."""
    if correlation_id is not None:
        current_correlation_id.set(str(correlation_id))
    if job_id is not None:
        current_job_id.set(str(job_id))
    if job_type is not None:
        current_job_type.set(str(job_type))
    if user_id is not None:
        current_user_id.set(str(user_id))
    if worker_name is not None:
        current_worker_name.set(str(worker_name))
    if client_ip is not None:
        current_client_ip.set(str(client_ip))

    return get_log_context()


def set_client_ip(ip: Optional[str]) -> Any:
    """Bind the current HTTP client IP to log context; returns a reset token."""
    if ip:
        current_client_ip.set(str(ip))
    return current_client_ip


def get_client_ip() -> Optional[str]:
    return current_client_ip.get()


def clear_log_context() -> None:
    """Clear all ambient logging context variables to prevent leakage across jobs."""
    current_correlation_id.set(None)
    current_job_id.set(None)
    current_job_type.set(None)
    current_user_id.set(None)
    current_worker_name.set(None)
    current_client_ip.set(None)


def get_log_context() -> dict[str, Optional[str]]:
    """Retrieve current ambient context values."""
    return {
        "correlation_id": current_correlation_id.get(),
        "job_id": current_job_id.get(),
        "job_type": current_job_type.get(),
        "user_id": current_user_id.get(),
        "worker_name": current_worker_name.get(),
        "client_ip": current_client_ip.get(),
    }


class SensitiveDataFilter(logging.Filter):
    """Logging filter to intercept and redact secrets, tokens, and email bodies.

    Only sanitizes fully-composed messages (no %-style args): sanitized args
    would be coerced to str and break printf formatting like %d. Records with
    args are redacted at format time instead (see the formatters below).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str) and not record.args:
            record.msg = sanitize_sensitive_text(record.msg)
        return True


def _resolve_context(record: logging.LogRecord) -> dict[str, Optional[str]]:
    """Resolve context fields from record attributes first, then contextvars."""
    return {
        "correlation_id": getattr(record, "correlation_id", None) or current_correlation_id.get(),
        "job_id": getattr(record, "job_id", None) or current_job_id.get(),
        "job_type": getattr(record, "job_type", None) or current_job_type.get(),
        "user_id": getattr(record, "user_id", None) or current_user_id.get(),
        "worker_name": getattr(record, "worker_name", None) or current_worker_name.get(),
        "client_ip": getattr(record, "client_ip", None) or current_client_ip.get(),
    }


def _local_timestamp(record: logging.LogRecord) -> str:
    """Local-wall-clock timestamp with timezone label, e.g. '2026-09-19 21:10:46,605 IST'."""
    tz = datetime.now().astimezone().tzinfo
    dt = datetime.fromtimestamp(record.created, tz=tz)
    base = dt.strftime("%Y-%m-%d %H:%M:%S")
    tz_label = dt.strftime("%Z") or dt.strftime("%z") or ""
    return f"{base},{int(record.msecs):03d} {tz_label}".rstrip()


class HumanReadableFormatter(logging.Formatter):
    """Unified single-line format: local time, level, module, context (only when
    present), and message. Replaces the null-strewn JSON dumps on the console."""

    def format(self, record: logging.LogRecord) -> str:
        ctx = _resolve_context(record)
        parts = [
            _local_timestamp(record),
            f"[{record.levelname}]",
            f"[{record.name}]",
        ]
        if ctx["client_ip"]:
            parts.append(f"[ip={ctx['client_ip']}]")
        if ctx["user_id"]:
            parts.append(f"[user={ctx['user_id']}]")
        if ctx["job_type"]:
            parts.append(f"[job_type={ctx['job_type']}]")
        if ctx["job_id"]:
            parts.append(f"[job={ctx['job_id'][:12]}]")
        if ctx["worker_name"]:
            parts.append(f"[worker={ctx['worker_name']}]")
        if ctx["correlation_id"]:
            parts.append(f"[corr={ctx['correlation_id'][:12]}]")

        message = sanitize_sensitive_text(record.getMessage())
        line = f"{' '.join(parts)} — {message}"
        if record.exc_info:
            line += "\n" + sanitize_sensitive_text(self.formatException(record.exc_info))
        return line


class StructuredJsonFormatter(logging.Formatter):
    """Structured JSON log formatter with contextvar resolution and token redaction."""

    def format(self, record: logging.LogRecord) -> str:
        import json

        ctx = _resolve_context(record)
        log_obj: dict[str, Any] = {
            "timestamp": _local_timestamp(record),
            "level": record.levelname,
            "logger": record.name,
            "message": sanitize_sensitive_text(record.getMessage()),
            **{k: v for k, v in ctx.items() if v is not None},
        }
        if record.exc_info:
            log_obj["exception"] = sanitize_sensitive_text(self.formatException(record.exc_info))
        return json.dumps(log_obj)


class _NamePrefixFilter(logging.Filter):
    """Route records to a file based on logger-name prefixes."""

    def __init__(self, prefixes: tuple[str, ...]):
        super().__init__()
        self.prefixes = prefixes

    def filter(self, record: logging.LogRecord) -> bool:
        return record.name.startswith(self.prefixes)


_JOB_LOGGERS = ("cyberguard.worker", "cyberguard.queue", "cyberguard.jobs", "cyberguard.scheduler", "arq")
_CONNECTOR_LOGGERS = ("cyberguard.connectors", "cyberguard.gmail", "cyberguard.mail_scanner", "cyberguard.enforcement")
_API_LOGGERS = ("cyberguard.api",)


def _make_file_handler(
    path: Path,
    formatter: logging.Formatter,
    *,
    prefixes: Optional[tuple[str, ...]] = None,
    min_level: Optional[int] = None,
) -> logging.Handler:
    handler = TimedRotatingFileHandler(path, when="midnight", backupCount=14, encoding="utf-8", delay=True)
    handler.setFormatter(formatter)
    handler.addFilter(SensitiveDataFilter())
    if prefixes:
        handler.addFilter(_NamePrefixFilter(prefixes))
    if min_level is not None:
        handler.setLevel(min_level)
    return handler


def configure_structured_logging(level: Optional[int] = None, log_dir: Optional[str] = None) -> None:
    """Configure console + modular rotating file logging.

    Files (backend/logs/, rotated daily, 14 days retained):
      app.log         — everything under the cyberguard namespace
      api.log         — per-request API lines (method, path, status, duration, IP)
      jobs.log        — background workers, queue, scheduler
      connectors.log  — Gmail connector, mail scanning, enforcement pipeline
      errors.log      — WARNING and above from any logger (incl. uvicorn)
    Set LOG_FORMAT=json for machine-readable output instead of the text format.
    """
    if level is None:
        level = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO)
    if log_dir is None:
        log_dir = os.getenv("LOG_DIR") or str(Path(__file__).resolve().parents[2] / "logs")
    logs_path = Path(log_dir)
    logs_path.mkdir(parents=True, exist_ok=True)

    formatter: logging.Formatter = (
        StructuredJsonFormatter() if os.getenv("LOG_FORMAT", "text").lower() == "json" else HumanReadableFormatter()
    )

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    console.addFilter(SensitiveDataFilter())

    root = logging.getLogger()
    root.setLevel(level)
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(console)
    root.addHandler(_make_file_handler(logs_path / "errors.log", formatter, min_level=logging.WARNING))

    cg = logging.getLogger("cyberguard")
    cg.setLevel(level)
    for h in list(cg.handlers):
        cg.removeHandler(h)
    cg.addHandler(_make_file_handler(logs_path / "app.log", formatter))
    cg.addHandler(_make_file_handler(logs_path / "api.log", formatter, prefixes=_API_LOGGERS))
    cg.addHandler(_make_file_handler(logs_path / "jobs.log", formatter, prefixes=_JOB_LOGGERS))
    cg.addHandler(_make_file_handler(logs_path / "connectors.log", formatter, prefixes=_CONNECTOR_LOGGERS))
    cg.propagate = True
