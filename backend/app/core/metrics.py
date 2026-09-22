"""Prometheus metrics export and instrumentation for CyberGuard real-time pipelines."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from prometheus_client import (
    REGISTRY,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

from app.core.config import get_settings

logger = logging.getLogger("cyberguard.metrics")


def _get_or_create(metric_cls: Any, name: str, documentation: str, labelnames: tuple[str, ...] = (), **kwargs: Any) -> Any:
    """Safe metric instantiation preventing duplicate registration errors across module reloads."""
    if name in REGISTRY._names_to_collectors:
        return REGISTRY._names_to_collectors[name]
    return metric_cls(name, documentation, labelnames=labelnames, **kwargs)


# 1. Total Gmail Pub/Sub push notification events received
gmail_events_received_total: Counter = _get_or_create(
    Counter,
    "gmail_events_received_total",
    "Total Gmail Pub/Sub push notification events received",
    labelnames=("owner_user_id",),
)

# 2. Total Gmail sync worker jobs processed
gmail_sync_jobs_total: Counter = _get_or_create(
    Counter,
    "gmail_sync_jobs_total",
    "Total Gmail synchronization jobs processed",
    labelnames=("status",),
)

# 3. Total email fetch worker jobs processed
email_fetch_jobs_total: Counter = _get_or_create(
    Counter,
    "email_fetch_jobs_total",
    "Total email fetch jobs processed",
    labelnames=("status", "failure_reason"),
)

# 4. Total email threat analysis worker jobs processed
email_analysis_jobs_total: Counter = _get_or_create(
    Counter,
    "email_analysis_jobs_total",
    "Total email threat analysis jobs processed",
    labelnames=("status", "classification"),
)

# 5. Background job execution processing duration
job_processing_duration_seconds: Histogram = _get_or_create(
    Histogram,
    "job_processing_duration_seconds",
    "Duration of background job processing in seconds",
    labelnames=("job_type",),
    buckets=(0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0),
)

# 6. Current depth of pending jobs in Redis queue
queue_depth: Gauge = _get_or_create(
    Gauge,
    "queue_depth",
    "Current number of pending jobs in Redis queue",
    labelnames=("queue_name",),
)

# 7. Total unrecoverable poison pill jobs transitioned to dead_letter
dead_letter_jobs_total: Counter = _get_or_create(
    Counter,
    "dead_letter_jobs_total",
    "Total jobs transitioned to dead_letter queue",
    labelnames=("job_type",),
)

# 8. Total Gmail API errors encountered (auth, rate_limit, server)
gmail_api_errors_total: Counter = _get_or_create(
    Counter,
    "gmail_api_errors_total",
    "Total Gmail API errors encountered",
    labelnames=("error_type",),
)

# 9. Total processed emails classified by CyberGuard engines
processed_emails_total: Counter = _get_or_create(
    Counter,
    "processed_emails_total",
    "Total processed emails classified by CyberGuard engines",
    labelnames=("classification",),
)

# 10. Total jobs executed per worker name
worker_jobs_total: Counter = _get_or_create(
    Counter,
    "worker_jobs_total",
    "Total worker jobs processed by worker instance",
    labelnames=("worker_name", "job_type", "status"),
)


# 11. Total Firecrawl live scrapes attempted (success / http_error / rate_limited / error)
firecrawl_scrapes_total: Counter = _get_or_create(
    Counter,
    "firecrawl_scrapes_total",
    "Total Firecrawl scrape attempts by status",
    labelnames=("status",),
)

# 12. Total Firecrawl Redis cache hits (scrape served without an outbound call)
firecrawl_cache_hits_total: Counter = _get_or_create(
    Counter,
    "firecrawl_cache_hits_total",
    "Total Firecrawl scrape cache hits",
)


def init_metrics() -> None:
    """Initialize default metric series so all metric names appear in scrapers immediately."""
    try:
        gmail_events_received_total.labels(owner_user_id="default")
        gmail_sync_jobs_total.labels(status="success")
        gmail_sync_jobs_total.labels(status="failed")
        email_fetch_jobs_total.labels(status="success", failure_reason="none")
        email_analysis_jobs_total.labels(status="success", classification="safe")
        job_processing_duration_seconds.labels(job_type="gmail_sync")
        queue_depth.labels(queue_name="cyberguard:queue")
        dead_letter_jobs_total.labels(job_type="email_fetch")
        gmail_api_errors_total.labels(error_type="auth")
        gmail_api_errors_total.labels(error_type="rate_limit")
        gmail_api_errors_total.labels(error_type="server")
        processed_emails_total.labels(classification="safe")
        processed_emails_total.labels(classification="phishing")
        processed_emails_total.labels(classification="suspicious")
        for w in ("gmail-worker", "email-worker", "scheduler-worker"):
            worker_jobs_total.labels(worker_name=w, job_type="default", status="success")
        firecrawl_scrapes_total.labels(status="success")
        firecrawl_scrapes_total.labels(status="http_error")
        firecrawl_scrapes_total.labels(status="rate_limited")
        firecrawl_scrapes_total.labels(status="error")
        firecrawl_cache_hits_total.inc(0)
    except Exception:
        pass


init_metrics()


async def update_queue_depth(
    redis_client: Optional[Any] = None,
    queue_name: Optional[str] = None,
) -> int:
    """Query Redis for queue depth and update the Prometheus gauge.

    Handles both list (LLEN) and sorted set (ZCARD) representations used by Redis/Arq.
    """
    settings = get_settings()
    q_name = queue_name or settings.ARQ_QUEUE_NAME

    pool = redis_client
    if pool is None:
        try:
            from app.queue.client import get_queue

            q = await get_queue()
            pool = q.pool
        except Exception:
            return 0

    try:
        depth = 0
        ktype = ""
        if hasattr(pool, "type"):
            try:
                res = pool.type(q_name)
                raw_type = await res if asyncio.iscoroutine(res) else res
                ktype = raw_type.decode("utf-8") if isinstance(raw_type, bytes) else str(raw_type)
            except Exception:
                ktype = ""

        if ktype == "zset":
            if hasattr(pool, "zcard"):
                res = pool.zcard(q_name)
                depth = await res if asyncio.iscoroutine(res) else res
        elif hasattr(pool, "llen"):
            try:
                res = pool.llen(q_name)
                depth = await res if asyncio.iscoroutine(res) else res
            except Exception:
                if hasattr(pool, "zcard"):
                    res = pool.zcard(q_name)
                    depth = await res if asyncio.iscoroutine(res) else res
        elif hasattr(pool, "zcard"):
            res = pool.zcard(q_name)
            depth = await res if asyncio.iscoroutine(res) else res

        val = int(depth or 0)
        queue_depth.labels(queue_name=q_name).set(val)
        return val
    except Exception as exc:
        logger.warning("Could not update queue depth metric: %s", exc)
        return 0


def generate_prometheus_metrics() -> str:
    """Generate Prometheus exposition text format string."""
    return generate_latest().decode("utf-8")
