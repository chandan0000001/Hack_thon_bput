"""Scheduler worker for periodic watch renewal and stuck account reconciliation."""

from __future__ import annotations

import logging
from typing import Any

from arq.cron import cron

from app.services.gmail.purge_service import purge_stale_gmail_accounts
from app.services.gmail.reconciliation_service import reconcile_stuck_accounts
from app.services.gmail.watch_service import renew_watches
from app.workers.base import (
    WorkerSettings as BaseWorkerSettings,
    get_worker_logger,
)

logger = get_worker_logger("cyberguard.scheduler")

cron_jobs = [
    cron(renew_watches, hour={0, 6, 12, 18}, minute=0),  # 4x daily (Gmail watches expire in 7 days)
    cron(reconcile_stuck_accounts, minute={15, 45}),      # 2x hourly (catch dropped Pub/Sub)
    cron(purge_stale_gmail_accounts, hour=3, minute=0),   # 1x daily (purge stale accounts older than 3 days)
]


class WorkerSettings(BaseWorkerSettings):
    """Worker settings for CYBERGUARD scheduled cron operations."""

    queue_name: str = "cyberguard_scheduler"
    cron_jobs = cron_jobs
    functions: list[Any] = [renew_watches, reconcile_stuck_accounts, purge_stale_gmail_accounts]

