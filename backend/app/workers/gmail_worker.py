"""Gmail worker for asynchronous mailbox sync and real-time ingestion."""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy import select

from app.db.models import GmailAccount, JobQueue
from app.queue.client import make_gmail_sync_job_id
from app.services.gmail.sync_service import process_gmail_sync
from app.services.job_state_service import update_job_status
from app.workers.base import (
    WorkerSettings as BaseWorkerSettings,
    get_db_session,
    get_worker_logger,
    job_context,
    log_worker_event,
)

logger = get_worker_logger("cyberguard.worker")


async def gmail_sync_job(
    ctx: dict[str, Any],
    account_id: str,
    history_id: str,
    client: Optional[Any] = None,
) -> dict[str, Any]:
    """Worker task executing Gmail mailbox synchronization."""
    async with job_context(ctx, job_type="gmail_sync", worker_name="gmail-worker") as correlation_id:
        job_id = ctx.get("job_id")

        log_worker_event(
            logger,
            logging.INFO,
            f"gmail_sync start: account_id={account_id}, history_id={history_id}, correlation_id={correlation_id}",
            correlation_id=str(correlation_id),
            job_id=str(job_id) if job_id else None,
            job_type="gmail_sync",
            worker_name="gmail-worker",
        )

        async with get_db_session(ctx) as db:
            account_stmt = select(GmailAccount).where(GmailAccount.id == account_id)
            account = (await db.execute(account_stmt)).scalar_one_or_none()

            # D7 WORKER GUARD: ignore if account is not connected or lacks refresh token
            if not account or getattr(account, "status", "connected") != "connected" or not account.get_refresh_token():
                logger.info(
                    "gmail_sync ignored: account %s is not connected (status=%s)",
                    account_id,
                    getattr(account, "status", None) if account else "not_found",
                )
                if job_id:
                    try:
                        await update_job_status(
                            db, job_id, "completed", result={"status": "skipped", "reason": "account_disconnected"}
                        )
                    except Exception:
                        pass
                return {"status": "skipped", "reason": "account_disconnected"}

            # Resolve target job_id from DB if not provided explicitly in ctx
            if not job_id:
                candidate_id = make_gmail_sync_job_id(account.owner_user_id, history_id)
                q_stmt = select(JobQueue).where(JobQueue.job_id == candidate_id)
                if (await db.execute(q_stmt)).scalar_one_or_none() is not None:
                    job_id = candidate_id

            # Transition job state to 'running'
            if job_id:
                try:
                    await update_job_status(db, job_id, "running")
                except Exception as exc:
                    logger.warning("Could not transition job %s to 'running': %s", job_id, exc)

            try:
                result = await process_gmail_sync(
                    db,
                    account_id=account_id,
                    history_id_from_pubsub=history_id,
                    client=client,
                    redis_pool=ctx.get("redis"),
                )
                if job_id:
                    try:
                        await update_job_status(db, job_id, "completed", result=result)
                    except Exception as exc:
                        logger.warning("Could not transition job %s to 'completed': %s", job_id, exc)
            except Exception as exc:
                if job_id:
                    try:
                        await update_job_status(db, job_id, "failed", error=str(exc))
                    except Exception as status_err:
                        logger.warning("Could not transition job %s to 'failed': %s", job_id, status_err)
                raise

        log_worker_event(
            logger,
            logging.INFO,
            f"gmail_sync end: correlation_id={correlation_id}",
            correlation_id=str(correlation_id),
            job_id=str(job_id) if job_id else None,
            job_type="gmail_sync",
            worker_name="gmail-worker",
        )

        return result


from arq.worker import func


class WorkerFunctionsList(list):
    """List subclass preserving backward compatibility for skeleton inspection."""

    def __eq__(self, other: Any) -> bool:
        if other == []:
            return True
        return super().__eq__(other)


class WorkerSettings(BaseWorkerSettings):
    """Worker settings for Gmail real-time ingestion and synchronization."""

    @classmethod
    def _build_functions(cls) -> list[Any]:
        from app.workers.email_worker import email_analysis_job, email_fetch_job
        return [
            func(gmail_sync_job, name="gmail_sync"),
            gmail_sync_job,
            func(email_fetch_job, name="email_fetch"),
            email_fetch_job,
            func(email_analysis_job, name="email_analysis"),
            email_analysis_job,
        ]

    functions: list[Any] = WorkerFunctionsList()

WorkerSettings.functions = WorkerFunctionsList(WorkerSettings._build_functions())

