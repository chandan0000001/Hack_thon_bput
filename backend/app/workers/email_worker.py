"""Email worker for asynchronous email fetch, analysis, heuristics, ML scoring, and enforcement."""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy import select

from app.core.errors import NonRetryableError
from app.core.metrics import dead_letter_jobs_total
from app.db.models import GmailAccount, JobQueue, ProcessedEmail
from app.queue.client import make_email_analysis_job_id, make_email_fetch_job_id
from app.services.gmail.analysis_service import process_email_analysis
from app.services.gmail.fetch_service import process_email_fetch
from app.services.job_state_service import update_job_status
from app.workers.base import (
    WorkerSettings as BaseWorkerSettings,
    get_db_session,
    get_worker_logger,
    job_context,
    log_worker_event,
)

logger = get_worker_logger("cyberguard.worker")


async def email_fetch_job(
    ctx: dict[str, Any],
    account_id: str,
    message_id: str,
    client: Optional[Any] = None,
) -> dict[str, Any]:
    """Worker task executing email retrieval, MIME normalization, and analysis enqueue."""
    async with job_context(ctx, job_type="email_fetch", worker_name="email-worker") as correlation_id:
        job_id = ctx.get("job_id")

        log_worker_event(
            logger,
            logging.INFO,
            f"email_fetch start: account_id={account_id}, message_id={message_id}, correlation_id={correlation_id}",
            correlation_id=str(correlation_id),
            job_id=str(job_id) if job_id else None,
            job_type="email_fetch",
            worker_name="email-worker",
        )

        async with get_db_session(ctx) as db:
            # Resolve target job_id from DB if not provided explicitly in ctx
            if not job_id:
                account_stmt = select(GmailAccount).where(GmailAccount.id == account_id)
                account = (await db.execute(account_stmt)).scalar_one_or_none()
                if account is not None:
                    candidate_id = make_email_fetch_job_id(account.owner_user_id, message_id)
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
                result = await process_email_fetch(
                    db,
                    account_id=account_id,
                    message_id=message_id,
                    client=client,
                    redis_pool=ctx.get("redis"),
                )
                if job_id:
                    try:
                        await update_job_status(db, job_id, "completed", result=result)
                    except Exception as exc:
                        logger.warning("Could not transition job %s to 'completed': %s", job_id, exc)
            except NonRetryableError as exc:
                # Poison pill protection: send straight to dead_letter without retry loop
                if job_id:
                    try:
                        await update_job_status(db, job_id, "dead_letter", error=str(exc))
                    except Exception as dl_err:
                        logger.warning("Could not transition job %s to 'dead_letter': %s", job_id, dl_err)
                else:
                    dead_letter_jobs_total.labels(job_type="email_fetch").inc()
                raise
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
            f"email_fetch end: correlation_id={correlation_id}",
            correlation_id=str(correlation_id),
            job_id=str(job_id) if job_id else None,
            job_type="email_fetch",
            worker_name="email-worker",
        )

        return result


async def email_analysis_job(ctx: dict[str, Any], processed_email_id: str) -> dict[str, Any]:
    """Worker task executing threat analysis, ML scoring, and result persistence."""
    async with job_context(ctx, job_type="email_analysis", worker_name="email-worker") as correlation_id:
        job_id = ctx.get("job_id")

        log_worker_event(
            logger,
            logging.INFO,
            f"email_analysis start: processed_email_id={processed_email_id}, correlation_id={correlation_id}",
            correlation_id=str(correlation_id),
            job_id=str(job_id) if job_id else None,
            job_type="email_analysis",
            worker_name="email-worker",
        )

        async with get_db_session(ctx) as db:
            if not job_id:
                pe_stmt = select(ProcessedEmail).where(ProcessedEmail.id == processed_email_id)
                pe = (await db.execute(pe_stmt)).scalar_one_or_none()
                if pe is not None:
                    candidate_id = make_email_analysis_job_id(pe.owner_user_id, pe.gmail_message_id)
                    q_stmt = select(JobQueue).where(JobQueue.job_id == candidate_id)
                    if (await db.execute(q_stmt)).scalar_one_or_none() is not None:
                        job_id = candidate_id

            if job_id:
                try:
                    await update_job_status(db, job_id, "running")
                except Exception as exc:
                    logger.warning("Could not transition job %s to 'running': %s", job_id, exc)

            try:
                result = await process_email_analysis(
                    db,
                    processed_email_id=processed_email_id,
                    supabase_client=ctx.get("supabase_client"),
                )

                # Automated SOAR Enforcement for high-risk threats / phishing
                pe_stmt = select(ProcessedEmail).where(ProcessedEmail.id == processed_email_id)
                pe_row = (await db.execute(pe_stmt)).scalar_one_or_none()

                if pe_row:
                    from app.db.session import current_user_id
                    current_user_id.set(pe_row.owner_user_id)

                    if result.get("classification") == "phishing" or (result.get("risk_score") or 0.0) >= 0.7:
                        try:
                            from app.db.models import EmailConnectorAccount, ScanResult as DBScanResult
                            from app.schemas.email import NormalizedMessage
                            from app.schemas.scan_results import ScanResult as PydanticScanResult, FeatureAnalysis
                            from app.services.action_engine import enforce_scan_result

                            if pe_row.gmail_message_id:
                                conn_stmt = select(EmailConnectorAccount).where(
                                    EmailConnectorAccount.owner_user_id == pe_row.owner_user_id,
                                    EmailConnectorAccount.status == "connected",
                                )
                                connector = (await db.execute(conn_stmt)).scalars().first()
                                if connector:
                                    explanation_text = f"High-risk threat detected (risk score: {pe_row.risk_score})"
                                    if pe_row.scan_result_id:
                                        sr_stmt = select(DBScanResult).where(DBScanResult.id == pe_row.scan_result_id)
                                        sr_row = (await db.execute(sr_stmt)).scalar_one_or_none()
                                        if sr_row and sr_row.scan_details:
                                            explanation_text = sr_row.scan_details.get("explanation", explanation_text)

                                    # ScanResult contract: overall_score / FeatureAnalysis.score
                                    # are 0.0-1.0 (schemas/scan_results.py) — UI renders x100.
                                    enforcement_score = round(min(1.0, pe_row.risk_score or 0.0), 3)
                                    scan_pydantic = PydanticScanResult(
                                        message_id=pe_row.gmail_message_id,
                                        subject=pe_row.subject,
                                        sender=pe_row.sender,
                                        overall_severity="critical" if (pe_row.risk_score or 0) >= 0.7 else "high",
                                        overall_score=enforcement_score,
                                        overall_explanation=explanation_text,
                                        feature_analyses=[
                                            FeatureAnalysis(
                                                engine="heuristics",
                                                severity="critical" if (pe_row.risk_score or 0) >= 0.7 else "high",
                                                score=enforcement_score,
                                                explanation=explanation_text,
                                            ),
                                            FeatureAnalysis(
                                                engine="ml_model",
                                                severity="critical" if (pe_row.risk_score or 0) >= 0.7 else "high",
                                                score=enforcement_score,
                                                explanation="ML classifier high threat probability",
                                            ),
                                        ],
                                        recommended_action="quarantine",
                                        provider_operation_status="pending",
                                    )
                                    norm_msg = NormalizedMessage(
                                        provider_message_id=pe_row.gmail_message_id,
                                        thread_id=pe_row.gmail_message_id,
                                        sender=pe_row.sender or "",
                                        recipients=[connector.provider_email],
                                        subject=pe_row.subject or "",
                                        snippet="",
                                        raw_size_bytes=100,
                                        has_attachments=False,
                                        internal_date=pe_row.created_at,
                                    )
                                    enforced = await enforce_scan_result(db, connector, norm_msg, scan_pydantic)
                                    # Record the real outcome on the processed email signals for UI visibility
                                    updated_signals = dict(pe_row.signals or {})
                                    updated_signals["enforcement_status"] = enforced.provider_operation_status
                                    updated_signals["enforcement_detail"] = enforced.provider_operation_detail
                                    pe_row.signals = updated_signals
                                    await db.commit()
                                    logger.info(
                                        "Auto-enforcement completed for message %s: status=%s (%s)",
                                        pe_row.gmail_message_id,
                                        enforced.provider_operation_status,
                                        enforced.provider_operation_detail,
                                    )
                        except Exception as enf_exc:
                            logger.warning("Auto-enforcement hook encountered error (non-fatal): %s", enf_exc)
                            try:
                                updated_signals = dict(pe_row.signals or {})
                                updated_signals["enforcement_status"] = "enforcement_error"
                                updated_signals["enforcement_detail"] = str(enf_exc)
                                pe_row.signals = updated_signals
                                await db.commit()
                            except Exception:
                                pass
                    else:
                        updated_signals = dict(pe_row.signals or {})
                        updated_signals["enforcement_status"] = "clean"
                        updated_signals["enforcement_detail"] = "Verdict safe: email kept in inbox."
                        pe_row.signals = updated_signals
                        await db.commit()

                # ORG-WIRE D3: fan critical/phishing verdicts out to the
                # owner's NON-personal org (personal orgs are suppressed —
                # Phase-7 already notifies the owner). Non-fatal.
                try:
                    from app.services.org_notification_service import fan_out_email_verdict

                    await fan_out_email_verdict(
                        db,
                        owner_user_id=pe_row.owner_user_id,
                        email_id=str(pe_row.id),
                        verdict=pe_row.verdict,
                        severity=pe_row.severity,
                        classification=result.get("classification"),
                    )
                except Exception as fan_exc:  # noqa: BLE001 - never break the pipeline
                    logger.warning("org fan-out hook error (non-fatal): %s", fan_exc)

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
            f"email_analysis end: correlation_id={correlation_id}, risk_score={result.get('risk_score')}",
            correlation_id=str(correlation_id),
            job_id=str(job_id) if job_id else None,
            job_type="email_analysis",
            worker_name="email-worker",
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
    """Worker settings for general email analysis and autonomous SOAR enforcement."""

    @classmethod
    def _build_functions(cls) -> list[Any]:
        from app.workers.gmail_worker import gmail_sync_job
        return [
            func(email_fetch_job, name="email_fetch"),
            email_fetch_job,
            func(email_analysis_job, name="email_analysis"),
            email_analysis_job,
            func(gmail_sync_job, name="gmail_sync"),
            gmail_sync_job,
        ]

    functions: list[Any] = WorkerFunctionsList()

WorkerSettings.functions = WorkerFunctionsList(WorkerSettings._build_functions())
