"""Gmail mailbox synchronization service for real-time message discovery."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.metrics import (
    gmail_api_errors_total,
    gmail_sync_jobs_total,
    job_processing_duration_seconds,
)
from app.db.models import GmailAccount
from app.queue.client import enqueue, make_email_fetch_job_id
from app.services.gmail.client import (
    GmailAuthError,
    GmailClient,
    GmailRateLimitError,
    GmailServerError,
)
from app.services.gmail_account_service import is_greater_history_id
from app.services.idempotency_service import ensure_job

logger = logging.getLogger("cyberguard.gmail.sync")


def max_history_id(id1: Optional[str], id2: Optional[str]) -> Optional[str]:
    """Return the greater of two history IDs."""
    if id1 is None:
        return id2
    if id2 is None:
        return id1
    try:
        return str(max(int(id1), int(id2)))
    except (ValueError, TypeError):
        return max(str(id1), str(id2))


def extract_unique_message_ids(history_data: Any) -> list[str]:
    """Extract and deduplicate message IDs from Gmail history response."""
    records: list[dict[str, Any]] = []
    if isinstance(history_data, dict):
        records = history_data.get("history", [])
    elif isinstance(history_data, list):
        records = history_data

    seen: set[str] = set()
    message_ids: list[str] = []

    def _add(m_id: Any) -> None:
        if m_id and isinstance(m_id, str) and m_id not in seen:
            seen.add(m_id)
            message_ids.append(m_id)

    for item in records:
        if not isinstance(item, dict):
            continue

        # 1. messagesAdded list
        if "messagesAdded" in item and isinstance(item["messagesAdded"], list):
            for entry in item["messagesAdded"]:
                if isinstance(entry, dict):
                    msg = entry.get("message")
                    if isinstance(msg, dict) and "id" in msg:
                        _add(msg["id"])
                    elif "id" in entry:
                        _add(entry["id"])

        # 2. labelsAdded list (e.g. INBOX label added)
        if "labelsAdded" in item and isinstance(item["labelsAdded"], list):
            for entry in item["labelsAdded"]:
                if isinstance(entry, dict):
                    msg = entry.get("message")
                    if isinstance(msg, dict) and "id" in msg:
                        _add(msg["id"])
                    elif "id" in entry:
                        _add(entry["id"])

        # 3. messages list
        if "messages" in item and isinstance(item["messages"], list):
            for entry in item["messages"]:
                if isinstance(entry, dict) and "id" in entry:
                    _add(entry["id"])
                elif isinstance(entry, str):
                    _add(entry)

        # 4. Direct id if item has neither messagesAdded nor messages nor labelsAdded
        if "messagesAdded" not in item and "messages" not in item and "labelsAdded" not in item and "id" in item:
            _add(item["id"])

    return message_ids


async def process_gmail_sync(
    db: AsyncSession,
    account_id: str,
    history_id_from_pubsub: str,
    client: Optional[GmailClient] = None,
    redis_pool: Optional[Any] = None,
) -> dict[str, Any]:
    """Process real-time Gmail mailbox synchronization.

    1. Load gmail_account with SELECT ... FOR UPDATE (row lock).
    2. If sync_status == 'paused' or 'error', skip processing.
    3. Decrypt access_token and refresh_token via crypto helpers.
    4. If last_history_id is None (initial sync): call get_profile, discover recent inbox messages, enqueue them.
    5. Call list_history(access_token, start_history_id=account.last_history_id). Handle 404 recovery.
    6. Extract unique message IDs from history response (messagesAdded, labelsAdded).
    7. For each message_id, enqueue email_fetch job with deterministic ID and payload.
    8. Update account.last_history_id to max(historyId from response, history_id_from_pubsub).
    9. Update account.last_sync_at = now(), sync_status='active', last_error=None.
    10. Catch GmailAuthError -> sync_status='error', last_error='reauth_required', re-raise.
    11. Catch GmailRateLimitError -> re-raise for Arq backoff retry.
    12. Catch GmailServerError -> re-raise for Arq backoff retry.
    """
    start_time = time.perf_counter()

    # 1. Load account with FOR UPDATE lock
    stmt = select(GmailAccount).where(GmailAccount.id == account_id).with_for_update()
    account = (await db.execute(stmt)).scalar_one_or_none()
    if account is None:
        logger.warning("Gmail account %s not found for sync", account_id)
        return {"status": "not_found", "messages_enqueued": 0}

    # 2. Skip disconnected, paused, or error accounts
    if getattr(account, "status", "connected") != "connected" or not account.get_refresh_token():
        logger.info("Account %s status is '%s'; skipping sync", account_id, getattr(account, "status", None))
        return {"status": "skipped", "reason": "account_disconnected", "messages_enqueued": 0}

    if account.sync_status in ("paused", "error"):
        logger.info("Account %s sync_status is '%s'; skipping sync", account_id, account.sync_status)
        return {"status": "skipped", "reason": account.sync_status, "messages_enqueued": 0}

    # 3. Decrypt tokens
    access_token = account.get_access_token()
    refresh_token = account.get_refresh_token()

    gmail = client or GmailClient()

    # 4. Initial sync: if last_history_id is None
    if account.last_history_id is None:
        try:
            profile = await gmail.get_profile(access_token=access_token or "", refresh_token=refresh_token)
        except GmailAuthError:
            account.sync_status = "error"
            account.last_error = "reauth_required"
            account.updated_at = datetime.now(timezone.utc)
            await db.commit()
            duration = time.perf_counter() - start_time
            job_processing_duration_seconds.labels(job_type="gmail_sync").observe(duration)
            gmail_sync_jobs_total.labels(status="failed").inc()
            gmail_api_errors_total.labels(error_type="auth").inc()
            raise
        except GmailRateLimitError:
            duration = time.perf_counter() - start_time
            job_processing_duration_seconds.labels(job_type="gmail_sync").observe(duration)
            gmail_sync_jobs_total.labels(status="failed").inc()
            gmail_api_errors_total.labels(error_type="rate_limit").inc()
            raise
        except GmailServerError:
            duration = time.perf_counter() - start_time
            job_processing_duration_seconds.labels(job_type="gmail_sync").observe(duration)
            gmail_sync_jobs_total.labels(status="failed").inc()
            gmail_api_errors_total.labels(error_type="server").inc()
            raise
        except Exception:
            duration = time.perf_counter() - start_time
            job_processing_duration_seconds.labels(job_type="gmail_sync").observe(duration)
            gmail_sync_jobs_total.labels(status="failed").inc()
            raise

        initial_history_id = str(profile.get("historyId") or history_id_from_pubsub or "")
        now = datetime.now(timezone.utc)
        account.last_history_id = initial_history_id
        account.sync_status = "active"
        account.last_error = None
        account.last_sync_at = now
        account.updated_at = now
        await db.commit()
        await db.refresh(account)

        # Discover recent inbox messages so the email that triggered this notification is not dropped
        initial_enqueued = 0
        try:
            recent_msgs = await gmail.list_messages(
                access_token=access_token or "",
                q="in:inbox",
                max_results=5,
                refresh_token=refresh_token,
            )
            for m in recent_msgs:
                mid = m.get("id") if isinstance(m, dict) else None
                if not mid:
                    continue
                fetch_job_id = make_email_fetch_job_id(account.owner_user_id, mid)
                fetch_payload = {"account_id": str(account.id), "message_id": mid}
                await ensure_job(
                    db,
                    owner_user_id=account.owner_user_id,
                    job_type="email_fetch",
                    job_id=fetch_job_id,
                    payload=fetch_payload,
                )
                try:
                    await enqueue("email_fetch", kwargs=fetch_payload, job_id=fetch_job_id)
                except Exception as exc:
                    logger.warning("Failed to enqueue initial email_fetch job %s: %s", fetch_job_id, exc)
                initial_enqueued += 1
        except Exception as msg_exc:
            logger.warning("Could not list recent inbox messages during initial sync: %s", msg_exc)

        logger.info("Initial sync completed for account %s: historyId=%s, messages_enqueued=%d", account_id, initial_history_id, initial_enqueued)
        duration = time.perf_counter() - start_time
        try:
            job_processing_duration_seconds.labels(job_type="gmail_sync").observe(duration)
            gmail_sync_jobs_total.labels(status="success").inc()
        except Exception:
            pass
        return {"status": "initial_sync", "history_id": initial_history_id, "messages_enqueued": initial_enqueued}

    # 5. Call list_history with 404 expiry fallback
    from app.services.gmail.client import GmailClientError
    try:
        history_response = await gmail.list_history(
            access_token=access_token or "",
            start_history_id=account.last_history_id,
            refresh_token=refresh_token,
        )
    except GmailAuthError:
        account.sync_status = "error"
        account.last_error = "reauth_required"
        account.updated_at = datetime.now(timezone.utc)
        await db.commit()
        duration = time.perf_counter() - start_time
        job_processing_duration_seconds.labels(job_type="gmail_sync").observe(duration)
        gmail_sync_jobs_total.labels(status="failed").inc()
        gmail_api_errors_total.labels(error_type="auth").inc()
        raise
    except GmailRateLimitError:
        duration = time.perf_counter() - start_time
        job_processing_duration_seconds.labels(job_type="gmail_sync").observe(duration)
        gmail_sync_jobs_total.labels(status="failed").inc()
        gmail_api_errors_total.labels(error_type="rate_limit").inc()
        raise
    except GmailServerError:
        duration = time.perf_counter() - start_time
        job_processing_duration_seconds.labels(job_type="gmail_sync").observe(duration)
        gmail_sync_jobs_total.labels(status="failed").inc()
        gmail_api_errors_total.labels(error_type="server").inc()
        raise
    except GmailClientError as exc:
        if getattr(exc, "status_code", None) == 404:
            logger.info("History ID %s expired (404); recovering via profile and recent messages", account.last_history_id)
            profile = await gmail.get_profile(access_token=access_token or "", refresh_token=refresh_token)
            account.last_history_id = str(profile.get("historyId") or history_id_from_pubsub or "")
            await db.commit()
            recent_msgs = await gmail.list_messages(access_token=access_token or "", q="in:inbox", max_results=5, refresh_token=refresh_token)
            history_response = [{"messagesAdded": [{"message": {"id": m["id"]}}]} for m in recent_msgs if isinstance(m, dict) and "id" in m]
        else:
            raise
    except Exception:
        duration = time.perf_counter() - start_time
        job_processing_duration_seconds.labels(job_type="gmail_sync").observe(duration)
        gmail_sync_jobs_total.labels(status="failed").inc()
        raise

    # 6. Extract unique message IDs
    message_ids = extract_unique_message_ids(history_response)

    # 7. For each message_id, enqueue email_fetch job
    enqueued_count = 0
    for mid in message_ids:
        fetch_job_id = make_email_fetch_job_id(account.owner_user_id, mid)
        fetch_payload = {
            "account_id": str(account.id),
            "message_id": mid,
        }
        await ensure_job(
            db,
            owner_user_id=account.owner_user_id,
            job_type="email_fetch",
            job_id=fetch_job_id,
            payload=fetch_payload,
        )
        try:
            await enqueue(
                "email_fetch",
                kwargs=fetch_payload,
                job_id=fetch_job_id,
            )
        except Exception as exc:
            logger.warning("Failed to enqueue email_fetch job to Redis (job %s): %s", fetch_job_id, exc)
        enqueued_count += 1

    # 8. Update account.last_history_id to max(historyId from response, history_id_from_pubsub)
    resp_history_id = getattr(history_response, "history_id", None)
    if not resp_history_id and isinstance(history_response, dict):
        resp_history_id = history_response.get("historyId")
    if not resp_history_id and isinstance(history_response, list):
        record_ids = [item.get("id") or item.get("historyId") for item in history_response if isinstance(item, dict)]
        if record_ids:
            resp_history_id = max(record_ids, key=lambda x: int(x) if str(x).isdigit() else str(x))

    candidate_history_id = max_history_id(resp_history_id, history_id_from_pubsub)
    if is_greater_history_id(candidate_history_id, account.last_history_id):
        account.last_history_id = str(candidate_history_id)

    # 9. Update last_sync_at, sync_status, last_error
    now = datetime.now(timezone.utc)
    account.last_sync_at = now
    account.sync_status = "active"
    account.last_error = None
    account.updated_at = now
    await db.commit()
    await db.refresh(account)

    logger.info(
        "Gmail sync completed for account %s: %d messages discovered, last_history_id=%s",
        account_id,
        enqueued_count,
        account.last_history_id,
    )
    duration = time.perf_counter() - start_time
    try:
        job_processing_duration_seconds.labels(job_type="gmail_sync").observe(duration)
        gmail_sync_jobs_total.labels(status="success").inc()
    except Exception:
        pass

    return {
        "status": "synced",
        "messages_enqueued": enqueued_count,
        "last_history_id": account.last_history_id,
    }
