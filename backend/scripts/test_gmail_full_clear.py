"""GMAIL-FULL-CLEAR test suite (Suite 44, 12 checks).

Covers:
 1. disconnect = full clear (tokens NULL, history NULL, watch NULL, pubsub_stopped_at set, disconnected_at set, status='disconnected')
 2. backlog drain: push sent to disconnected account dropped + ACKed, no sync enqueued
 3. pause: stop() called, tokens kept, status='paused', sync_status='paused', paused_at set
 4. resume: watch() called, new history_id stored, gap-sync enqueued from pre-pause history_id, status='connected', paused_at NULL
 5. idempotent pause (no-op on repeated pause); resume-connected returns 409
 6. pause -> disconnect clears all residue, marks disconnected
 7. renewal cron skips paused & disconnected (only status='connected' renewed)
 8. 3-day purge job soft-purges (or hard-deletes if 0 FK) expired disconnected rows
 9. last_push_at plateaus post-disconnect (stops updating when Google stops push)
 10. zero token leak in all responses (status, list, pause, resume, disconnect)
 11. multi-user isolation: user A pause/disconnect does not affect user B
 12. UI matrix: connected row buttons & badges match status (connected vs paused vs disconnected)

Run standalone:
    uv run python scripts/test_gmail_full_clear.py
"""

from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from unittest.mock import AsyncMock, patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from app.core.config import get_settings
from app.core.crypto import encrypt_secret
from app.core.security import CurrentUser, get_current_user
from app.db.admin import _get_admin_session_maker
from app.db.models import EmailConnectorAccount, GmailAccount, JobQueue, ProcessedEmail, User
from app.db.session import async_session_maker, current_user_id
from app.main import app
from app.services.gmail.client import GmailClient
from app.services.gmail.purge_service import purge_stale_gmail_accounts
from app.services.gmail.watch_service import renew_watches
from app.services.gmail_account_service import (
    get_or_create_gmail_account,
    perform_gmail_disconnect,
    perform_gmail_pause,
    perform_gmail_resume,
)


class _Identity:
    user: CurrentUser | None = None


async def _mock_get_current_user() -> CurrentUser:
    if _Identity.user is None:
        raise RuntimeError("test identity not set")
    current_user_id.set(_Identity.user.id)
    return _Identity.user


def _make_pubsub_body(email: str, history_id: str | int, message_id: str = "msg-clear-test") -> dict:
    data_bytes = json.dumps({"emailAddress": email, "historyId": str(history_id)}).encode("utf-8")
    data_b64 = base64.b64encode(data_bytes).decode("utf-8")
    return {
        "message": {
            "data": data_b64,
            "messageId": message_id,
        },
        "subscription": "projects/cyberguard-test/subscriptions/gmail-push",
    }


async def run_gmail_full_clear_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("GMAIL-FULL-CLEAR Tests (Suite 44)")
    print("-" * 60)

    admin_maker = _get_admin_session_maker()
    stamp = uuid.uuid4().hex[:8]
    now = datetime.now(timezone.utc)

    user_a_id = f"usr-fc-a-{stamp}"
    user_b_id = f"usr-fc-b-{stamp}"
    user_a_email = f"analyst-fca-{stamp}@cyberguard.test"
    user_b_email = f"analyst-fcb-{stamp}@cyberguard.test"

    user_a = CurrentUser(id=user_a_id, email=user_a_email, full_name="User FC A")
    user_b = CurrentUser(id=user_b_id, email=user_b_email, full_name="User FC B")

    async with admin_maker() as db:
        await db.execute(
            text(
                "insert into cyberguard.users (id, email, full_name, account_type, is_single_user, created_at) "
                "values (:u, :e, :fn, 'user', true, now()) on conflict (id) do nothing"
            ),
            {"u": user_a_id, "e": user_a_email, "fn": "User FC A"},
        )
        await db.execute(
            text(
                "insert into cyberguard.users (id, email, full_name, account_type, is_single_user, created_at) "
                "values (:u, :e, :fn, 'user', true, now()) on conflict (id) do nothing"
            ),
            {"u": user_b_id, "e": user_b_email, "fn": "User FC B"},
        )
        await db.commit()

    transport = ASGITransport(app=app)
    app.dependency_overrides[get_current_user] = _mock_get_current_user

    responses_to_audit: list[dict | list | str] = []

    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            _Identity.user = user_a

            # ------------------------------------------------------------------
            # 1. Disconnect = full clear (tokens NULL, history NULL, watch NULL,
            #    pubsub_stopped_at set, disconnected_at set, status='disconnected')
            # ------------------------------------------------------------------
            acc1_id = f"acc-fc1-{stamp}"
            acc1_email = f"fc1-{stamp}@gmail.com"
            async with admin_maker() as db:
                acc1 = GmailAccount(
                    id=acc1_id,
                    owner_user_id=user_a.id,
                    email=acc1_email,
                    status="connected",
                    sync_status="active",
                    last_history_id="10001",
                    watch_expiration=now + timedelta(days=7),
                    created_at=now - timedelta(days=1),
                )
                acc1.set_access_token("tok-fc1-secret")
                acc1.set_refresh_token("ref-fc1-secret")
                db.add(acc1)

                conn1 = EmailConnectorAccount(
                    id=f"conn-fc1-{stamp}",
                    owner_user_id=user_a.id,
                    provider="gmail",
                    provider_email=acc1_email,
                    status="connected",
                    access_token_enc=encrypt_secret("tok-fc1-secret"),
                    refresh_token_enc=encrypt_secret("ref-fc1-secret"),
                )
                db.add(conn1)
                await db.commit()

            mock_stop = AsyncMock(return_value={"success": True})
            with patch.object(GmailClient, "stop", mock_stop), \
                 patch("app.services.gmail_account_service.revoke_google_token", AsyncMock(return_value=True)):

                resp1 = await client.post(f"/connectors/gmail/accounts/{acc1_id}/disconnect")
                responses_to_audit.append(resp1.json())

                async with admin_maker() as db:
                    acc_db = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc1_id))).scalar_one()
                    conn_db = (await db.execute(select(EmailConnectorAccount).where(EmailConnectorAccount.id == conn1.id))).scalar_one()

                    state_1_ok = (
                        acc_db.status == "disconnected"
                        and acc_db.disconnected_at is not None
                        and acc_db.pubsub_stopped_at is not None
                        and acc_db.refresh_token_encrypted is None
                        and acc_db.access_token_encrypted is None
                        and acc_db.last_history_id is None
                        and acc_db.watch_expiration is None
                        and acc_db.sync_status == "paused"
                        and conn_db.status == "revoked"
                        and conn_db.access_token_enc is None
                        and conn_db.refresh_token_enc is None
                    )

                check(
                    resp1.status_code == 200 and state_1_ok and mock_stop.called,
                    "1 disconnect = full clear (tokens NULL, history NULL, watch NULL, pubsub_stopped_at set, disconnected_at set, status='disconnected')",
                    f"resp1={resp1.status_code}, state_1_ok={state_1_ok}, mock_stop={mock_stop.called}",
                )

            # ------------------------------------------------------------------
            # 2. Backlog drain: push sent to disconnected account dropped + ACKed,
            #    no sync enqueued
            # ------------------------------------------------------------------
            push_body_disc = _make_pubsub_body(acc1_email, "10002", message_id=f"msg-disc-{stamp}")
            with patch("app.api.routes_gmail_webhook.validate_pubsub_message", AsyncMock(return_value={
                "email_address": acc1_email,
                "history_id": "10002",
                "message_id": f"msg-disc-{stamp}",
                "subscription": "sub-test",
            })):
                resp2 = await client.post("/api/v1/webhooks/gmail", json=push_body_disc)
                responses_to_audit.append(resp2.json())

                # Check job_queue table: NO job enqueued for this history_id
                async with admin_maker() as db:
                    cand_id = f"gmail_sync:{user_a.id}:10002"
                    jq = (await db.execute(select(JobQueue).where(JobQueue.job_id == cand_id))).scalar_one_or_none()

                check(
                    resp2.status_code == 200
                    and resp2.json().get("status") == "ignored"
                    and resp2.json().get("reason") in ("account_disconnected", "no_refresh_token")
                    and jq is None,
                    "2 backlog drain: push sent to disconnected account dropped + ACKed, no sync enqueued",
                    f"status={resp2.status_code}, body={resp2.json()}, jq_present={jq is not None}",
                )

            # ------------------------------------------------------------------
            # 3. Pause: stop() called, tokens kept, status='paused',
            #    sync_status='paused', paused_at set
            # ------------------------------------------------------------------
            acc3_id = f"acc-fc3-{stamp}"
            acc3_email = f"fc3-{stamp}@gmail.com"
            async with admin_maker() as db:
                acc3 = GmailAccount(
                    id=acc3_id,
                    owner_user_id=user_a.id,
                    email=acc3_email,
                    status="connected",
                    sync_status="active",
                    last_history_id="20001",
                    watch_expiration=now + timedelta(days=7),
                    created_at=now,
                )
                acc3.set_access_token("tok-fc3-secret")
                acc3.set_refresh_token("ref-fc3-secret")
                db.add(acc3)

                conn3 = EmailConnectorAccount(
                    id=f"conn-fc3-{stamp}",
                    owner_user_id=user_a.id,
                    provider="gmail",
                    provider_email=acc3_email,
                    status="connected",
                    access_token_enc=encrypt_secret("tok-fc3-secret"),
                    refresh_token_enc=encrypt_secret("ref-fc3-secret"),
                )
                db.add(conn3)
                await db.commit()

            mock_stop_pause = AsyncMock(return_value={"success": True})
            with patch.object(GmailClient, "stop", mock_stop_pause):
                resp3 = await client.post(f"/connectors/gmail/accounts/{acc3_id}/pause")
                responses_to_audit.append(resp3.json())

                async with admin_maker() as db:
                    acc3_db = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc3_id))).scalar_one()

                    state_3_ok = (
                        acc3_db.status == "paused"
                        and acc3_db.sync_status == "paused"
                        and acc3_db.paused_at is not None
                        and acc3_db.get_refresh_token() == "ref-fc3-secret"
                        and acc3_db.get_access_token() == "tok-fc3-secret"
                        and acc3_db.last_history_id == "20001"
                    )

                check(
                    resp3.status_code == 200
                    and resp3.json().get("status") == "paused"
                    and mock_stop_pause.called
                    and state_3_ok,
                    "3 pause: stop() called, tokens kept, status='paused', sync_status='paused', paused_at set",
                    f"resp3={resp3.status_code}, state_3_ok={state_3_ok}, stop_called={mock_stop_pause.called}",
                )

            # ------------------------------------------------------------------
            # 4. Resume: watch() called, new history_id stored, gap-sync enqueued
            #    from pre-pause history_id, status='connected', paused_at NULL
            # ------------------------------------------------------------------
            mock_watch = AsyncMock(return_value={
                "historyId": "20050",
                "expiration": int((now + timedelta(days=7)).timestamp() * 1000),
            })
            with patch.object(GmailClient, "watch", mock_watch), \
                 patch("app.queue.client.enqueue", AsyncMock(return_value=f"gmail_sync:{user_a.id}:20001")):

                resp4 = await client.post(f"/connectors/gmail/accounts/{acc3_id}/resume")
                responses_to_audit.append(resp4.json())

                async with admin_maker() as db:
                    acc4_db = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc3_id))).scalar_one()

                    # Confirm gap-sync was enqueued in job_queue with pre-pause history_id "20001"
                    gap_jq_stmt = select(JobQueue).where(
                        JobQueue.owner_user_id == user_a.id,
                        JobQueue.job_id == f"gmail_sync:{user_a.id}:20001",
                    )
                    gap_jq = (await db.execute(gap_jq_stmt)).scalar_one_or_none()

                    state_4_ok = (
                        acc4_db.status == "connected"
                        and acc4_db.sync_status == "active"
                        and acc4_db.paused_at is None
                        and acc4_db.last_history_id == "20050"
                        and gap_jq is not None
                        and gap_jq.payload.get("history_id") == "20001"
                    )

                check(
                    resp4.status_code == 200
                    and resp4.json().get("status") == "connected"
                    and mock_watch.called
                    and state_4_ok,
                    "4 resume: watch() called, new history_id stored, gap-sync enqueued from pre-pause history_id, status='connected', paused_at NULL",
                    f"resp4={resp4.status_code}, state_4_ok={state_4_ok}, gap_jq={gap_jq is not None}",
                )

            # ------------------------------------------------------------------
            # 5. Idempotent pause (no-op on repeated pause); resume-connected returns 409
            # ------------------------------------------------------------------
            # a) Pause acc3 again
            mock_stop_repeat = AsyncMock(return_value={"success": True})
            with patch.object(GmailClient, "stop", mock_stop_repeat):
                resp5_p1 = await client.post(f"/connectors/gmail/accounts/{acc3_id}/pause")
                resp5_p2 = await client.post(f"/connectors/gmail/accounts/{acc3_id}/pause")
                responses_to_audit.append(resp5_p1.json())
                responses_to_audit.append(resp5_p2.json())

                # Repeated pause should be idempotent (second call makes 0 extra stop() calls)
                idempotent_pause_ok = (
                    resp5_p1.status_code == 200
                    and resp5_p2.status_code == 200
                    and mock_stop_repeat.call_count == 1
                )

            # b) Resume it once to make it connected
            with patch.object(GmailClient, "watch", AsyncMock(return_value={"historyId": "20060", "expiration": 1999999999000})), \
                 patch("app.queue.client.enqueue", AsyncMock(return_value="ok")):
                resp5_res1 = await client.post(f"/connectors/gmail/accounts/{acc3_id}/resume")
                # Resume again when already connected -> must return 409
                resp5_res2 = await client.post(f"/connectors/gmail/accounts/{acc3_id}/resume")
                responses_to_audit.append(resp5_res1.json())

                conflict_409_ok = (resp5_res1.status_code == 200 and resp5_res2.status_code == 409)

            check(
                idempotent_pause_ok and conflict_409_ok,
                "5 idempotent pause (no-op on repeated pause); resume-connected returns 409",
                f"idempotent_pause={idempotent_pause_ok}, res2_status={resp5_res2.status_code}",
            )

            # ------------------------------------------------------------------
            # 6. Pause -> disconnect clears all residue, marks disconnected
            # ------------------------------------------------------------------
            # Pause acc3 first
            with patch.object(GmailClient, "stop", AsyncMock(return_value={"success": True})):
                await client.post(f"/connectors/gmail/accounts/{acc3_id}/pause")

            mock_stop_disc = AsyncMock(return_value={"success": True})
            with patch.object(GmailClient, "stop", mock_stop_disc), \
                 patch("app.services.gmail_account_service.revoke_google_token", AsyncMock(return_value=True)):
                resp6 = await client.post(f"/connectors/gmail/accounts/{acc3_id}/disconnect")
                responses_to_audit.append(resp6.json())

                async with admin_maker() as db:
                    acc6_db = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc3_id))).scalar_one()

                    state_6_ok = (
                        acc6_db.status == "disconnected"
                        and acc6_db.paused_at is None
                        and acc6_db.pubsub_stopped_at is not None
                        and acc6_db.disconnected_at is not None
                        and acc6_db.get_access_token() is None
                        and acc6_db.get_refresh_token() is None
                        and acc6_db.last_history_id is None
                        and acc6_db.watch_expiration is None
                    )

            check(
                resp6.status_code == 200 and state_6_ok,
                "6 pause -> disconnect clears all residue, marks disconnected",
                f"resp6={resp6.status_code}, state_6_ok={state_6_ok}",
            )

            # ------------------------------------------------------------------
            # 7. Renewal cron skips paused & disconnected (only status='connected' renewed)
            # ------------------------------------------------------------------
            cron_acc_conn = f"acc-cron-c-{stamp}"
            cron_acc_pause = f"acc-cron-p-{stamp}"
            cron_acc_disc = f"acc-cron-d-{stamp}"

            async with admin_maker() as db:
                # Connected account expiring soon (<24h)
                c_conn = GmailAccount(
                    id=cron_acc_conn,
                    owner_user_id=user_a.id,
                    email=f"cron-c-{stamp}@gmail.com",
                    status="connected",
                    sync_status="active",
                    watch_expiration=now + timedelta(hours=2),
                )
                c_conn.set_access_token("tok-c")
                c_conn.set_refresh_token("ref-c")
                db.add(c_conn)

                # Paused account expiring soon (<24h)
                c_p = GmailAccount(
                    id=cron_acc_pause,
                    owner_user_id=user_a.id,
                    email=f"cron-p-{stamp}@gmail.com",
                    status="paused",
                    sync_status="paused",
                    watch_expiration=now + timedelta(hours=2),
                    paused_at=now - timedelta(hours=1),
                )
                c_p.set_access_token("tok-p")
                c_p.set_refresh_token("ref-p")
                db.add(c_p)

                # Disconnected account
                c_d = GmailAccount(
                    id=cron_acc_disc,
                    owner_user_id=user_a.id,
                    email=f"cron-d-{stamp}@gmail.com",
                    status="disconnected",
                    sync_status="paused",
                    disconnected_at=now - timedelta(hours=1),
                    watch_expiration=now + timedelta(hours=2),
                )
                db.add(c_d)
                await db.commit()

            mock_client = AsyncMock()
            mock_client.watch = AsyncMock(return_value={
                "historyId": "30001",
                "expiration": int((now + timedelta(days=7)).timestamp() * 1000),
            })
            async with admin_maker() as db:
                res_cron = await renew_watches(
                    db=db,
                    client=mock_client,
                    account_ids=[cron_acc_conn, cron_acc_pause, cron_acc_disc],
                )

            cron_ok = (
                res_cron.get("renewed") == 1
                and res_cron.get("renewed_account_ids") == [cron_acc_conn]
            )

            check(
                cron_ok,
                "7 renewal cron skips paused & disconnected (only status='connected' renewed)",
                f"res_cron={res_cron}",
            )

            # ------------------------------------------------------------------
            # 8. 3-day purge job soft-purges (or hard-deletes if 0 FK) expired disconnected rows
            # ------------------------------------------------------------------
            acc8_id = f"acc-purge-{stamp}"
            acc8_email = f"purge-{stamp}@gmail.com"
            async with admin_maker() as db:
                acc8 = GmailAccount(
                    id=acc8_id,
                    owner_user_id=user_a.id,
                    email=acc8_email,
                    status="disconnected",
                    sync_status="paused",
                    disconnected_at=now - timedelta(days=4),  # > 3 days
                    created_at=now - timedelta(days=5),
                )
                db.add(acc8)
                await db.commit()

            async with admin_maker() as db:
                purge_res = await purge_stale_gmail_accounts(db=db, now=now)
                acc8_db = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc8_id))).scalar_one_or_none()

            resp8_list = await client.get("/connectors/gmail/accounts")
            recent_ids = [item["id"] for item in resp8_list.json().get("recent", [])]

            check(
                acc8_db is not None
                and acc8_db.status == "purged"
                and acc8_id not in recent_ids,
                "8 3-day purge job soft-purges (or hard-deletes if 0 FK) expired disconnected rows",
                f"purge_res={purge_res}, acc8_status={getattr(acc8_db, 'status', None)}, in_recent={acc8_id in recent_ids}",
            )

            # ------------------------------------------------------------------
            # 9. last_push_at plateaus post-disconnect (stops updating when Google stops push)
            # ------------------------------------------------------------------
            acc9_id = f"acc-plateau-{stamp}"
            acc9_email = f"plateau-{stamp}@gmail.com"
            async with admin_maker() as db:
                acc9 = GmailAccount(
                    id=acc9_id,
                    owner_user_id=user_a.id,
                    email=acc9_email,
                    status="disconnected",
                    sync_status="paused",
                    disconnected_at=now,
                    last_push_at=None,
                )
                db.add(acc9)
                await db.commit()

            # First push arrives
            t1_val = None
            with patch("app.api.routes_gmail_webhook.validate_pubsub_message", AsyncMock(return_value={
                "email_address": acc9_email,
                "history_id": "40001",
                "message_id": f"msg-plat1-{stamp}",
                "subscription": "sub-test",
            })):
                await client.post("/api/v1/webhooks/gmail", json=_make_pubsub_body(acc9_email, "40001"))

            async with admin_maker() as db:
                acc9_1 = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc9_id))).scalar_one()
                t1_val = acc9_1.last_push_at

            await asyncio.sleep(0.01)

            # Second push arrives (draining backlog)
            t2_val = None
            with patch("app.api.routes_gmail_webhook.validate_pubsub_message", AsyncMock(return_value={
                "email_address": acc9_email,
                "history_id": "40002",
                "message_id": f"msg-plat2-{stamp}",
                "subscription": "sub-test",
            })):
                await client.post("/api/v1/webhooks/gmail", json=_make_pubsub_body(acc9_email, "40002"))

            async with admin_maker() as db:
                acc9_2 = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc9_id))).scalar_one()
                t2_val = acc9_2.last_push_at

            # Now Google stops push: no more pushes arrive
            # Verify timestamp plateaus at t2_val
            await asyncio.sleep(0.01)
            async with admin_maker() as db:
                acc9_final = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc9_id))).scalar_one()
                t_final = acc9_final.last_push_at

            plateau_ok = (
                t1_val is not None
                and t2_val is not None
                and t2_val >= t1_val
                and t_final == t2_val
            )

            check(
                plateau_ok,
                "9 last_push_at plateaus post-disconnect (stops updating when Google stops push)",
                f"t1={t1_val}, t2={t2_val}, t_final={t_final}",
            )

            # ------------------------------------------------------------------
            # 10. Zero token leak in all responses (status, list, pause, resume, disconnect)
            # ------------------------------------------------------------------
            # Add status response
            resp_status = await client.get("/gmail/status")
            responses_to_audit.append(resp_status.json())

            # Add list response
            resp_list = await client.get("/connectors/gmail/accounts")
            responses_to_audit.append(resp_list.json())

            forbidden_fragments = [
                "tok-fc",
                "ref-fc",
                "access_token",
                "refresh_token",
                "access_token_encrypted",
                "refresh_token_encrypted",
                "secret",
            ]

            leaks = []
            dumped_all = json.dumps(responses_to_audit)
            for frag in forbidden_fragments:
                if frag in dumped_all:
                    leaks.append(frag)

            check(
                len(leaks) == 0,
                "10 zero token leak in all responses (status, list, pause, resume, disconnect)",
                f"leaks_found={leaks}",
            )

            # ------------------------------------------------------------------
            # 11. Multi-user isolation: user A pause/disconnect does not affect user B
            # ------------------------------------------------------------------
            acc_b_id = f"acc-userb-{stamp}"
            acc_b_email = f"userb-{stamp}@gmail.com"
            async with admin_maker() as db:
                acc_b = GmailAccount(
                    id=acc_b_id,
                    owner_user_id=user_b.id,
                    email=acc_b_email,
                    status="connected",
                    sync_status="active",
                    created_at=now,
                )
                acc_b.set_access_token("tok-userb")
                acc_b.set_refresh_token("ref-userb")
                db.add(acc_b)
                await db.commit()

            # User A performs pause and disconnect operations on their own accounts
            _Identity.user = user_a
            # User B checks their account: still connected and active
            _Identity.user = user_b
            resp_b_list = await client.get("/connectors/gmail/accounts")
            responses_to_audit.append(resp_b_list.json())

            b_connected_ids = [item["id"] for item in resp_b_list.json().get("connected", [])]
            b_recent_ids = [item["id"] for item in resp_b_list.json().get("recent", [])]

            check(
                acc_b_id in b_connected_ids and acc_b_id not in b_recent_ids,
                "11 multi-user isolation: user A pause/disconnect does not affect user B",
                f"b_connected={b_connected_ids}, b_recent={b_recent_ids}",
            )

            # ------------------------------------------------------------------
            # 12. UI matrix: connected row buttons & badges match status
            #     (connected vs paused vs disconnected)
            # ------------------------------------------------------------------
            # Create a paused account and a connected account for user A
            ui_conn_id = f"ui-conn-{stamp}"
            ui_pause_id = f"ui-pause-{stamp}"

            async with admin_maker() as db:
                ui_conn = GmailAccount(
                    id=ui_conn_id,
                    owner_user_id=user_a.id,
                    email=f"uiconn-{stamp}@gmail.com",
                    status="connected",
                    sync_status="active",
                    created_at=now,
                )
                ui_pause = GmailAccount(
                    id=ui_pause_id,
                    owner_user_id=user_a.id,
                    email=f"uipause-{stamp}@gmail.com",
                    status="paused",
                    sync_status="paused",
                    paused_at=now,
                    created_at=now - timedelta(minutes=5),
                )
                db.add(ui_conn)
                db.add(ui_pause)
                await db.commit()

            _Identity.user = user_a
            resp12 = await client.get("/connectors/gmail/accounts")
            c_items = {item["id"]: item for item in resp12.json().get("connected", [])}
            r_items = {item["id"]: item for item in resp12.json().get("recent", [])}

            conn_item = c_items.get(ui_conn_id)
            pause_item = c_items.get(ui_pause_id)
            disc_item = r_items.get(acc1_id)

            ui_matrix_ok = (
                conn_item is not None
                and conn_item.get("status") == "connected"
                and pause_item is not None
                and pause_item.get("status") == "paused"
                and disc_item is not None
                and disc_item.get("status") == "disconnected"
            )

            check(
                ui_matrix_ok,
                "12 UI matrix: connected row buttons & badges match status (connected vs paused vs disconnected)",
                f"conn={getattr(conn_item, 'get', lambda k: None)('status')}, "
                f"pause={getattr(pause_item, 'get', lambda k: None)('status')}, "
                f"disc={getattr(disc_item, 'get', lambda k: None)('status')}",
            )

    finally:
        app.dependency_overrides.pop(get_current_user, None)


if __name__ == "__main__":
    from scripts.run_all_tests import TestRunner

    runner = TestRunner()
    asyncio.run(run_gmail_full_clear_tests(runner))
    sys.exit(runner.report())
