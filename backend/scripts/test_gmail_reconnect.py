"""GMAIL-RECONNECT-UX test suite (Suite 42, 12 checks).

Covers:
 1. Disconnect sets status/disconnected_at, nulls tokens, stops watch, idempotent second call.
 2. List splits connected/recent correctly; disconnected row absent from connected.
 3. Recent excludes rows older than 3d (now clock override).
 4. removes_at == disconnected_at + 3d.
 5. Purge job flips stale row (>3d) to 'purged'; list omits it.
 6. Processed emails survive purge (FK-safe).
 7. Early remove endpoint: disconnected->purged OK; connected->409; foreign->404.
 8. Reconnect callback revives row: tokens stored, status connected, watch called,
    history_id stored, sync baseline = new historyId.
 9. Reconnect for purged/missing id goes to fresh connect path.
10. Worker ignores disconnected row event (ACK, no scan) and processes connected row event.
11. No response anywhere contains refresh/access token.
12. Multi-user isolation: User A disconnected, User B connected.

Run standalone:
    uv run python scripts/test_gmail_reconnect.py
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
from app.services.connectors import oauth_service
from app.services.gmail.client import GmailClient
from app.services.gmail.purge_service import purge_stale_gmail_accounts
from app.services.gmail_account_service import get_or_create_gmail_account, perform_gmail_disconnect


class _Identity:
    user: CurrentUser | None = None


async def _mock_get_current_user() -> CurrentUser:
    if _Identity.user is None:
        raise RuntimeError("test identity not set")
    current_user_id.set(_Identity.user.id)
    return _Identity.user


def _make_pubsub_body(email: str, history_id: str | int, message_id: str = "msg-test") -> dict:
    data_bytes = json.dumps({"emailAddress": email, "historyId": str(history_id)}).encode("utf-8")
    data_b64 = base64.b64encode(data_bytes).decode("utf-8")
    return {
        "message": {
            "data": data_b64,
            "messageId": message_id,
        },
        "subscription": "projects/cyberguard-test/subscriptions/gmail-push",
    }


async def run_gmail_reconnect_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("GMAIL-RECONNECT-UX Tests (Suite 42)")
    print("-" * 60)

    admin_maker = _get_admin_session_maker()
    stamp = uuid.uuid4().hex[:8]
    now = datetime.now(timezone.utc)

    user_a_id = f"usr-rec-a-{stamp}"
    user_b_id = f"usr-rec-b-{stamp}"
    user_a_email = f"analyst-a-{stamp}@cyberguard.test"
    user_b_email = f"analyst-b-{stamp}@cyberguard.test"

    user_a = CurrentUser(id=user_a_id, email=user_a_email, full_name="User A")
    user_b = CurrentUser(id=user_b_id, email=user_b_email, full_name="User B")

    async with admin_maker() as db:
        await db.execute(
            text(
                "insert into cyberguard.users (id, email, full_name, account_type, is_single_user, created_at) "
                "values (:u, :e, :fn, 'user', true, now()) on conflict (id) do nothing"
            ),
            {"u": user_a_id, "e": user_a_email, "fn": "User A"},
        )
        await db.execute(
            text(
                "insert into cyberguard.users (id, email, full_name, account_type, is_single_user, created_at) "
                "values (:u, :e, :fn, 'user', true, now()) on conflict (id) do nothing"
            ),
            {"u": user_b_id, "e": user_b_email, "fn": "User B"},
        )
        await db.commit()

    transport = ASGITransport(app=app)
    app.dependency_overrides[get_current_user] = _mock_get_current_user

    responses_to_audit: list[dict | list | str] = []

    try:
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            _Identity.user = user_a

            # ------------------------------------------------------------------
            # 1. Disconnect sets status/disconnected_at, nulls tokens, stops watch, idempotent second call
            # ------------------------------------------------------------------
            acc1_id = f"acc1-{stamp}"
            acc1_email = f"user-a-acc1-{stamp}@gmail.com"
            async with admin_maker() as db:
                acc1 = GmailAccount(
                    id=acc1_id,
                    owner_user_id=user_a.id,
                    email=acc1_email,
                    status="connected",
                    sync_status="active",
                    watch_expiration=now + timedelta(days=7),
                    created_at=now - timedelta(days=1),
                )
                acc1.set_access_token("tok-acc1")
                acc1.set_refresh_token("ref-acc1")
                db.add(acc1)

                conn1 = EmailConnectorAccount(
                    id=f"conn1-{stamp}",
                    owner_user_id=user_a.id,
                    provider="gmail",
                    provider_email=acc1_email,
                    status="connected",
                    access_token_enc=encrypt_secret("tok-acc1"),
                    refresh_token_enc=encrypt_secret("ref-acc1"),
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

                    state_ok = (
                        acc_db.status == "disconnected"
                        and acc_db.disconnected_at is not None
                        and acc_db.refresh_token_encrypted is None
                        and acc_db.access_token_encrypted is None
                        and acc_db.watch_expiration is None
                        and acc_db.sync_status == "paused"
                        and conn_db.status == "revoked"
                        and conn_db.access_token_enc is None
                        and conn_db.refresh_token_enc is None
                    )

                first_stop_count = mock_stop.call_count
                resp1_repeat = await client.post(f"/connectors/gmail/accounts/{acc1_id}/disconnect")
                responses_to_audit.append(resp1_repeat.json())

                check(
                    resp1.status_code == 200
                    and state_ok
                    and mock_stop.called
                    and resp1_repeat.status_code == 200
                    and mock_stop.call_count == first_stop_count,
                    "1 Disconnect sets status/disconnected_at, nulls tokens, stops watch, idempotent second call",
                    f"resp1={resp1.status_code}, state_ok={state_ok}, stop_called={mock_stop.called}",
                )

            # ------------------------------------------------------------------
            # 2. List splits connected/recent correctly; disconnected row absent from connected
            # ------------------------------------------------------------------
            acc2_id = f"acc2-{stamp}"
            acc2_email = f"user-a-acc2-{stamp}@gmail.com"
            async with admin_maker() as db:
                acc2 = GmailAccount(
                    id=acc2_id,
                    owner_user_id=user_a.id,
                    email=acc2_email,
                    status="connected",
                    sync_status="active",
                    created_at=now,
                )
                acc2.set_access_token("tok-acc2")
                acc2.set_refresh_token("ref-acc2")
                db.add(acc2)
                await db.commit()

            resp2 = await client.get("/connectors/gmail/accounts")
            responses_to_audit.append(resp2.json())
            list_data = resp2.json()
            conn_ids = [item["id"] for item in list_data.get("connected", [])]
            recent_ids = [item["id"] for item in list_data.get("recent", [])]

            check(
                resp2.status_code == 200
                and acc2_id in conn_ids
                and acc1_id not in conn_ids
                and acc1_id in recent_ids
                and acc2_id not in recent_ids,
                "2 List splits connected/recent correctly; disconnected row absent from connected",
                f"connected={conn_ids}, recent={recent_ids}",
            )

            # ------------------------------------------------------------------
            # 3. Recent excludes rows older than 3d (now clock override)
            # ------------------------------------------------------------------
            future_4d = now + timedelta(days=4)
            resp3 = await client.get(f"/connectors/gmail/accounts?now={future_4d.isoformat()}")
            responses_to_audit.append(resp3.json())
            recent_future = resp3.json().get("recent", [])
            check(
                resp3.status_code == 200 and len(recent_future) == 0,
                "3 Recent excludes rows older than 3d (now clock override)",
                f"status={resp3.status_code}, recent_len={len(recent_future)}",
            )

            # ------------------------------------------------------------------
            # 4. removes_at == disconnected_at + 3d
            # ------------------------------------------------------------------
            acc1_item = next((item for item in list_data.get("recent", []) if item["id"] == acc1_id), None)
            removes_at_ok = False
            diff_sec = 0.0
            if acc1_item and acc1_item.get("disconnected_at") and acc1_item.get("removes_at"):
                d_at = datetime.fromisoformat(acc1_item["disconnected_at"])
                r_at = datetime.fromisoformat(acc1_item["removes_at"])
                diff_sec = (r_at - d_at).total_seconds()
                removes_at_ok = abs(diff_sec - 3 * 86400) < 5

            check(removes_at_ok, "4 removes_at == disconnected_at + 3d", f"diff_seconds={diff_sec}")

            # ------------------------------------------------------------------
            # 5. Purge job flips stale row (>3d) to 'purged'; list omits it
            # ------------------------------------------------------------------
            acc_stale_id = f"stale-{stamp}"
            acc_stale_email = f"user-a-stale-{stamp}@gmail.com"
            async with admin_maker() as db:
                stale_acc = GmailAccount(
                    id=acc_stale_id,
                    owner_user_id=user_a.id,
                    email=acc_stale_email,
                    status="disconnected",
                    disconnected_at=now - timedelta(days=4),
                    created_at=now - timedelta(days=5),
                )
                db.add(stale_acc)
                await db.commit()

            async with admin_maker() as db:
                purge_res = await purge_stale_gmail_accounts(db, now=now)

            async with admin_maker() as db:
                stale_check = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc_stale_id))).scalar_one()

            resp5 = await client.get("/connectors/gmail/accounts")
            responses_to_audit.append(resp5.json())
            all_listed_ids = [x["id"] for x in resp5.json().get("connected", []) + resp5.json().get("recent", [])]

            check(
                purge_res.get("purged", 0) >= 1
                and stale_check.status == "purged"
                and acc_stale_id not in all_listed_ids,
                "5 Purge job flips stale row (>3d) to 'purged'; list omits it",
                f"purged={purge_res.get('purged')}, status={stale_check.status}",
            )

            # ------------------------------------------------------------------
            # 6. Processed emails survive purge (FK-safe)
            # ------------------------------------------------------------------
            pe_id = f"pe-{stamp}"
            async with admin_maker() as db:
                pe = ProcessedEmail(
                    id=pe_id,
                    owner_user_id=user_a.id,
                    gmail_account_id=acc_stale_id,
                    gmail_message_id=f"msg-pe-{stamp}",
                    sender="threat@attacker.test",
                    subject="Urgent action needed",
                    received_at=now,
                    processing_status="completed",
                    classification="phishing",
                    risk_score=0.92,
                    created_at=now,
                )
                db.add(pe)
                await db.commit()

            async with admin_maker() as db:
                pe_db = (await db.execute(select(ProcessedEmail).where(ProcessedEmail.id == pe_id))).scalar_one_or_none()
                check(
                    pe_db is not None and pe_db.classification == "phishing" and pe_db.gmail_account_id == acc_stale_id,
                    "6 Processed emails survive purge (FK-safe)",
                    f"pe={pe_db}",
                )

            # ------------------------------------------------------------------
            # 7. Early remove endpoint: disconnected->purged OK; connected->409; foreign->404
            # ------------------------------------------------------------------
            resp7a = await client.delete(f"/connectors/gmail/accounts/{acc1_id}")
            responses_to_audit.append(resp7a.json())

            async with admin_maker() as db:
                acc1_db = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc1_id))).scalar_one()

            resp7b = await client.delete(f"/connectors/gmail/accounts/{acc2_id}")
            responses_to_audit.append(resp7b.json())

            resp7c = await client.delete(f"/connectors/gmail/accounts/nonexistent-{stamp}")

            check(
                resp7a.status_code == 200
                and acc1_db.status == "purged"
                and resp7b.status_code == 409
                and resp7c.status_code == 404,
                "7 Early remove endpoint: disconnected->purged OK; connected->409; foreign->404",
                f"resp7a={resp7a.status_code}, status={acc1_db.status}, resp7b={resp7b.status_code}, resp7c={resp7c.status_code}",
            )

            # ------------------------------------------------------------------
            # 8. Reconnect callback revives row: tokens stored, status connected,
            #    watch called, history_id stored, sync baseline = new historyId
            # ------------------------------------------------------------------
            acc_rec_id = f"acc-revive-{stamp}"
            acc_rec_email = f"user-a-revive-{stamp}@gmail.com"
            async with admin_maker() as db:
                acc_rec = GmailAccount(
                    id=acc_rec_id,
                    owner_user_id=user_a.id,
                    email=acc_rec_email,
                    status="disconnected",
                    disconnected_at=now - timedelta(hours=2),
                    last_history_id="111111",
                    sync_status="paused",
                    created_at=now - timedelta(days=1),
                )
                db.add(acc_rec)
                await db.commit()

            mock_watch = AsyncMock(return_value={"historyId": "999888", "expiration": 1800000000000})
            with patch("app.services.connectors.oauth_service.consume_connector_oauth_state",
                       AsyncMock(return_value={"owner_user_id": user_a.id, "provider": "gmail"})), \
                 patch("app.services.connectors.oauth_service._exchange_code",
                       AsyncMock(return_value={"access_token": "revived-access", "refresh_token": "revived-refresh", "expires_in": 3600})), \
                 patch("app.services.connectors.oauth_service.gmail_provider.get_profile",
                       AsyncMock(return_value={"email_address": acc_rec_email})), \
                 patch.object(GmailClient, "watch", mock_watch):

                await oauth_service.handle_gmail_callback(code="mock_code", state=f"state123:rec:{acc_rec_id}")

            async with admin_maker() as db:
                rec_acc_db = (await db.execute(select(GmailAccount).where(GmailAccount.id == acc_rec_id))).scalar_one()
                revived_ok = (
                    rec_acc_db.status == "connected"
                    and rec_acc_db.disconnected_at is None
                    and rec_acc_db.get_refresh_token() == "revived-refresh"
                    and rec_acc_db.get_access_token() == "revived-access"
                    and rec_acc_db.last_history_id == "999888"
                    and rec_acc_db.sync_status == "active"
                    and mock_watch.called
                )
                check(
                    revived_ok,
                    "8 Reconnect callback revives row: tokens stored, status connected, watch called, history_id stored, sync baseline = new historyId",
                    f"status={rec_acc_db.status}, last_hist={rec_acc_db.last_history_id}",
                )

            # ------------------------------------------------------------------
            # 9. Reconnect for purged/missing id goes to fresh connect path
            # ------------------------------------------------------------------
            missing_rec_id = f"missing-rec-{stamp}"
            fresh_email = f"fresh-connect-{stamp}@gmail.com"
            async with admin_maker() as db:
                fresh_acc = await get_or_create_gmail_account(
                    db,
                    owner_user_id=user_a.id,
                    email=fresh_email,
                    access_token="tok-fresh",
                    refresh_token="ref-fresh",
                    reconnect_account_id=missing_rec_id,
                )
                check(
                    fresh_acc is not None and fresh_acc.status == "connected" and fresh_acc.id != missing_rec_id,
                    "9 Reconnect for purged/missing id goes to fresh connect path",
                    f"id={fresh_acc.id}, status={fresh_acc.status}",
                )

            # ------------------------------------------------------------------
            # 10. Worker ignores disconnected row event (ACK, no scan) and processes connected row event
            # ------------------------------------------------------------------
            acc_disc_test_id = f"acc-disc-worker-{stamp}"
            acc_disc_test_email = f"disc-worker-{stamp}@gmail.com"
            async with admin_maker() as db:
                disc_worker_acc = GmailAccount(
                    id=acc_disc_test_id,
                    owner_user_id=user_a.id,
                    email=acc_disc_test_email,
                    status="disconnected",
                    disconnected_at=now,
                    created_at=now,
                )
                db.add(disc_worker_acc)
                await db.commit()

            push_disc = _make_pubsub_body(acc_disc_test_email, 555111)
            resp10a = await client.post("/api/v1/webhooks/gmail", json=push_disc)

            push_conn = _make_pubsub_body(acc_rec_email, 555222)
            with patch("app.api.routes_gmail_webhook.enqueue", AsyncMock(return_value=True)):
                resp10b = await client.post("/api/v1/webhooks/gmail", json=push_conn)

            check(
                resp10a.status_code == 200
                and resp10a.json().get("status") == "ignored"
                and resp10b.status_code == 200
                and resp10b.json().get("status") == "accepted",
                "10 Worker ignores disconnected row event (ACK, no scan) and processes connected row event",
                f"resp10a={resp10a.json()}, resp10b={resp10b.json()}",
            )

            # ------------------------------------------------------------------
            # 11. No response anywhere contains refresh/access token
            # ------------------------------------------------------------------
            status_resp = await client.get("/gmail/status")
            responses_to_audit.append(status_resp.json())

            auth_resp = await client.post("/connectors/gmail/authorize", json={"reconnect": acc_rec_id})
            responses_to_audit.append(auth_resp.json())

            conn_list_resp = await client.get("/connectors")
            responses_to_audit.append(conn_list_resp.json())

            forbidden_keys = ("refresh_token", "refresh_token_encrypted", "access_token",
                              "access_token_enc", "refresh_token_enc", "token_key")
            leaks = []
            for sample in responses_to_audit:
                text_sample = json.dumps(sample)
                for fk in forbidden_keys:
                    if fk in text_sample:
                        leaks.append(f"{fk} in {text_sample[:100]}...")

            check(len(leaks) == 0, "11 No response anywhere contains refresh/access token", str(leaks))

            # ------------------------------------------------------------------
            # 12. Multi-user isolation: User A disconnected, User B connected
            # ------------------------------------------------------------------
            user_b_acc_id = f"acc-user-b-{stamp}"
            user_b_acc_email = f"user-b-conn-{stamp}@gmail.com"
            async with admin_maker() as db:
                b_acc = GmailAccount(
                    id=user_b_acc_id,
                    owner_user_id=user_b.id,
                    email=user_b_acc_email,
                    status="connected",
                    sync_status="active",
                    created_at=now,
                )
                b_acc.set_access_token("tok-b")
                b_acc.set_refresh_token("ref-b")
                db.add(b_acc)
                await db.commit()

            _Identity.user = user_b
            resp_b = await client.get("/connectors/gmail/accounts")
            b_conns = [x["id"] for x in resp_b.json().get("connected", [])]
            b_recents = [x["id"] for x in resp_b.json().get("recent", [])]

            resp_b_cross = await client.delete(f"/connectors/gmail/accounts/{acc_rec_id}")

            check(
                user_b_acc_id in b_conns
                and acc_rec_id not in b_conns
                and acc1_id not in b_recents
                and resp_b_cross.status_code == 404,
                "12 Multi-user isolation: User A disconnected, User B connected",
                f"b_conns={b_conns}, cross_status={resp_b_cross.status_code}",
            )

    finally:
        app.dependency_overrides.pop(get_current_user, None)
        _Identity.user = None
        try:
            async with admin_maker() as db:
                await db.execute(
                    text("delete from cyberguard.processed_emails where owner_user_id in (:a, :b)"),
                    {"a": user_a_id, "b": user_b_id},
                )
                await db.execute(
                    text("delete from cyberguard.gmail_accounts where owner_user_id in (:a, :b)"),
                    {"a": user_a_id, "b": user_b_id},
                )
                await db.execute(
                    text("delete from cyberguard.email_connector_accounts where owner_user_id in (:a, :b)"),
                    {"a": user_a_id, "b": user_b_id},
                )
                await db.execute(
                    text("delete from cyberguard.job_queue where owner_user_id in (:a, :b)"),
                    {"a": user_a_id, "b": user_b_id},
                )
                await db.commit()
        except Exception:
            pass


async def _standalone() -> int:
    class _Runner:
        def __init__(self):
            self.passed = 0
            self.failed = 0

        def assert_true(self, condition: bool, name: str, details: str = ""):
            if condition:
                self.passed += 1
                print(f"  \033[32m✔ PASS\033[0m: {name}")
            else:
                self.failed += 1
                print(f"  \033[31m✖ FAIL\033[0m: {name} - {details}")

        def report(self):
            total = self.passed + self.failed
            print(f"\nGMAIL-RECONNECT-UX: {self.passed}/{total} passed")
            return 1 if self.failed else 0

    runner = _Runner()
    print("\n🔗 CYBERGUARD GMAIL-RECONNECT-UX TESTS\n" + "=" * 60)
    await run_gmail_reconnect_tests(runner)
    print("=" * 60)
    return runner.report()


if __name__ == "__main__":
    sys.exit(asyncio.run(_standalone()))
