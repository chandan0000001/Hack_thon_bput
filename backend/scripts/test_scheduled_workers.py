"""RT-8 — Watch renewal + reconciliation scheduled workers tests (Suite 28).

Covers:
1 renew_watches: 3 accounts expiring soon -> 3 watch API calls, watch_expiration updated.
2 renew_watches: paused account skipped.
3 renew_watches: 401 error -> sync_status='error', last_error='reauth_required'.
4 renew_watches: success -> sync_status='active', last_error cleared.
5 reconcile: account last_sync_at 3h ago -> gmail_sync job enqueued.
6 reconcile: account synced 10m ago -> skipped.
7 reconcile: account with reauth_required error -> skipped (needs user action).
8 reconcile: account with transient 'rate_limit' error -> enqueued.
9 cron job registration: verify renew_watches and reconcile_stuck_accounts in WorkerSettings.cron_jobs.
10 RLS: scheduler worker operates under service role (job_queue rows get correct owner_user_id from account).
11 watch_expiration epoch ms conversion: 1700000000000 -> correct datetime.
12 idempotency: reconcile running twice for same stuck account -> only 1 job enqueued (deterministic job_id).

Run standalone:
    uv run python scripts/test_scheduled_workers.py
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import select, text

from app.db.admin import _get_admin_session_maker
from app.db.models import GmailAccount, JobQueue
from app.db.session import async_session_maker, current_user_id
from app.services.gmail.client import GmailAuthError, GmailClient
from app.services.gmail.reconciliation_service import reconcile_stuck_accounts
from app.services.gmail.watch_service import epoch_ms_to_datetime, renew_watches
from app.workers.scheduler_worker import WorkerSettings


async def run_scheduled_workers_tests(runner) -> None:
    def check(condition: bool, name: str, details: str = ""):
        runner.assert_true(condition, name, details)

    print("\n" + "-" * 60)
    print("RT-8 Scheduled Workers & Safety Nets Tests (Suite 28)")
    print("-" * 60)

    admin_maker = _get_admin_session_maker()
    stamp = uuid.uuid4().hex[:8]
    now = datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Helper to ensure user exists
    # ------------------------------------------------------------------
    async def _ensure_user(user_id: str):
        async with admin_maker() as db:
            await db.execute(
                text(
                    "insert into cyberguard.users (id, account_type, is_single_user, created_at) "
                    "values (:u, 'user', true, now()) on conflict (id) do nothing"
                ),
                {"u": user_id},
            )
            await db.commit()

    user_1 = f"sched-usr1-{stamp}"
    await _ensure_user(user_1)

    # ------------------------------------------------------------------
    # 1. renew_watches: 3 accounts expiring soon -> 3 watch API calls, watch_expiration updated
    # ------------------------------------------------------------------
    target_epoch_ms = 1700000000000
    expected_dt = epoch_ms_to_datetime(target_epoch_ms)

    acc_ids_1: list[str] = []
    async with admin_maker() as db:
        for i in range(3):
            acc = GmailAccount(
                owner_user_id=user_1,
                email=f"expiring_{i}_{stamp}@example.com",
                sync_status="active",
                watch_expiration=now + timedelta(hours=2),
                last_history_id="1000",
            )
            acc.set_access_token(f"ya29.token_renew_{i}_{stamp}")
            acc.set_refresh_token(f"1//refresh_renew_{i}_{stamp}")
            db.add(acc)
            await db.flush()
            acc_ids_1.append(str(acc.id))
        await db.commit()

    mock_client_1 = MagicMock(spec=GmailClient)
    mock_client_1.watch = AsyncMock(
        return_value={"historyId": "1005", "expiration": target_epoch_ms}
    )

    async with admin_maker() as db:
        result_1 = await renew_watches(db, client=mock_client_1, account_ids=acc_ids_1)
        # Verify db rows updated
        stmt = select(GmailAccount).where(GmailAccount.id.in_(acc_ids_1))
        renewed_accs = (await db.execute(stmt)).scalars().all()
        all_updated = len(renewed_accs) == 3 and all(
            a.watch_expiration == expected_dt and a.sync_status == "active"
            for a in renewed_accs
        )
        check(
            mock_client_1.watch.call_count == 3 and all_updated,
            "1 renew_watches: 3 accounts expiring soon -> 3 watch API calls, watch_expiration updated",
            f"calls={mock_client_1.watch.call_count}, updated={all_updated}",
        )

    # ------------------------------------------------------------------
    # 2. renew_watches: paused account skipped
    # ------------------------------------------------------------------
    user_paused = f"sched-paused-{stamp}"
    await _ensure_user(user_paused)
    paused_acc_id: str = ""
    async with admin_maker() as db:
        acc_paused = GmailAccount(
            owner_user_id=user_paused,
            email=f"paused_{stamp}@example.com",
            sync_status="paused",
            watch_expiration=now + timedelta(hours=1),
            last_history_id="2000",
        )
        acc_paused.set_access_token(f"ya29.paused_{stamp}")
        acc_paused.set_refresh_token(f"1//paused_{stamp}")
        db.add(acc_paused)
        await db.commit()
        paused_acc_id = str(acc_paused.id)

    mock_client_2 = MagicMock(spec=GmailClient)
    mock_client_2.watch = AsyncMock(return_value={"historyId": "2001", "expiration": target_epoch_ms})

    async with admin_maker() as db:
        await renew_watches(db, client=mock_client_2, account_ids=[paused_acc_id])
        refreshed_paused = (
            await db.execute(select(GmailAccount).where(GmailAccount.id == paused_acc_id))
        ).scalar_one()

        check(
            mock_client_2.watch.call_count == 0
            and refreshed_paused.sync_status == "paused"
            and refreshed_paused.watch_expiration != expected_dt,
            "2 renew_watches: paused account skipped",
            f"calls={mock_client_2.watch.call_count}, status={refreshed_paused.sync_status}",
        )

    # ------------------------------------------------------------------
    # 3. renew_watches: 401 error -> sync_status='error', last_error='reauth_required'
    # ------------------------------------------------------------------
    user_401 = f"sched-401-{stamp}"
    await _ensure_user(user_401)
    acc_401_id: str = ""
    async with admin_maker() as db:
        acc_401 = GmailAccount(
            owner_user_id=user_401,
            email=f"auth_err_{stamp}@example.com",
            sync_status="active",
            watch_expiration=now + timedelta(hours=1),
            last_history_id="3000",
        )
        acc_401.set_access_token(f"ya29.auth_err_{stamp}")
        acc_401.set_refresh_token(f"1//auth_err_{stamp}")
        db.add(acc_401)
        await db.commit()
        acc_401_id = str(acc_401.id)

    mock_client_3 = MagicMock(spec=GmailClient)
    mock_client_3.watch = AsyncMock(side_effect=GmailAuthError("401 Unauthorized", status_code=401))

    async with admin_maker() as db:
        await renew_watches(db, client=mock_client_3, account_ids=[acc_401_id])
        refreshed_401 = (
            await db.execute(select(GmailAccount).where(GmailAccount.id == acc_401_id))
        ).scalar_one()
        check(
            refreshed_401.sync_status == "error" and refreshed_401.last_error == "reauth_required",
            "3 renew_watches: 401 error -> sync_status='error', last_error='reauth_required'",
            f"status={refreshed_401.sync_status}, last_error={refreshed_401.last_error}",
        )

    # ------------------------------------------------------------------
    # 4. renew_watches: success -> sync_status='active', last_error cleared
    # ------------------------------------------------------------------
    user_succ = f"sched-succ-{stamp}"
    await _ensure_user(user_succ)
    acc_succ_id: str = ""
    async with admin_maker() as db:
        acc_succ = GmailAccount(
            owner_user_id=user_succ,
            email=f"recover_{stamp}@example.com",
            sync_status="error",
            last_error="transient_glitch",
            watch_expiration=now + timedelta(hours=1),
            last_history_id="4000",
        )
        acc_succ.set_access_token(f"ya29.recover_{stamp}")
        acc_succ.set_refresh_token(f"1//recover_{stamp}")
        db.add(acc_succ)
        await db.commit()
        acc_succ_id = str(acc_succ.id)

    mock_client_4 = MagicMock(spec=GmailClient)
    mock_client_4.watch = AsyncMock(return_value={"historyId": "4005", "expiration": target_epoch_ms})

    async with admin_maker() as db:
        await renew_watches(db, client=mock_client_4, account_ids=[acc_succ_id])
        refreshed_succ = (
            await db.execute(select(GmailAccount).where(GmailAccount.id == acc_succ_id))
        ).scalar_one()
        check(
            refreshed_succ.sync_status == "active"
            and refreshed_succ.last_error is None
            and refreshed_succ.watch_expiration == expected_dt,
            "4 renew_watches: success -> sync_status='active', last_error cleared",
            f"status={refreshed_succ.sync_status}, last_error={refreshed_succ.last_error}",
        )

    # ------------------------------------------------------------------
    # 5. reconcile: account last_sync_at 3h ago -> gmail_sync job enqueued
    # ------------------------------------------------------------------
    user_stuck = f"sched-stuck-{stamp}"
    await _ensure_user(user_stuck)
    stuck_3h_id: str = ""
    async with admin_maker() as db:
        acc_stuck_3h = GmailAccount(
            owner_user_id=user_stuck,
            email=f"stuck_3h_{stamp}@example.com",
            sync_status="active",
            last_sync_at=now - timedelta(hours=3),
            last_history_id="5000",
        )
        acc_stuck_3h.set_access_token(f"ya29.stuck3h_{stamp}")
        acc_stuck_3h.set_refresh_token(f"1//stuck3h_{stamp}")
        db.add(acc_stuck_3h)
        await db.commit()
        stuck_3h_id = str(acc_stuck_3h.id)

    with patch("app.services.gmail.reconciliation_service.enqueue", new_callable=AsyncMock) as mock_enq:
        mock_enq.return_value = f"gmail_sync:{user_stuck}:reconciliation"
        async with admin_maker() as db:
            await reconcile_stuck_accounts(db, owner_user_id=user_stuck)

            # Check job_queue table
            expected_job_id = f"gmail_sync:{user_stuck}:reconciliation"
            job_row = (
                await db.execute(select(JobQueue).where(JobQueue.job_id == expected_job_id))
            ).scalar_one_or_none()

            check(
                job_row is not None
                and job_row.payload.get("account_id") == stuck_3h_id
                and job_row.payload.get("history_id") == "5000",
                "5 reconcile: account last_sync_at 3h ago -> gmail_sync job enqueued",
                f"job_row={job_row.job_id if job_row else None}",
            )

    # ------------------------------------------------------------------
    # 6. reconcile: account synced 10m ago -> skipped
    # ------------------------------------------------------------------
    fresh_user = f"fresh-usr-{stamp}"
    await _ensure_user(fresh_user)
    async with admin_maker() as db:
        acc_fresh = GmailAccount(
            owner_user_id=fresh_user,
            email=f"fresh_{stamp}@example.com",
            sync_status="active",
            last_sync_at=now - timedelta(minutes=10),
            last_history_id="6000",
        )
        acc_fresh.set_access_token(f"ya29.fresh_{stamp}")
        acc_fresh.set_refresh_token(f"1//fresh_{stamp}")
        db.add(acc_fresh)
        await db.commit()

    with patch("app.services.gmail.reconciliation_service.enqueue", new_callable=AsyncMock):
        async with admin_maker() as db:
            await reconcile_stuck_accounts(db, owner_user_id=fresh_user)
            fresh_job = (
                await db.execute(
                    select(JobQueue).where(JobQueue.job_id == f"gmail_sync:{fresh_user}:reconciliation")
                )
            ).scalar_one_or_none()
            check(
                fresh_job is None,
                "6 reconcile: account synced 10m ago -> skipped",
                f"fresh_job={fresh_job}",
            )

    # ------------------------------------------------------------------
    # 7. reconcile: account with reauth_required error -> skipped (needs user action)
    # ------------------------------------------------------------------
    reauth_user = f"reauth-usr-{stamp}"
    await _ensure_user(reauth_user)
    async with admin_maker() as db:
        acc_reauth = GmailAccount(
            owner_user_id=reauth_user,
            email=f"fatal_err_{stamp}@example.com",
            sync_status="error",
            last_error="reauth_required",
            last_sync_at=now - timedelta(hours=5),
            last_history_id="7000",
        )
        acc_reauth.set_access_token(f"ya29.fatal_{stamp}")
        acc_reauth.set_refresh_token(f"1//fatal_{stamp}")
        db.add(acc_reauth)
        await db.commit()

    with patch("app.services.gmail.reconciliation_service.enqueue", new_callable=AsyncMock):
        async with admin_maker() as db:
            await reconcile_stuck_accounts(db, owner_user_id=reauth_user)
            reauth_job = (
                await db.execute(
                    select(JobQueue).where(JobQueue.job_id == f"gmail_sync:{reauth_user}:reconciliation")
                )
            ).scalar_one_or_none()
            check(
                reauth_job is None,
                "7 reconcile: account with reauth_required error -> skipped (needs user action)",
                f"reauth_job={reauth_job}",
            )

    # ------------------------------------------------------------------
    # 8. reconcile: account with transient 'rate_limit' error -> enqueued
    # ------------------------------------------------------------------
    transient_user = f"transient-usr-{stamp}"
    await _ensure_user(transient_user)
    async with admin_maker() as db:
        acc_transient = GmailAccount(
            owner_user_id=transient_user,
            email=f"transient_{stamp}@example.com",
            sync_status="error",
            last_error="rate_limit",
            last_sync_at=now - timedelta(minutes=5),
            last_history_id="8000",
        )
        acc_transient.set_access_token(f"ya29.transient_{stamp}")
        acc_transient.set_refresh_token(f"1//transient_{stamp}")
        db.add(acc_transient)
        await db.commit()

    with patch("app.services.gmail.reconciliation_service.enqueue", new_callable=AsyncMock):
        async with admin_maker() as db:
            await reconcile_stuck_accounts(db, owner_user_id=transient_user)
            transient_job = (
                await db.execute(
                    select(JobQueue).where(JobQueue.job_id == f"gmail_sync:{transient_user}:reconciliation")
                )
            ).scalar_one_or_none()
            check(
                transient_job is not None and transient_job.owner_user_id == transient_user,
                "8 reconcile: account with transient 'rate_limit' error -> enqueued",
                f"transient_job={transient_job.job_id if transient_job else None}",
            )

    # ------------------------------------------------------------------
    # 9. cron job registration: verify renew_watches and reconcile_stuck_accounts in WorkerSettings.cron_jobs
    # ------------------------------------------------------------------
    cron_jobs = getattr(WorkerSettings, "cron_jobs", [])
    cron_map = {c.coroutine.__name__: c for c in cron_jobs if hasattr(c, "coroutine")}

    watch_cron = cron_map.get("renew_watches")
    reconcile_cron = cron_map.get("reconcile_stuck_accounts")

    watch_cron_valid = (
        watch_cron is not None
        and watch_cron.hour == {0, 6, 12, 18}
        and watch_cron.minute == 0
    )
    reconcile_cron_valid = (
        reconcile_cron is not None
        and reconcile_cron.minute == {15, 45}
    )
    check(
        len(cron_jobs) >= 2 and watch_cron_valid and reconcile_cron_valid,
        "9 cron job registration: verify renew_watches and reconcile_stuck_accounts in WorkerSettings.cron_jobs",
        f"cron_jobs={len(cron_jobs)}, watch_valid={watch_cron_valid}, reconcile_valid={reconcile_cron_valid}",
    )

    # ------------------------------------------------------------------
    # 10. RLS: scheduler worker operates under service role (job_queue rows get correct owner_user_id from account)
    # ------------------------------------------------------------------
    rls_user_a = f"rls-a-{stamp}"
    rls_user_b = f"rls-b-{stamp}"
    await _ensure_user(rls_user_a)
    await _ensure_user(rls_user_b)

    async with admin_maker() as db:
        acc_a = GmailAccount(
            owner_user_id=rls_user_a,
            email=f"rls_a_{stamp}@example.com",
            sync_status="active",
            last_sync_at=now - timedelta(hours=3),
            last_history_id="10001",
        )
        acc_a.set_access_token(f"ya29.rls_a_{stamp}")
        acc_a.set_refresh_token(f"1//rls_a_{stamp}")
        db.add(acc_a)

        acc_b = GmailAccount(
            owner_user_id=rls_user_b,
            email=f"rls_b_{stamp}@example.com",
            sync_status="active",
            last_sync_at=now - timedelta(hours=3),
            last_history_id="10002",
        )
        acc_b.set_access_token(f"ya29.rls_b_{stamp}")
        acc_b.set_refresh_token(f"1//rls_b_{stamp}")
        db.add(acc_b)
        await db.commit()

    with patch("app.services.gmail.reconciliation_service.enqueue", new_callable=AsyncMock):
        async with admin_maker() as db:
            await reconcile_stuck_accounts(db, account_ids=[str(acc_a.id), str(acc_b.id)])

            job_a = (
                await db.execute(
                    select(JobQueue).where(JobQueue.job_id == f"gmail_sync:{rls_user_a}:reconciliation")
                )
            ).scalar_one_or_none()
            owner_correct = job_a is not None and job_a.owner_user_id == rls_user_a

    # In tenant context, user B should not see user A's job
    current_user_id.set(rls_user_b)
    async with async_session_maker() as db:
        job_for_b = (
            await db.execute(
                select(JobQueue).where(JobQueue.job_id == f"gmail_sync:{rls_user_a}:reconciliation")
            )
        ).scalar_one_or_none()
        isolation_ok = job_for_b is None

    check(
        owner_correct and isolation_ok,
        "10 RLS: scheduler worker operates under service role (job_queue rows get correct owner_user_id from account)",
        f"owner_correct={owner_correct}, isolation_ok={isolation_ok}",
    )

    # ------------------------------------------------------------------
    # 11. watch_expiration epoch ms conversion: 1700000000000 -> correct datetime
    # ------------------------------------------------------------------
    dt_from_int = epoch_ms_to_datetime(1700000000000)
    dt_from_str = epoch_ms_to_datetime("1700000000000")
    expected_fixed = datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)
    check(
        dt_from_int == expected_fixed and dt_from_str == expected_fixed,
        "11 watch_expiration epoch ms conversion: 1700000000000 -> correct datetime",
        f"got={dt_from_int}, expected={expected_fixed}",
    )

    # ------------------------------------------------------------------
    # 12. idempotency: reconcile running twice for same stuck account -> only 1 job enqueued (deterministic job_id)
    # ------------------------------------------------------------------
    idem_user = f"idem-usr-{stamp}"
    await _ensure_user(idem_user)
    idem_acc_id: str = ""
    async with admin_maker() as db:
        acc_idem = GmailAccount(
            owner_user_id=idem_user,
            email=f"idem_{stamp}@example.com",
            sync_status="active",
            last_sync_at=now - timedelta(hours=4),
            last_history_id="9000",
        )
        acc_idem.set_access_token(f"ya29.idem_{stamp}")
        acc_idem.set_refresh_token(f"1//idem_{stamp}")
        db.add(acc_idem)
        await db.commit()
        idem_acc_id = str(acc_idem.id)

    with patch("app.services.gmail.reconciliation_service.enqueue", new_callable=AsyncMock):
        async with admin_maker() as db:
            # First execution
            await reconcile_stuck_accounts(db, account_ids=[idem_acc_id])
            # Second execution
            await reconcile_stuck_accounts(db, account_ids=[idem_acc_id])

            # Assert database has strictly 1 record for this reconciliation job
            rows = (
                await db.execute(
                    select(JobQueue).where(JobQueue.job_id == f"gmail_sync:{idem_user}:reconciliation")
                )
            ).scalars().all()

            check(
                len(rows) == 1,
                "12 idempotency: reconcile running twice for same stuck account -> only 1 job enqueued (deterministic job_id)",
                f"row_count={len(rows)}",
            )


class StandaloneRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def assert_true(self, condition: bool, name: str, details: str = ""):
        if condition:
            self.passed += 1
            print(f"  ✔ PASS: {name}")
        else:
            self.failed += 1
            print(f"  ✖ FAIL: {name} - {details}")

    def report(self) -> int:
        total = self.passed + self.failed
        print(f"\nSuite 28 total: {self.passed}/{total} passed")
        return 0 if self.failed == 0 else 1


if __name__ == "__main__":
    runner = StandaloneRunner()
    asyncio.run(run_scheduled_workers_tests(runner))
    sys.exit(runner.report())
