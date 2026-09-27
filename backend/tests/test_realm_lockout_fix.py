"""REGRESSION TESTS for REALM-LOCKOUT-FIX.

Root cause reproduced: personal-mode sign-in returned 403 (permission_denied)
for invalid credentials while cyberguard.users was empty, and the frontend
mapped ANY 403 from /auth/signin to the account_type_mismatch banner —
locking users out with a false "registered as an organization account"
message. The backend also never enforced the realm check itself (it was
dropped in the unify commit), so real org rows were accepted in personal mode.

These tests pin the corrected contract:
- credential failures are 401 invalid_credentials (never 403),
- only COMMITTED org rows reject personal-mode sign-in (403 account_type_mismatch),
- an empty users table never rejects,
- no row is ever created or left behind by a failed sign-in.
"""

import uuid
from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.db.models import User
from app.db.session import async_session_maker
from app.main import app

MIGRATION_0103 = "alembic/versions/0103_account_type_realm.py"


def _make_mock_sb_response(user_id: str, email: str):
    user_mock = MagicMock()
    user_mock.id = user_id
    user_mock.email = email
    user_mock.user_metadata = {"full_name": email.split("@")[0]}

    session_mock = MagicMock()
    session_mock.access_token = f"test-token-{user_id}"
    session_mock.refresh_token = f"refresh-{user_id}"
    session_mock.expires_in = 3600
    session_mock.token_type = "bearer"

    res = MagicMock()
    res.user = user_mock
    res.session = session_mock
    return res


async def _count_rows_for_email(email: str) -> int:
    async with async_session_maker() as db:
        res = await db.execute(select(User).where(User.email == email))
        return len(res.scalars().all())


@pytest.fixture
async def async_client(initialized_db):
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_01_empty_table_personal_signin_unknown_email_401_never_403(async_client):
    """1. empty_table_personal_signin_unknown_email_401: with cyberguard.users empty for the
    email, a failed personal sign-in is 401 invalid_credentials — never 403, never a
    account_type_mismatch verdict, and no row is provisioned."""
    email = f"ghost_{uuid.uuid4().hex[:8]}@example.com"
    assert await _count_rows_for_email(email) == 0

    with patch("app.core.security._get_anon_client") as mock_get_client:
        mock_client = MagicMock()
        mock_client.auth.sign_in_with_password.side_effect = Exception("Invalid login credentials")
        mock_get_client.return_value = mock_client

        resp = await async_client.post(
            "/api/v1/auth/signin",
            json={"identifier": email, "password": "Whatever123!", "mode": "personal"},
        )

    assert resp.status_code == 401, resp.text
    body = resp.json()
    assert body["error"] == "invalid_credentials"
    assert body["error"] != "account_type_mismatch"
    assert await _count_rows_for_email(email) == 0


@pytest.mark.asyncio
async def test_02_empty_table_auth_side_identity_personal_signin_200_provisions_personal(
    async_client,
):
    """2. empty_table_signin_auth_side_identity: sign-in succeeds (200) when only the auth-side
    identity exists, resolves to 'personal', and the profile is provisioned with
    account_type='personal' by the post-auth JIT path (committed, separate transaction)."""
    test_id = str(uuid.uuid4())
    email = f"fresh_{test_id[:8]}@example.com"
    assert await _count_rows_for_email(email) == 0

    sb_res = _make_mock_sb_response(test_id, email)
    with patch("app.core.security._get_anon_client") as mock_get_client:
        mock_client = MagicMock()
        mock_client.auth.sign_in_with_password.return_value = sb_res
        mock_get_client.return_value = mock_client

        resp = await async_client.post(
            "/api/v1/auth/signin",
            json={"identifier": email, "password": "ValidPassword123!", "mode": "personal"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["user"]["account_type"] == "personal"

        # Profile bootstrap happens AFTER the auth verdict, via /auth/me JIT
        # (the sign-in transaction itself stays read-only). The "test-" token
        # prefix routes get_current_user through its deterministic fallback —
        # force the Supabase verification to raise so the fallback engages.
        mock_client.auth.sign_in_with_password.return_value = sb_res
        mock_client.auth.get_user.side_effect = Exception("token verification unavailable")
        me = await async_client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer test-{email}"},
        )
        assert me.status_code == 200, me.text

    async with async_session_maker() as db:
        res = await db.execute(select(User).where(User.email == email))
        rows = res.scalars().all()
        assert len(rows) == 1
        assert rows[0].account_type == "personal"
        assert rows[0].is_single_user is True


@pytest.mark.asyncio
async def test_03_org_window_register_commits_org(async_client):
    """3. org_window_register_commits_org: the org window (register-org) is the only sanctioned
    self-service path that commits account_type='org'."""
    test_id = str(uuid.uuid4())
    email = f"orgwin_{test_id[:8]}@example.com"
    sb_res = _make_mock_sb_response(test_id, email)

    with patch("app.core.security._get_anon_client") as mock_get_client:
        mock_client = MagicMock()
        mock_client.auth.sign_up.return_value = sb_res
        mock_get_client.return_value = mock_client

        resp = await async_client.post(
            "/api/v1/auth/register-org",
            json={
                "email": email,
                "password": "Password123!",
                "org_name": f"Realm Corp {test_id[:6]}",
            },
        )
        assert resp.status_code == 201, resp.text

    async with async_session_maker() as db:
        res = await db.execute(select(User).where(User.email == email))
        user = res.scalar_one_or_none()
        assert user is not None
        assert user.account_type == "org"
        assert user.is_single_user is False


@pytest.mark.asyncio
async def test_04_personal_mode_for_committed_org_row_403_banner(async_client):
    """4. personal_mode_org_row_403_banner: a committed org row rejects personal-mode sign-in
    with 403 account_type_mismatch + use_org_mode hint (the exact payload the frontend
    banner renders), and creates no extra row."""
    test_id = str(uuid.uuid4())
    email = f"lockout_{test_id[:8]}@example.com"

    async with async_session_maker() as db:
        db.add(
            User(
                id=test_id,
                email=email,
                username=f"lock{test_id[:6]}",
                account_type="org",
                status="active",
                is_single_user=False,
            )
        )
        await db.commit()

    before = await _count_rows_for_email(email)

    sb_res = _make_mock_sb_response(test_id, email)
    with patch("app.core.security._get_anon_client") as mock_get_client:
        mock_client = MagicMock()
        mock_client.auth.sign_in_with_password.return_value = sb_res
        mock_get_client.return_value = mock_client

        resp = await async_client.post(
            "/api/v1/auth/signin",
            json={"identifier": email, "password": "ValidPassword123!", "mode": "personal"},
        )

    assert resp.status_code == 403, resp.text
    body = resp.json()
    assert body["error"] == "account_type_mismatch"
    assert body["hint"] == "use_org_mode"
    assert await _count_rows_for_email(email) == before


@pytest.mark.asyncio
async def test_05_org_mode_for_committed_org_row_200(async_client):
    """5. org_mode_org_row_200: the same committed org row signs in fine in org mode."""
    test_id = str(uuid.uuid4())
    email = f"orgok_{test_id[:8]}@example.com"

    async with async_session_maker() as db:
        db.add(
            User(
                id=test_id,
                email=email,
                username=f"orgok{test_id[:6]}",
                account_type="org",
                status="active",
                is_single_user=False,
            )
        )
        await db.commit()

    sb_res = _make_mock_sb_response(test_id, email)
    with patch("app.core.security._get_anon_client") as mock_get_client:
        mock_client = MagicMock()
        mock_client.auth.sign_in_with_password.return_value = sb_res
        mock_get_client.return_value = mock_client

        resp = await async_client.post(
            "/api/v1/auth/signin",
            json={"identifier": email, "password": "ValidPassword123!", "mode": "org"},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user"]["email"] == email
    assert body["user"]["account_type"] == "org"
    assert "access_token" in body


@pytest.mark.asyncio
async def test_06_defaults_parity_orm_vs_migration():
    """6. defaults_parity: the ORM column default and the migration server default for
    account_type are both 'personal' — a provisioned row can never default to 'org'
    without an explicit org-window origin."""
    from app.db.models import User

    orm_default = User.__table__.columns["account_type"].default.arg
    assert orm_default == "personal"

    with open(MIGRATION_0103, encoding="utf-8") as fh:
        migration_src = fh.read()
    assert "ADD COLUMN account_type VARCHAR(16) NOT NULL DEFAULT 'personal'" in migration_src
    assert "ALTER COLUMN account_type SET DEFAULT 'personal'" in migration_src
    # The downgrade returns to the legacy default; upgrade paths must not.
    assert migration_src.index("SET DEFAULT 'personal'") < migration_src.index("SET DEFAULT 'user'")


@pytest.mark.asyncio
async def test_07_no_row_left_behind_after_any_failed_signin(async_client):
    """7. no_row_left_behind_after_any_403: failed sign-ins (401 for unknown emails, 403 for
    realm-locked org rows) leave the users table exactly as they found it."""
    ghost_email = f"noleak_{uuid.uuid4().hex[:8]}@example.com"
    org_id = str(uuid.uuid4())
    org_email = f"noleak_org_{org_id[:8]}@example.com"

    async with async_session_maker() as db:
        db.add(
            User(
                id=org_id,
                email=org_email,
                username=f"nlk{org_id[:6]}",
                account_type="org",
                status="active",
                is_single_user=False,
            )
        )
        await db.commit()

    ghost_before = await _count_rows_for_email(ghost_email)
    org_before = await _count_rows_for_email(org_email)

    with patch("app.core.security._get_anon_client") as mock_get_client:
        mock_client = MagicMock()
        # Credential failure for the unknown email
        mock_client.auth.sign_in_with_password.side_effect = Exception("Invalid login credentials")
        mock_get_client.return_value = mock_client

        resp_401 = await async_client.post(
            "/api/v1/auth/signin",
            json={"identifier": ghost_email, "password": "Whatever123!", "mode": "personal"},
        )
        assert resp_401.status_code == 401

        # Realm mismatch for the committed org row (credential check passes)
        mock_client.auth.sign_in_with_password.side_effect = None
        mock_client.auth.sign_in_with_password.return_value = _make_mock_sb_response(org_id, org_email)
        resp_403 = await async_client.post(
            "/api/v1/auth/signin",
            json={"identifier": org_email, "password": "ValidPassword123!", "mode": "personal"},
        )
        assert resp_403.status_code == 403
        assert resp_403.json()["error"] == "account_type_mismatch"

    assert await _count_rows_for_email(ghost_email) == ghost_before == 0
    assert await _count_rows_for_email(org_email) == org_before == 1
