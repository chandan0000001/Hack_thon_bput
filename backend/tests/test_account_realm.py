"""Tests for ACCOUNT-REALM-FIX: account realm enforcement and single identity invariant."""

import uuid
from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.db.admin import find_user_by_email, precreate_user_for_invite, claim_invited_stub
from app.db.models import OrgOrganization, OrgMember, User
from app.db.session import async_session_maker
from app.main import app


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


@pytest.fixture
async def async_client(initialized_db):
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_01_signup_sets_personal_account_type(async_client):
    """1. signup_sets_personal_account_type: verify personal registration creates account_type='personal'."""
    test_id = str(uuid.uuid4())
    test_email = f"pers_{test_id[:8]}@example.com"
    sb_res = _make_mock_sb_response(test_id, test_email)

    with patch("app.core.security._get_anon_client") as mock_get_client:
        mock_client = MagicMock()
        mock_client.auth.sign_up.return_value = sb_res
        mock_get_client.return_value = mock_client

        resp = await async_client.post(
            "/api/v1/auth/signup",
            json={
                "email": test_email,
                "password": "Password123!",
                "username": f"puser{test_id[:6]}",
            },
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["user"]["email"] == test_email

        async with async_session_maker() as db:
            res = await db.execute(select(User).where(User.email == test_email))
            user = res.scalar_one_or_none()
            assert user is not None
            assert user.account_type == "personal"
            assert user.is_single_user is True


@pytest.mark.asyncio
async def test_02_register_org_sets_org_account_type(async_client):
    """2. register_org_sets_org_account_type: verify org registration creates account_type='org'."""
    test_id = str(uuid.uuid4())
    test_email = f"org_{test_id[:8]}@example.com"
    sb_res = _make_mock_sb_response(test_id, test_email)

    with patch("app.core.security._get_anon_client") as mock_get_client:
        mock_client = MagicMock()
        mock_client.auth.sign_up.return_value = sb_res
        mock_get_client.return_value = mock_client

        resp = await async_client.post(
            "/api/v1/auth/register-org",
            json={
                "email": test_email,
                "password": "Password123!",
                "org_name": f"Org {test_id[:6]}",
                "username": f"orguser{test_id[:6]}",
            },
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["user"]["email"] == test_email

        async with async_session_maker() as db:
            res = await db.execute(select(User).where(User.email == test_email))
            user = res.scalar_one_or_none()
            assert user is not None
            assert user.account_type == "org"
            assert user.is_single_user is False


@pytest.mark.asyncio
async def test_03_invite_sets_org_account_type():
    """3. invite_sets_org_account_type: pre-created invite stubs have account_type='org' and preserve it upon claim."""
    test_id = str(uuid.uuid4())
    invite_email = f"invited_{test_id[:8]}@example.com"

    stub_info = await precreate_user_for_invite(invite_email)
    assert stub_info is not None
    assert stub_info["account_type"] == "org"
    assert stub_info["status"] == "invited"

    async with async_session_maker() as db:
        res = await db.execute(select(User).where(User.id == stub_info["id"]))
        stub_user = res.scalar_one_or_none()
        assert stub_user is not None
        assert stub_user.account_type == "org"
        assert stub_user.status == "invited"

    # Claim invited stub
    new_auth_id = str(uuid.uuid4())
    await claim_invited_stub(old_user_id=stub_info["id"], new_user_id=new_auth_id)

    async with async_session_maker() as db:
        res = await db.execute(select(User).where(User.id == new_auth_id))
        claimed_user = res.scalar_one_or_none()
        assert claimed_user is not None
        assert claimed_user.account_type == "org"
        assert claimed_user.status == "active"


@pytest.mark.asyncio
async def test_04_signin_personal_with_org_account_rejected_403(async_client):
    """4. signin_personal_with_org_account_rejected_403: org account signing in personal mode returns 403 mismatch."""
    test_id = str(uuid.uuid4())
    test_email = f"alice_org_{test_id[:8]}@example.com"

    async with async_session_maker() as db:
        user = User(
            id=test_id,
            email=test_email,
            username=f"alice{test_id[:6]}",
            account_type="org",
            status="active",
            is_single_user=False,
        )
        db.add(user)
        await db.commit()

    # Explicit mode=personal
    resp = await async_client.post(
        "/api/v1/auth/signin",
        json={"identifier": test_email, "password": "AnyPassword123!", "mode": "personal"},
    )
    assert resp.status_code == 403
    data = resp.json()
    assert data["error"] == "account_type_mismatch"
    assert data["hint"] == "use_org_mode"
    assert "organization account" in data["message"]

    # Omitted mode (defaults to personal)
    resp2 = await async_client.post(
        "/api/v1/auth/signin",
        json={"identifier": test_email, "password": "AnyPassword123!"},
    )
    assert resp2.status_code == 403
    assert resp2.json()["error"] == "account_type_mismatch"


@pytest.mark.asyncio
async def test_05_signin_org_with_org_account_allowed(async_client):
    """5. signin_org_with_org_account_allowed: org account signing in org mode is permitted."""
    test_id = str(uuid.uuid4())
    test_email = f"bob_org_{test_id[:8]}@example.com"

    async with async_session_maker() as db:
        user = User(
            id=test_id,
            email=test_email,
            username=f"bob{test_id[:6]}",
            account_type="org",
            status="active",
            is_single_user=False,
        )
        db.add(user)
        await db.commit()

    sb_res = _make_mock_sb_response(test_id, test_email)
    with patch("app.core.security._get_anon_client") as mock_get_client:
        mock_client = MagicMock()
        mock_client.auth.sign_in_with_password.return_value = sb_res
        mock_get_client.return_value = mock_client

        resp = await async_client.post(
            "/api/v1/auth/signin",
            json={"identifier": test_email, "password": "ValidPassword123!", "mode": "org"},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["user"]["email"] == test_email
        assert data["user"]["account_type"] == "org"
        assert "access_token" in data


@pytest.mark.asyncio
async def test_06_signin_org_with_personal_account_allowed(async_client):
    """6. signin_org_with_personal_account_allowed: personal account signing in org mode is allowed."""
    test_id = str(uuid.uuid4())
    test_email = f"carol_pers_{test_id[:8]}@example.com"

    async with async_session_maker() as db:
        user = User(
            id=test_id,
            email=test_email,
            username=f"carol{test_id[:6]}",
            account_type="personal",
            status="active",
            is_single_user=True,
        )
        db.add(user)
        await db.commit()

    sb_res = _make_mock_sb_response(test_id, test_email)
    with patch("app.core.security._get_anon_client") as mock_get_client:
        mock_client = MagicMock()
        mock_client.auth.sign_in_with_password.return_value = sb_res
        mock_get_client.return_value = mock_client

        resp = await async_client.post(
            "/api/v1/auth/signin",
            json={"identifier": test_email, "password": "ValidPassword123!", "mode": "org"},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["user"]["email"] == test_email
        assert data["user"]["account_type"] == "personal"
        assert "access_token" in data


@pytest.mark.asyncio
async def test_07_oauth_callback_personal_with_org_rejected(async_client):
    """7. oauth_callback_personal_with_org_rejected: OAuth callback rejects org account in personal mode."""
    test_id = str(uuid.uuid4())
    test_email = f"dan_org_{test_id[:8]}@example.com"

    async with async_session_maker() as db:
        user = User(
            id=test_id,
            email=test_email,
            username=f"dan{test_id[:6]}",
            account_type="org",
            status="active",
            is_single_user=False,
        )
        db.add(user)
        await db.commit()

    # GET redirect test
    resp_get = await async_client.get(
        f"/api/v1/auth/callback?email={test_email}&mode=personal",
        follow_redirects=False,
    )
    assert resp_get.status_code in (302, 303, 307)
    location = resp_get.headers.get("location", "")
    assert "/login?mode=personal&error=account_type_mismatch" in location

    # POST API test
    resp_post = await async_client.post(
        "/api/v1/auth/callback",
        json={"email": test_email, "mode": "personal"},
    )
    assert resp_post.status_code == 403
    assert resp_post.json()["error"] == "account_type_mismatch"


@pytest.mark.asyncio
async def test_08_duplicate_signup_cross_realm_rejected_409(async_client):
    """8. duplicate_signup_cross_realm_rejected_409: cross-realm duplicate registration returns 409 and creates no extra row."""
    test_id = str(uuid.uuid4())
    org_email = f"shared_org_{test_id[:8]}@example.com"

    async with async_session_maker() as db:
        user = User(
            id=test_id,
            email=org_email,
            username=f"sorg{test_id[:6]}",
            account_type="org",
            status="active",
            is_single_user=False,
        )
        db.add(user)
        await db.commit()

    # Attempt personal signup with existing org email
    resp_signup = await async_client.post(
        "/api/v1/auth/signup",
        json={"email": org_email, "password": "Password123!"},
    )
    assert resp_signup.status_code == 409
    assert resp_signup.json()["error"] == "email_exists"

    # Verify single-identity invariant: exactly one row in DB
    async with async_session_maker() as db:
        rows = (await db.execute(select(User).where(User.email == org_email))).scalars().all()
        assert len(rows) == 1
        assert rows[0].account_type == "org"

    # Attempt org registration with existing personal email
    pers_id = str(uuid.uuid4())
    pers_email = f"shared_pers_{pers_id[:8]}@example.com"
    async with async_session_maker() as db:
        pers_user = User(
            id=pers_id,
            email=pers_email,
            username=f"spers{pers_id[:6]}",
            account_type="personal",
            status="active",
            is_single_user=True,
        )
        db.add(pers_user)
        await db.commit()

    resp_register = await async_client.post(
        "/api/v1/auth/register-org",
        json={"email": pers_email, "password": "Password123!", "org_name": "Conflict Corp"},
    )
    assert resp_register.status_code == 409
    assert resp_register.json()["error"] == "email_exists"

    # Verify single-identity invariant: exactly one row in DB
    async with async_session_maker() as db:
        pers_rows = (await db.execute(select(User).where(User.email == pers_email))).scalars().all()
        assert len(pers_rows) == 1
        assert pers_rows[0].account_type == "personal"
