"""Suite 47 — Single Identity, Atomic Org Signup, and Graceful 409 Invariants.

Verifies the 10 critical invariants of ORG-IDENTITY-FIX:
1. POST /auth/register personal on fresh email -> 200/201, User created, status='active'.
2. POST /auth/register personal duplicate email -> 409 {"error":"email_exists","hint":"sign_in"}.
3. POST /auth/register-org fresh email -> 200/201, atomic User+Org+Member(admin)+Project, returns tokens+memberships, active_organization_id set.
4. POST /auth/register-org duplicate email (exists as personal user) -> 409 {"error":"email_exists","hint":"sign_in_then_create_org"}, ZERO new rows.
5. POST /orgs unauthenticated -> 401 Unauthorized (not 403, not 500).
6. POST /orgs authenticated (valid JWT) -> 201, attaches new org to caller, owner_id=user.id, ZERO new user rows.
7. Invite member with existing personal email -> OrgMember created pointing to existing user, ZERO new user rows, status untouched.
8. Invite member with unknown email -> stub user created status='invited', OrgMember attached to stub.
9. Personal register on invited stub email -> 409 {"error":"email_exists","hint":"check_invite"}.
10. First login on invited stub email claims row -> status becomes 'active', OrgMember intact, user logged in.
"""

import asyncio
from types import SimpleNamespace
from typing import Any
import uuid

from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from app.core.config import get_settings
from app.db.admin import _get_admin_session_maker
from app.db.models import OrgMember, OrgOrganization, OrgProject, User
from app.main import app


class _FakeAuth:
    def __init__(self) -> None:
        self.identities: dict[str, dict[str, Any]] = {}
        self.tokens: dict[str, str] = {}  # token -> user_id

    def sign_up(self, payload: dict[str, Any]) -> Any:
        email = payload["email"].lower()
        if email in self.identities:
            raise RuntimeError("User already registered")
        user_id = f"sb-{uuid.uuid4().hex[:12]}"
        self.identities[email] = {
            "id": user_id,
            "email": email,
            "password": payload["password"],
            "user_metadata": payload.get("options", {}).get("data", {}),
            "email_confirmed_at": None,
        }
        token = f"sb-token-{user_id}"
        self.tokens[token] = user_id
        session = SimpleNamespace(
            access_token=token,
            refresh_token=f"sb-refresh-{user_id}",
            expires_in=3600,
            token_type="bearer",
            user=self._user(email),
        )
        return SimpleNamespace(user=self._user(email), session=session)

    def sign_in_with_password(self, payload: dict[str, Any]) -> Any:
        email = payload["email"].lower()
        identity = self.identities.get(email)
        if identity is None or identity["password"] != payload["password"]:
            raise RuntimeError("Invalid login credentials")
        user_id = identity["id"]
        token = f"sb-token-{user_id}"
        self.tokens[token] = user_id
        session = SimpleNamespace(
            access_token=token,
            refresh_token=f"sb-refresh-{user_id}",
            expires_in=3600,
            token_type="bearer",
            user=self._user(email),
        )
        return SimpleNamespace(user=self._user(email), session=session)

    def get_user(self, token: str) -> Any:
        if token in self.tokens:
            user_id = self.tokens[token]
            for identity in self.identities.values():
                if identity["id"] == user_id:
                    return SimpleNamespace(
                        user=SimpleNamespace(
                            id=user_id,
                            email=identity["email"],
                            user_metadata=identity.get("user_metadata", {}),
                        )
                    )
        if token.startswith("sb-token-"):
            user_id = token.replace("sb-token-", "")
            for identity in self.identities.values():
                if identity["id"] == user_id:
                    return SimpleNamespace(
                        user=SimpleNamespace(
                            id=user_id,
                            email=identity["email"],
                            user_metadata=identity.get("user_metadata", {}),
                        )
                    )
        raise RuntimeError("Invalid token")

    def _user(self, email: str) -> Any:
        identity = self.identities[email]
        return SimpleNamespace(
            id=identity["id"],
            email=identity["email"],
            user_metadata=identity["user_metadata"],
        )


def _install_fake_supabase() -> _FakeAuth:
    fake = _FakeAuth()
    client = SimpleNamespace(auth=fake)
    import app.core.security as sec
    sec._get_anon_client = lambda: client
    return fake


async def run_org_identity_tests(runner) -> None:
    print("\n[Suite 47] ORG-IDENTITY-FIX — Single Identity, Atomic Signup, and Graceful 409 UX")

    saved_org_enabled = get_settings().ORG_ENABLED
    get_settings().ORG_ENABLED = True

    try:
        await _run_org_identity_body(runner)
    finally:
        get_settings().ORG_ENABLED = saved_org_enabled


async def _run_org_identity_body(runner) -> None:
    fake_auth = _install_fake_supabase()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        suffix = uuid.uuid4().hex[:6]
        personal_email = f"personal-{suffix}@test.local"
        org_email = f"orgadmin-{suffix}@test.local"
        invited_email = f"invited-{suffix}@test.local"

        # -------------------------------------------------------------------
        # Check 1: POST /auth/register personal on fresh email -> 200/201, User created, status='active'
        # -------------------------------------------------------------------
        r1 = await ac.post(
            "/api/v1/auth/register",
            json={
                "email": personal_email,
                "password": "Password123!",
                "name": "Personal User",
            },
        )
        d1 = r1.json() if r1.status_code in (200, 201) else {}
        async with _get_admin_session_maker()() as db:
            u1_row = (await db.execute(select(User).where(User.email == personal_email))).scalar_one_or_none()

        runner.assert_true(
            r1.status_code in (200, 201)
            and d1.get("user", {}).get("status") == "active"
            and u1_row is not None
            and u1_row.status == "active",
            "Check 1: POST /auth/register personal on fresh email -> 200/201, User created, status='active'",
        )

        # -------------------------------------------------------------------
        # Check 2: POST /auth/register personal duplicate email -> 409 {"error":"email_exists","hint":"sign_in"}
        # -------------------------------------------------------------------
        r2 = await ac.post(
            "/api/v1/auth/register",
            json={
                "email": personal_email,
                "password": "Password123!",
                "name": "Personal User Duplicate",
            },
        )
        d2 = r2.json() if r2.status_code == 409 else {}
        runner.assert_true(
            r2.status_code == 409
            and d2.get("error") == "email_exists"
            and d2.get("hint") == "sign_in",
            "Check 2: POST /auth/register personal duplicate email -> 409 {\"error\":\"email_exists\",\"hint\":\"sign_in\"}",
        )

        # -------------------------------------------------------------------
        # Check 3: POST /auth/register-org fresh email -> 200/201 atomic User+Org+Member(admin)+Project
        # -------------------------------------------------------------------
        r3 = await ac.post(
            "/api/v1/auth/register-org",
            json={
                "email": org_email,
                "password": "Password123!",
                "name": "Org Admin User",
                "org_name": f"Enterprise SOC {suffix}",
            },
        )
        d3 = r3.json() if r3.status_code in (200, 201) else {}
        org_id = d3.get("organization", {}).get("id")
        token_org = d3.get("access_token")
        memberships = d3.get("memberships", [])

        async with _get_admin_session_maker()() as db:
            org_row = (await db.execute(select(OrgOrganization).where(OrgOrganization.id == org_id))).scalar_one_or_none() if org_id else None
            mem_row = (await db.execute(select(OrgMember).where(OrgMember.organization_id == org_id))).scalar_one_or_none() if org_id else None
            proj_row = (await db.execute(select(OrgProject).where(OrgProject.organization_id == org_id))).scalar_one_or_none() if org_id else None

        runner.assert_true(
            r3.status_code in (200, 201)
            and bool(org_id and token_org and len(memberships) >= 1)
            and d3.get("user", {}).get("active_organization_id") == org_id
            and org_row is not None
            and mem_row is not None
            and proj_row is not None
            and mem_row.role == "admin",
            "Check 3: POST /auth/register-org fresh email -> 200/201, atomic User+Org+Member(admin)+Project, returns tokens+memberships, active_organization_id set",
        )

        # -------------------------------------------------------------------
        # Check 4: POST /auth/register-org duplicate email -> 409 hint='sign_in_then_create_org', ZERO new rows
        # -------------------------------------------------------------------
        async with _get_admin_session_maker()() as db:
            users_before = (await db.execute(select(func.count(User.id)))).scalar()
            orgs_before = (await db.execute(select(func.count(OrgOrganization.id)))).scalar()

        r4 = await ac.post(
            "/api/v1/auth/register-org",
            json={
                "email": personal_email,  # Already exists as personal user
                "password": "Password123!",
                "name": "Duplicate Personal",
                "org_name": "Should Not Create Org",
            },
        )
        d4 = r4.json() if r4.status_code == 409 else {}

        async with _get_admin_session_maker()() as db:
            users_after = (await db.execute(select(func.count(User.id)))).scalar()
            orgs_after = (await db.execute(select(func.count(OrgOrganization.id)))).scalar()

        runner.assert_true(
            r4.status_code == 409
            and d4.get("error") == "email_exists"
            and d4.get("hint") == "sign_in_then_create_org"
            and users_after == users_before
            and orgs_after == orgs_before,
            "Check 4: POST /auth/register-org duplicate email (exists as personal user) -> 409 {\"error\":\"email_exists\",\"hint\":\"sign_in_then_create_org\"}, ZERO new rows",
        )

        # -------------------------------------------------------------------
        # Check 5: POST /orgs unauthenticated -> 401 Unauthorized (not 403, not 500)
        # -------------------------------------------------------------------
        r5 = await ac.post(
            "/api/v1/orgs",
            json={"name": "Unauthenticated Org"},
        )
        runner.assert_true(
            r5.status_code == 401 and r5.json().get("error") == "unauthorized",
            "Check 5: POST /orgs unauthenticated -> 401 Unauthorized (not 403, not 500)",
        )

        # -------------------------------------------------------------------
        # Check 6: POST /orgs authenticated (valid JWT) -> 201, attaches new org to caller, ZERO new user rows
        # -------------------------------------------------------------------
        async with _get_admin_session_maker()() as db:
            users_before_6 = (await db.execute(select(func.count(User.id)))).scalar()

        org_admin_headers = {"Authorization": f"Bearer {token_org}"}
        r6 = await ac.post(
            "/api/v1/orgs",
            json={"name": f"Second Org {suffix}"},
            headers=org_admin_headers,
        )
        d6 = r6.json() if r6.status_code == 201 else {}
        second_org_id = d6.get("id")

        async with _get_admin_session_maker()() as db:
            users_after_6 = (await db.execute(select(func.count(User.id)))).scalar()
            second_org = (await db.execute(select(OrgOrganization).where(OrgOrganization.id == second_org_id))).scalar_one_or_none() if second_org_id else None

        runner.assert_true(
            r6.status_code == 201
            and users_after_6 == users_before_6
            and second_org is not None
            and second_org.owner_id == d3["user"]["id"],
            "Check 6: POST /orgs authenticated (valid JWT) -> 201, attaches new org to caller, owner_id=user.id, ZERO new user rows",
        )

        # -------------------------------------------------------------------
        # Check 7: Invite member with existing personal email -> OrgMember created, ZERO new user rows, status untouched
        # -------------------------------------------------------------------
        async with _get_admin_session_maker()() as db:
            users_before_7 = (await db.execute(select(func.count(User.id)))).scalar()

        r7 = await ac.post(
            f"/api/v1/orgs/{org_id}/members",
            json={"email": personal_email, "role": "analyst"},
            headers=org_admin_headers,
        )

        async with _get_admin_session_maker()() as db:
            users_after_7 = (await db.execute(select(func.count(User.id)))).scalar()
            p_user = (await db.execute(select(User).where(User.email == personal_email))).scalar_one()
            p_mem = (await db.execute(
                select(OrgMember).where(OrgMember.organization_id == org_id, OrgMember.user_id == p_user.id)
            )).scalar_one_or_none()

        runner.assert_true(
            r7.status_code in (200, 201)
            and users_after_7 == users_before_7
            and p_mem is not None
            and p_mem.role == "analyst"
            and p_user.status == "active",
            "Check 7: Invite member with existing personal email -> OrgMember created pointing to existing user, ZERO new user rows, status untouched",
        )

        # -------------------------------------------------------------------
        # Check 8: Invite member with unknown email -> stub user created status='invited', OrgMember attached
        # -------------------------------------------------------------------
        r8 = await ac.post(
            f"/api/v1/orgs/{org_id}/members",
            json={"email": invited_email, "role": "viewer"},
            headers=org_admin_headers,
        )

        async with _get_admin_session_maker()() as db:
            stub_user = (await db.execute(select(User).where(User.email == invited_email))).scalar_one_or_none()
            stub_mem = (await db.execute(
                select(OrgMember).where(OrgMember.organization_id == org_id, OrgMember.user_id == stub_user.id)
            )).scalar_one_or_none() if stub_user else None

        runner.assert_true(
            r8.status_code in (200, 201)
            and stub_user is not None
            and stub_user.status == "invited"
            and stub_mem is not None
            and stub_mem.role == "viewer",
            "Check 8: Invite member with unknown email -> stub user created status='invited', OrgMember attached to stub",
        )

        # -------------------------------------------------------------------
        # Check 9: Personal register on invited stub email -> 409 hint='check_invite'
        # -------------------------------------------------------------------
        r9 = await ac.post(
            "/api/v1/auth/register",
            json={
                "email": invited_email,
                "password": "Password123!",
                "name": "Invited Claim Attempt",
            },
        )
        d9 = r9.json() if r9.status_code == 409 else {}
        runner.assert_true(
            r9.status_code == 409
            and d9.get("error") == "email_exists"
            and d9.get("hint") == "check_invite",
            "Check 9: Personal register on invited stub email -> 409 {\"error\":\"email_exists\",\"hint\":\"check_invite\"}",
        )

        # -------------------------------------------------------------------
        # Check 10: First login on invited stub email claims row -> status='active', OrgMember intact
        # -------------------------------------------------------------------
        fake_user_id = f"sb-invited-{suffix}"
        fake_auth.identities[invited_email] = {
            "id": fake_user_id,
            "email": invited_email,
            "password": "InvitedSecret123!",
            "user_metadata": {"full_name": "Invited User Completed"},
            "email_confirmed_at": None,
        }
        invited_token = f"sb-token-{fake_user_id}"
        fake_auth.tokens[invited_token] = fake_user_id

        r10 = await ac.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {invited_token}"},
        )
        d10 = r10.json() if r10.status_code == 200 else {}

        async with _get_admin_session_maker()() as db:
            claimed_user = (await db.execute(select(User).where(User.email == invited_email))).scalar_one_or_none()
            claimed_mem = (await db.execute(
                select(OrgMember).where(OrgMember.organization_id == org_id, OrgMember.user_id == claimed_user.id)
            )).scalar_one_or_none() if claimed_user else None

        runner.assert_true(
            r10.status_code == 200
            and len(d10.get("memberships", [])) >= 1
            and claimed_user is not None
            and claimed_user.status == "active"
            and claimed_mem is not None
            and claimed_mem.role == "viewer",
            "Check 10: First login on invited stub email claims row -> status becomes 'active', OrgMember intact, user logged in",
        )


if __name__ == "__main__":
    import sys

    class StandaloneRunner:
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
            print("\n" + "=" * 60)
            print(f"TEST RESULTS: {self.passed}/{total} passed")
            return 0 if self.failed == 0 else 1

    r = StandaloneRunner()
    asyncio.run(run_org_identity_tests(r))
    sys.exit(r.report())
