"""Suite 47 — Single Identity, Atomic Org Signup, and Graceful 409 Invariants.

Verifies the 10 critical invariants of ORG-IDENTITY-FIX:
1. POST /auth/register personal on fresh email -> 200/201, User created, status='active'.
2. POST /auth/register personal duplicate email -> 409 {"error":"email_exists","hint":"sign_in"}.
3. POST /auth/register-org fresh email -> 200/201, atomic User+Org+Member(admin)+Project, returns tokens+memberships, active_organization_id set.
4. POST /auth/register-org duplicate email (exists as personal user) -> 409 {"error":"email_exists","hint":"sign_in_then_create_org"}, ZERO new rows.
5. POST /orgs unauthenticated -> 401 Unauthorized (not 403, not 500).
6. POST /orgs authenticated (valid JWT) -> 201, attaches new org to caller, owner_id=user.id, ZERO new user rows.
7. Invite existing personal email -> pending token invitation created, ZERO new user rows, no direct membership.
8. Invite unknown email -> pending invitation (only the SHA-256 hash stored), NO stub user row.
9. Personal register on invited (stub-less) email -> 200/201, user self-registers normally.
10. Invited user redeems token via POST /invitations/accept -> membership with invited role, invitation accepted; replay -> 409.
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
        # Check 7: Invite existing personal email -> token invitation created,
        # ZERO new user rows, NO org_members row yet, status pending
        # -------------------------------------------------------------------
        from app.db.models import OrgInvitation

        async with _get_admin_session_maker()() as db:
            users_before_7 = (await db.execute(select(func.count(User.id)))).scalar()

        r7 = await ac.post(
            f"/api/v1/orgs/{org_id}/members",
            json={"email": personal_email, "role": "analyst"},
            headers=org_admin_headers,
        )
        d7 = r7.json() if r7.status_code in (200, 201) else {}

        async with _get_admin_session_maker()() as db:
            users_after_7 = (await db.execute(select(func.count(User.id)))).scalar()
            p_user = (await db.execute(select(User).where(User.email == personal_email))).scalar_one()
            p_mem = (await db.execute(
                select(OrgMember).where(OrgMember.organization_id == org_id, OrgMember.user_id == p_user.id)
            )).scalar_one_or_none()
            inv7 = (await db.execute(
                select(OrgInvitation).where(
                    OrgInvitation.organization_id == org_id, OrgInvitation.email == personal_email
                )
            )).scalar_one_or_none()

        runner.assert_true(
            r7.status_code in (200, 201)
            and bool(d7.get("token"))  # raw token returned once
            and users_after_7 == users_before_7
            and p_mem is None  # invitation flow: no direct membership
            and p_user.status == "active"
            and inv7 is not None
            and inv7.status == "pending"
            and inv7.role == "analyst",
            "Check 7: Invite existing personal email -> pending invitation created, ZERO new user rows, no direct membership",
        )

        # -------------------------------------------------------------------
        # Check 8: Invite unknown email -> pending invitation, NO stub user row
        # -------------------------------------------------------------------
        r8 = await ac.post(
            f"/api/v1/orgs/{org_id}/members",
            json={"email": invited_email, "role": "viewer"},
            headers=org_admin_headers,
        )
        d8 = r8.json() if r8.status_code in (200, 201) else {}
        invite_token = d8.get("token")

        async with _get_admin_session_maker()() as db:
            stub_user = (await db.execute(select(User).where(User.email == invited_email))).scalar_one_or_none()
            inv8 = (await db.execute(
                select(OrgInvitation).where(
                    OrgInvitation.organization_id == org_id, OrgInvitation.email == invited_email
                )
            )).scalar_one_or_none()

        runner.assert_true(
            r8.status_code in (200, 201)
            and bool(invite_token)
            and stub_user is None  # stub-user flow replaced: no user row pre-created
            and inv8 is not None
            and inv8.status == "pending"
            and inv8.role == "viewer"
            and len(inv8.token_hash) == 64,  # only the SHA-256 hash is stored
            "Check 8: Invite unknown email -> pending invitation (hash stored), NO stub user row",
        )

        # -------------------------------------------------------------------
        # Check 9: Personal register on invited (stub-less) email -> succeeds normally
        # -------------------------------------------------------------------
        r9 = await ac.post(
            "/api/v1/auth/register",
            json={
                "email": invited_email,
                "password": "Password123!",
                "name": "Invited User Self-Signup",
            },
        )
        runner.assert_true(
            r9.status_code in (200, 201),
            f"Check 9: Personal register on invited email (no stub exists) -> 200/201 (got {r9.status_code})",
        )

        # -------------------------------------------------------------------
        # Check 10: Invited user signs in and redeems the token -> membership
        # created with invited role, invitation consumed
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

        r10 = await ac.post(
            "/api/v1/invitations/accept",
            json={"token": invite_token},
            headers={"Authorization": f"Bearer {invited_token}"},
        )
        d10 = r10.json() if r10.status_code in (200, 201) else {}

        async with _get_admin_session_maker()() as db:
            claimed_user = (await db.execute(select(User).where(User.email == invited_email))).scalar_one_or_none()
            claimed_mem = (await db.execute(
                select(OrgMember).where(OrgMember.organization_id == org_id, OrgMember.user_id == claimed_user.id)
            )).scalar_one_or_none() if claimed_user else None
            inv10 = (await db.execute(
                select(OrgInvitation).where(
                    OrgInvitation.organization_id == org_id, OrgInvitation.email == invited_email
                )
            )).scalar_one_or_none()

        runner.assert_true(
            r10.status_code in (200, 201)
            and d10.get("organization_id") == org_id
            and d10.get("role") == "viewer"
            and claimed_mem is not None
            and claimed_mem.role == "viewer"
            and claimed_user is not None
            and claimed_user.status == "active"
            and inv10 is not None
            and inv10.status == "accepted"
            and inv10.accepted_at is not None,
            "Check 10: Invited user redeems token -> org_members row created with invited role, invitation accepted",
        )

        # Check 10b: the redeemed token is single-use -> replay rejected
        r10b = await ac.post(
            "/api/v1/invitations/accept",
            json={"token": invite_token},
            headers={"Authorization": f"Bearer {invited_token}"},
        )
        runner.assert_true(
            r10b.status_code == 409,
            f"Check 10b: Replay of accepted invitation token -> 409 (got {r10b.status_code})",
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
