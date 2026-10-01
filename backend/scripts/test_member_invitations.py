"""Suite 52 — MEMBER-INVITE-P1: token-based organization invitations.

Verifies the invitation infrastructure that replaces the stub-user flow:
1.  Admin creates invitation -> 201, raw token returned ONCE, row pending
    (only the SHA-256 hash stored), no user row / member row pre-created.
2.  Duplicate pending invitation for the same email -> 409.
3.  Inviting an email that is already a member -> 400.
4.  GET /orgs/{id}/invitations lists invitations, never leaks token/token_hash.
5.  Accept with an unknown token -> 404.
6.  Accept an expired invitation -> 410, row lazily flipped to 'expired'.
7.  Revoke lifecycle: DELETE pending -> revoked; re-revoke -> 409;
    accept revoked -> 410.
8.  Accept with a different email than invited -> 403, invitation stays pending.
9.  Accept success -> org_members row with invited role, invitation consumed
    (status='accepted', accepted_at set), new member visible in members list.
10. Replay of an accepted token -> 409.
11. Security fix: a non-owner admin CANNOT demote another admin -> 403.
12. Owner CAN demote an admin -> 200; self-demotion -> 400; owner's own
    member row immutable -> 400.
"""

import uuid
from datetime import datetime, timedelta, timezone

from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.core.security import CurrentUser, get_current_user
from app.db.models import OrgInvitation, OrgMember, OrgOrganization, User
from app.db.session import async_session_maker
from app.main import app


def _mk_user(tag: str) -> CurrentUser:
    uid = str(uuid.uuid4())
    return CurrentUser(
        id=uid,
        email=f"{tag}-{uid[:8]}@example.com",
        full_name=f"User {tag}",
        username=f"{tag}_{uid[:8]}",
        account_type="user",
    )


def _admin_maker():
    from app.db.admin import _get_admin_session_maker
    return _get_admin_session_maker()


async def _seed_user(user: CurrentUser) -> None:
    async with _admin_maker()() as db:
        db.add(User(
            id=user.id, email=user.email, full_name=user.full_name,
            username=user.username, account_type="user",
        ))
        await db.commit()


async def _seed_member(org_id: str, user_id: str, role: str) -> str:
    async with _admin_maker()() as db:
        member = OrgMember(
            id=str(uuid.uuid4()), organization_id=org_id, user_id=user_id,
            role=role, joined_at=datetime.now(timezone.utc),
        )
        db.add(member)
        await db.commit()
        return member.id


async def run_member_invitation_tests(runner) -> None:
    print("\n[Suite 52] MEMBER-INVITE-P1 — Token-Based Invitations")

    from app.core.config import get_settings
    _saved_org_enabled = get_settings().ORG_ENABLED
    get_settings().ORG_ENABLED = True

    try:
        await _run_body(runner)
    finally:
        get_settings().ORG_ENABLED = _saved_org_enabled
        app.dependency_overrides.pop(get_current_user, None)


async def _run_body(runner) -> None:
    owner = _mk_user("inv-owner")
    admin2 = _mk_user("inv-admin2")
    admin3 = _mk_user("inv-admin3")
    invitee = _mk_user("inv-invitee")
    outsider = _mk_user("inv-outsider")

    for u in (owner, admin2, admin3, invitee, outsider):
        await _seed_user(u)

    app.dependency_overrides[get_current_user] = lambda: owner
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r_org = await client.post("/api/v1/orgs", json={"name": "Invite Test Org"})
        assert r_org.status_code == 201, r_org.text
        org_id = r_org.json()["id"]

        # Seeded members: two extra admins for the demotion-guard checks.
        admin2_member_id = await _seed_member(org_id, admin2.id, "admin")
        admin3_member_id = await _seed_member(org_id, admin3.id, "admin")
        analyst_id_row = await _seed_member(org_id, outsider.id, "analyst")

        invitee_email = invitee.email

        # -----------------------------------------------------------------
        # Check 1: valid invitation -> 201, raw token once, pending, hash-only
        # -----------------------------------------------------------------
        try:
            r1 = await client.post(
                f"/api/v1/orgs/{org_id}/members",
                json={"email": invitee_email, "role": "analyst"},
            )
            d1 = r1.json() if r1.status_code in (200, 201) else {}
            raw_token = d1.get("token", "")

            async with _admin_maker()() as db:
                inv1 = (await db.execute(
                    select(OrgInvitation).where(
                        OrgInvitation.organization_id == org_id,
                        OrgInvitation.email == invitee_email,
                    )
                )).scalar_one_or_none()
                no_stub = (await db.execute(
                    select(User).where(User.email == invitee_email, User.status == "invited")
                )).scalar_one_or_none()
                no_member = (await db.execute(
                    select(OrgMember).where(
                        OrgMember.organization_id == org_id, OrgMember.user_id == invitee.id
                    )
                )).scalar_one_or_none()
                user_rows = (await db.execute(
                    select(User).where(User.email == invitee_email)
                )).scalars().all()

            expires_ok = bool(inv1 and inv1.expires_at)
            runner.assert_true(
                r1.status_code == 201
                and len(raw_token) >= 32
                and inv1 is not None
                and inv1.status == "pending"
                and inv1.role == "analyst"
                and inv1.invited_by == owner.id
                and len(inv1.token_hash) == 64
                and inv1.token_hash != raw_token
                and no_stub is None          # stub-user flow gone: no 'invited' user row
                and no_member is None        # no direct membership
                and len(user_rows) == 1      # invitation created NO user row (only the pre-seeded one)
                and user_rows[0].status == "active",
                "1. create invitation -> 201, raw token once, pending, hash-only, no stub user/member row",
                f"Status: {r1.status_code}, body: {r1.text[:200]}",
            )
        except Exception as exc:
            runner.assert_true(False, "1. create invitation -> 201", str(exc))

        # -----------------------------------------------------------------
        # Check 2: duplicate pending invitation -> 409
        # -----------------------------------------------------------------
        try:
            r2 = await client.post(
                f"/api/v1/orgs/{org_id}/members",
                json={"email": invitee_email, "role": "viewer"},
            )
            runner.assert_true(
                r2.status_code == 409,
                "2. duplicate pending invitation -> 409",
                f"Status: {r2.status_code}, body: {r2.text[:200]}",
            )
        except Exception as exc:
            runner.assert_true(False, "2. duplicate pending invitation -> 409", str(exc))

        # -----------------------------------------------------------------
        # Check 3: inviting an existing member's email -> 400
        # -----------------------------------------------------------------
        try:
            r3 = await client.post(
                f"/api/v1/orgs/{org_id}/members",
                json={"email": outsider.email, "role": "viewer"},
            )
            runner.assert_true(
                r3.status_code == 400,
                "3. invite already-member email -> 400",
                f"Status: {r3.status_code}, body: {r3.text[:200]}",
            )
        except Exception as exc:
            runner.assert_true(False, "3. invite already-member email -> 400", str(exc))

        # -----------------------------------------------------------------
        # Check 4: list invitations -> pending shown, no token leakage
        # -----------------------------------------------------------------
        try:
            r4 = await client.get(f"/api/v1/orgs/{org_id}/invitations")
            rows = r4.json().get("invitations", []) if r4.status_code == 200 else []
            mine = [r for r in rows if r.get("email") == invitee_email]
            leaked = any(("token" in r and r.get("token")) or r.get("token_hash") for r in rows)
            runner.assert_true(
                r4.status_code == 200
                and len(mine) == 1
                and mine[0]["status"] == "pending"
                and not leaked,
                "4. list invitations shows pending row, no token/token_hash leakage",
                f"Status: {r4.status_code}, rows: {rows}",
            )
        except Exception as exc:
            runner.assert_true(False, "4. list invitations", str(exc))

        # -----------------------------------------------------------------
        # Check 5: accept with unknown token -> 404
        # -----------------------------------------------------------------
        try:
            app.dependency_overrides[get_current_user] = lambda: invitee
            r5 = await client.post(
                "/api/v1/invitations/accept",
                json={"token": "not-a-real-token-abcdefabcdef"},
            )
            runner.assert_true(
                r5.status_code == 404,
                "5. accept unknown token -> 404",
                f"Status: {r5.status_code}, body: {r5.text[:200]}",
            )
        except Exception as exc:
            runner.assert_true(False, "5. accept unknown token -> 404", str(exc))
        finally:
            app.dependency_overrides[get_current_user] = lambda: owner

        # -----------------------------------------------------------------
        # Check 6: expired invitation -> 410, lazily marked expired
        # -----------------------------------------------------------------
        try:
            r6a = await client.post(
                f"/api/v1/orgs/{org_id}/members",
                json={"email": f"expired-{uuid.uuid4().hex[:6]}@example.com", "role": "viewer"},
            )
            exp_email = r6a.json()["email"]
            exp_token = r6a.json()["token"]
            async with _admin_maker()() as db:
                inv6 = (await db.execute(
                    select(OrgInvitation).where(
                        OrgInvitation.organization_id == org_id, OrgInvitation.email == exp_email
                    )
                )).scalar_one()
                inv6.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
                await db.commit()

            app.dependency_overrides[get_current_user] = lambda: invitee
            r6b = await client.post("/api/v1/invitations/accept", json={"token": exp_token})
            app.dependency_overrides[get_current_user] = lambda: owner

            async with _admin_maker()() as db:
                inv6b = (await db.execute(
                    select(OrgInvitation).where(OrgInvitation.id == inv6.id)
                )).scalar_one()
            runner.assert_true(
                r6b.status_code == 410 and inv6b.status == "expired",
                "6. accept expired invitation -> 410, row marked expired",
                f"Status: {r6b.status_code}, row status: {inv6b.status}",
            )
        except Exception as exc:
            runner.assert_true(False, "6. expired invitation -> 410", str(exc))

        # -----------------------------------------------------------------
        # Check 7: revoke lifecycle -> DELETE ok, re-revoke 409, accept revoked 410
        # -----------------------------------------------------------------
        try:
            r7a = await client.post(
                f"/api/v1/orgs/{org_id}/members",
                json={"email": f"revoke-{uuid.uuid4().hex[:6]}@example.com", "role": "viewer"},
            )
            rev_email = r7a.json()["email"]
            rev_token = r7a.json()["token"]
            rev_id = r7a.json()["id"]

            r7b = await client.delete(f"/api/v1/orgs/{org_id}/invitations/{rev_id}")
            r7c = await client.delete(f"/api/v1/orgs/{org_id}/invitations/{rev_id}")

            app.dependency_overrides[get_current_user] = lambda: invitee
            r7d = await client.post("/api/v1/invitations/accept", json={"token": rev_token})
            app.dependency_overrides[get_current_user] = lambda: owner

            runner.assert_true(
                r7b.status_code == 200
                and r7c.status_code == 409
                and r7d.status_code == 410,
                "7. revoke lifecycle: DELETE 200, re-revoke 409, accept revoked 410",
                f"delete: {r7b.status_code}, re-delete: {r7c.status_code}, accept: {r7d.status_code}",
            )
        except Exception as exc:
            runner.assert_true(False, "7. revoke lifecycle", str(exc))

        # -----------------------------------------------------------------
        # Check 8: accept with mismatched email -> 403, invitation stays pending
        # -----------------------------------------------------------------
        try:
            app.dependency_overrides[get_current_user] = lambda: outsider
            r8 = await client.post("/api/v1/invitations/accept", json={"token": raw_token})
            app.dependency_overrides[get_current_user] = lambda: owner

            async with _admin_maker()() as db:
                inv8 = (await db.execute(
                    select(OrgInvitation).where(
                        OrgInvitation.organization_id == org_id, OrgInvitation.email == invitee_email
                    )
                )).scalar_one()
            runner.assert_true(
                r8.status_code == 403 and inv8.status == "pending",
                "8. accept with mismatched email -> 403, invitation stays pending",
                f"Status: {r8.status_code}, row status: {inv8.status}",
            )
        except Exception as exc:
            runner.assert_true(False, "8. email mismatch -> 403", str(exc))

        # -----------------------------------------------------------------
        # Check 9: accept success -> membership with invited role, token consumed
        # -----------------------------------------------------------------
        try:
            app.dependency_overrides[get_current_user] = lambda: invitee
            r9 = await client.post("/api/v1/invitations/accept", json={"token": raw_token})
            d9 = r9.json() if r9.status_code in (200, 201) else {}
            app.dependency_overrides[get_current_user] = lambda: owner

            async with _admin_maker()() as db:
                inv9 = (await db.execute(
                    select(OrgInvitation).where(
                        OrgInvitation.organization_id == org_id, OrgInvitation.email == invitee_email
                    )
                )).scalar_one()
                mem9 = (await db.execute(
                    select(OrgMember).where(
                        OrgMember.organization_id == org_id, OrgMember.user_id == invitee.id
                    )
                )).scalar_one_or_none()

            r9c = await client.get(f"/api/v1/orgs/{org_id}/members")
            rows9 = r9c.json().get("members", []) if r9c.status_code == 200 else []
            invitee_listed = any(m.get("user_id") == invitee.id and m.get("role") == "analyst" for m in rows9)

            runner.assert_true(
                r9.status_code == 200
                and d9.get("organization_id") == org_id
                and d9.get("role") == "analyst"
                and inv9.status == "accepted"
                and inv9.accepted_at is not None
                and mem9 is not None
                and mem9.role == "analyst"
                and invitee_listed,
                "9. accept success -> member row (invited role), invitation accepted, member listed",
                f"Status: {r9.status_code}, body: {r9.text[:200]}, inv: {inv9.status}, listed: {invitee_listed}",
            )
        except Exception as exc:
            runner.assert_true(False, "9. accept success", str(exc))

        # -----------------------------------------------------------------
        # Check 10: replay accepted token -> 409
        # -----------------------------------------------------------------
        try:
            app.dependency_overrides[get_current_user] = lambda: invitee
            r10 = await client.post("/api/v1/invitations/accept", json={"token": raw_token})
            runner.assert_true(
                r10.status_code == 409,
                "10. replay accepted token -> 409",
                f"Status: {r10.status_code}, body: {r10.text[:200]}",
            )
        except Exception as exc:
            runner.assert_true(False, "10. replay accepted token -> 409", str(exc))
        finally:
            app.dependency_overrides[get_current_user] = lambda: admin2

        # -----------------------------------------------------------------
        # Check 11: non-owner admin demoting another admin -> 403
        # -----------------------------------------------------------------
        try:
            r11 = await client.patch(
                f"/api/v1/orgs/{org_id}/members/{admin3_member_id}",
                json={"role": "analyst"},
            )
            runner.assert_true(
                r11.status_code == 403,
                "11. non-owner admin demotes another admin -> 403",
                f"Status: {r11.status_code}, body: {r11.text[:200]}",
            )
        except Exception as exc:
            runner.assert_true(False, "11. non-owner admin demotion -> 403", str(exc))

        # -----------------------------------------------------------------
        # Check 11b: admin self-demotion -> 400
        # -----------------------------------------------------------------
        try:
            r11b = await client.patch(
                f"/api/v1/orgs/{org_id}/members/{admin2_member_id}",
                json={"role": "analyst"},
            )
            runner.assert_true(
                r11b.status_code == 400,
                "11b. admin self-demotion -> 400",
                f"Status: {r11b.status_code}, body: {r11b.text[:200]}",
            )
        except Exception as exc:
            runner.assert_true(False, "11b. admin self-demotion -> 400", str(exc))

        # -----------------------------------------------------------------
        # Check 11c: owner's own member row is immutable -> 400
        # -----------------------------------------------------------------
        try:
            async with _admin_maker()() as db:
                owner_member_id = (await db.execute(
                    select(OrgMember.id).where(
                        OrgMember.organization_id == org_id, OrgMember.user_id == owner.id
                    )
                )).scalar_one_or_none() or "nonexistent-owner-row"
            r11c = await client.patch(
                f"/api/v1/orgs/{org_id}/members/{owner_member_id}",
                json={"role": "viewer"},
            )
            runner.assert_true(
                r11c.status_code == 400,
                "11c. changing the organization owner's role -> 400",
                f"Status: {r11c.status_code}, body: {r11c.text[:200]}",
            )
        except Exception as exc:
            runner.assert_true(False, "11c. owner role immutable -> 400", str(exc))

        # -----------------------------------------------------------------
        # Check 12: owner CAN demote an admin -> 200
        # -----------------------------------------------------------------
        try:
            app.dependency_overrides[get_current_user] = lambda: owner
            r12 = await client.patch(
                f"/api/v1/orgs/{org_id}/members/{admin3_member_id}",
                json={"role": "analyst"},
            )
            runner.assert_true(
                r12.status_code == 200 and r12.json().get("role") == "analyst",
                "12. owner demotes an admin -> 200",
                f"Status: {r12.status_code}, body: {r12.text[:200]}",
            )
        except Exception as exc:
            runner.assert_true(False, "12. owner demotes admin -> 200", str(exc))
        finally:
            app.dependency_overrides[get_current_user] = lambda: owner

        # -----------------------------------------------------------------
        # Check 12b: non-admin (analyst) cannot create invitations -> 403
        # -----------------------------------------------------------------
        try:
            app.dependency_overrides[get_current_user] = lambda: outsider
            r12b = await client.post(
                f"/api/v1/orgs/{org_id}/members",
                json={"email": f"nope-{uuid.uuid4().hex[:6]}@example.com", "role": "viewer"},
            )
            runner.assert_true(
                r12b.status_code == 403,
                "12b. analyst (non-admin) create invitation -> 403",
                f"Status: {r12b.status_code}, body: {r12b.text[:200]}",
            )
        except Exception as exc:
            runner.assert_true(False, "12b. non-admin invitation -> 403", str(exc))
        finally:
            app.dependency_overrides.pop(get_current_user, None)


if __name__ == "__main__":
    import asyncio
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
    asyncio.run(run_member_invitation_tests(r))
    sys.exit(r.report())
