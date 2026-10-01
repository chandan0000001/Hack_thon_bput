"""Suite 53 — MEMBER-INVITE-P3: invitation email service + integration.

Verifies:
1. Config: SMTP_*/FROM_EMAIL/FRONTEND_URL settings exist and .env.example
   documents them.
2. Template: HTML body carries the subject phrase, org/role, the
   "Accept Invitation" button linking to the accept_url, the plain link, and
   the 7-day expiry footer; the text alternative mirrors it.
3. Dev mode: with SMTP_HOST empty, send_invitation_email sends nothing, logs
   the loud "EMAIL NOT SENT (SMTP not configured)" warning with the accept
   link, and returns {"sent": False}.
4. SMTP path: with SMTP_HOST set (fake smtplib.SMTP injected), the message is
   built with the right Subject/From/To and delivered; login honored.
5. create_invitation wiring: the sender is called with the invitee email,
   org name, role, and accept_url = FRONTEND_URL + /auth/accept-invite?token=
   {raw_token}; its status lands in the POST /members response (email_sent).
6. No rollback: an email-step failure leaves the invitation created (201) and
   reports email_sent=False with a note.
"""

import logging
import uuid
from email import message_from_string

from httpx import ASGITransport, AsyncClient

from app.core.config import get_settings
from app.core.security import CurrentUser, get_current_user
from app.main import app
from app.services import email_service


class _FakeSMTP:
    """Captures SMTP traffic without touching the network."""

    instances: list["_FakeSMTP"] = []

    def __init__(self, host: str, port: int, timeout: float = 0) -> None:
        self.host, self.port = host, port
        self.logged_in: tuple[str, str] | None = None
        self.sent: list[tuple[str, list[str], str]] = []
        _FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        pass

    def starttls(self) -> None:
        pass

    def login(self, user: str, password: str) -> None:
        self.logged_in = (user, password)

    def sendmail(self, from_addr: str, to_addrs: list[str], body: str) -> None:
        self.sent.append((from_addr, to_addrs, body))


class _CapturingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def _mk_user(tag: str) -> CurrentUser:
    uid = str(uuid.uuid4())
    return CurrentUser(
        id=uid,
        email=f"{tag}-{uid[:8]}@example.com",
        full_name=f"User {tag}",
        username=f"{tag}_{uid[:8]}",
        account_type="user",
    )


async def run_invite_email_tests(runner) -> None:
    print("\n[Suite 53] MEMBER-INVITE-P3 — Invitation Email Service")

    settings = get_settings()
    saved = {k: getattr(settings, k) for k in
             ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "FROM_EMAIL", "FRONTEND_URL")}
    try:
        await _run_body(runner, settings, saved)
    finally:
        for k, v in saved.items():
            setattr(settings, k, v)


async def _run_body(runner, settings, saved) -> None:
    # ---------------------------------------------------------------------
    # Check 1: config surface exists (config.py fields + .env.example docs)
    # ---------------------------------------------------------------------
    from pathlib import Path

    env_example = Path(__file__).resolve().parents[1] / ".env.example"
    env_text = env_example.read_text(encoding="utf-8") if env_example.exists() else ""
    runner.assert_true(
        all(hasattr(settings, k) for k in
            ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "FROM_EMAIL", "FRONTEND_URL"))
        and all(f"{k}=" in env_text for k in
                ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "FROM_EMAIL", "FRONTEND_URL"))
        and "Confirm email" in env_text,  # E3: Supabase-side toggle documented
        "1. SMTP_*/FROM_EMAIL/FRONTEND_URL config fields + .env.example docs (incl. Supabase confirm-email note)",
    )

    # ---------------------------------------------------------------------
    # Check 2: HTML/text template content
    # ---------------------------------------------------------------------
    accept_url = "http://localhost:5173/auth/accept-invite?token=tok-123"
    html = email_service._render_html("Acme SOC", "analyst", accept_url)
    text = email_service._render_text("Acme SOC", "analyst", accept_url)
    runner.assert_true(
        "Acme SOC" in html and "analyst" in html
        and 'href="http://localhost:5173/auth/accept-invite?token=tok-123"' in html
        and "Accept Invitation" in html
        and "This invitation expires in 7 days." in html
        and "accept-invite?token=tok-123" in text
        and "expires in 7 days" in text,
        "2. template: org/role, Accept Invitation button + plain link, 7-day expiry footer",
    )

    # ---------------------------------------------------------------------
    # Check 3: dev mode (SMTP_HOST empty) -> loud warning, nothing sent
    # ---------------------------------------------------------------------
    try:
        settings.SMTP_HOST = ""
        handler = _CapturingHandler()
        email_service.logger.addHandler(handler)
        email_service.logger.setLevel(logging.WARNING)
        status = await email_service.send_invitation_email(
            "dev@example.com", "Dev Org", "viewer", accept_url
        )
        warning_text = " ".join(r.getMessage() for r in handler.records if r.levelno >= logging.WARNING)
        runner.assert_true(
            status == {"sent": False, "reason": "SMTP not configured (dev mode) — invitation link logged"}
            and _FakeSMTP.instances == []  # no SMTP object ever constructed
            and "EMAIL NOT SENT (SMTP not configured)" in warning_text
            and accept_url in warning_text,
            "3. dev mode: no SMTP touched, EMAIL NOT SENT warning carries the accept link",
            f"status={status}, warnings={warning_text[:200]}",
        )
    except Exception as exc:
        runner.assert_true(False, "3. dev mode warning", str(exc))
    finally:
        for h in list(email_service.logger.handlers):
            if isinstance(h, _CapturingHandler):
                email_service.logger.removeHandler(h)

    # ---------------------------------------------------------------------
    # Check 4: SMTP path via injected fake smtplib.SMTP
    # ---------------------------------------------------------------------
    try:
        settings.SMTP_HOST = "smtp.test.local"
        settings.SMTP_PORT = 2525
        settings.SMTP_USER = "mailer"
        settings.SMTP_PASS = "secret"
        settings.FROM_EMAIL = "invites@cyberguard.test"
        _FakeSMTP.instances.clear()
        real_smtp = email_service.smtplib.SMTP
        email_service.smtplib.SMTP = _FakeSMTP
        try:
            status = await email_service.send_invitation_email(
                "invitee@example.com", "Acme SOC", "analyst", accept_url
            )
            fake = _FakeSMTP.instances[-1]
            delivered = fake.sent[-1] if fake.sent else ("", [], "")
            parsed = message_from_string(delivered[2])
            subject = parsed.get("Subject", "")
            has_html_part = any(part.get_content_type() == "text/html" for part in parsed.walk())
            runner.assert_true(
                status == {"sent": True}
                and fake.host == "smtp.test.local" and fake.port == 2525
                and fake.logged_in == ("mailer", "secret")
                and delivered[0] == "invites@cyberguard.test"
                and delivered[1] == ["invitee@example.com"]
                and subject == "You're invited to join Acme SOC on CyberGuard"
                and has_html_part,
                "4. SMTP path: correct host/port/login/From/To/Subject, html part present",
                f"status={status}, sent={bool(fake.sent)}, subject={subject!r}",
            )
        finally:
            email_service.smtplib.SMTP = real_smtp
    except Exception as exc:
        runner.assert_true(False, "4. SMTP path", str(exc))

    # ---------------------------------------------------------------------
    # Checks 5+6: API wiring through POST /orgs/{id}/members
    # ---------------------------------------------------------------------
    owner = _mk_user("email-owner")
    from app.db.admin import _get_admin_session_maker

    async with _get_admin_session_maker()() as db:
        from app.db.models import User as UserModel

        db.add(UserModel(
            id=owner.id, email=owner.email, full_name=owner.full_name,
            username=owner.username, account_type="user",
        ))
        await db.commit()

    settings.SMTP_HOST = ""  # default dev mode for the API flow
    settings.FRONTEND_URL = "http://localhost:5173"
    app.dependency_overrides[get_current_user] = lambda: owner
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            r_org = await client.post("/api/v1/orgs", json={"name": "Email Test Org"})
            assert r_org.status_code == 201, r_org.text
            org_id = r_org.json()["id"]

            # Check 5: sender called with the right args; accept_url embeds the raw token
            captured: dict = {}
            called = {"n": 0}

            async def fake_sender(to_email, org_name, role, accept_url):
                called["n"] += 1
                captured.update({
                    "to_email": to_email, "org_name": org_name,
                    "role": role, "accept_url": accept_url,
                })
                return {"sent": False, "reason": "SMTP not configured (dev mode) — invitation link logged"}

            real_sender = email_service.send_invitation_email
            email_service.send_invitation_email = fake_sender
            try:
                r5 = await client.post(
                    f"/api/v1/orgs/{org_id}/members",
                    json={"email": f"wire-{uuid.uuid4().hex[:6]}@example.com", "role": "analyst"},
                )
                d5 = r5.json() if r5.status_code == 201 else {}
                url_ok = (
                    captured.get("accept_url", "").startswith("http://localhost:5173/auth/accept-invite?token=")
                    and captured.get("accept_url", "").endswith(d5.get("token", "nomatch"))
                    and len(d5.get("token", "")) >= 32
                )
                runner.assert_true(
                    r5.status_code == 201
                    and called["n"] == 1
                    and captured.get("org_name") == "Email Test Org"
                    and captured.get("role") == "analyst"
                    and url_ok
                    and d5.get("email_sent") is False
                    and "SMTP not configured" in d5.get("email_note", ""),
                    "5. create_invitation emails with FRONTEND_URL accept link; status in response",
                    f"status={r5.status_code}, captured={captured}, body={r5.text[:200]}",
                )
            finally:
                email_service.send_invitation_email = real_sender

            # Check 6: sender raising must NOT roll the invitation back
            invitee_email = f"rollback-{uuid.uuid4().hex[:6]}@example.com"

            async def exploding_sender(*args, **kwargs):
                raise RuntimeError("SMTP server on fire")

            email_service.send_invitation_email = exploding_sender
            try:
                r6 = await client.post(
                    f"/api/v1/orgs/{org_id}/members",
                    json={"email": invitee_email, "role": "viewer"},
                )
                from sqlalchemy import select

                from app.db.models import OrgInvitation

                async with _get_admin_session_maker()() as db:
                    inv = (await db.execute(
                        select(OrgInvitation).where(
                            OrgInvitation.organization_id == org_id,
                            OrgInvitation.email == invitee_email,
                        )
                    )).scalar_one_or_none()
                runner.assert_true(
                    r6.status_code == 201
                    and inv is not None
                    and inv.status == "pending"
                    and r6.json().get("email_sent") is False
                    and "email step failed" in r6.json().get("email_note", ""),
                    "6. email failure does not roll back the invitation (201, row pending, note set)",
                    f"status={r6.status_code}, inv={bool(inv)}, body={r6.text[:200]}",
                )
            finally:
                email_service.send_invitation_email = real_sender
    except Exception as exc:
        runner.assert_true(False, "5/6. API wiring", str(exc))
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
    asyncio.run(run_invite_email_tests(r))
    sys.exit(r.report())
