"""Invitation email delivery (MEMBER-INVITE-P3).

Sends org-invitation emails over SMTP (stdlib ``smtplib``, run in a worker
thread so the event loop is never blocked). When SMTP is not configured —
the default for development — the rendered email is logged to the console
with a loud ``EMAIL NOT SENT (SMTP not configured)`` banner so the developer
can grab the accept link directly.

This is strictly separate from the Phase-7 alert notification pipeline
(``notification_service``): invitation mail has its own SMTP_* settings and
no DB-log fallback (a failed send is surfaced to the caller as
``{"sent": False, ...}`` instead).
"""

import asyncio
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.core.config import get_settings

logger = logging.getLogger("cyberguard.invitations.email")

# Expiry copy must stay in sync with invitation_service.INVITATION_TTL_DAYS.
EXPIRY_DAYS = 7


def _render_html(org_name: str, role: str, accept_url: str) -> str:
    """Dark-theme-friendly HTML body (inline CSS only — mail clients strip <style>)."""
    return f"""\
<!DOCTYPE html>
<html>
  <body style="margin:0;padding:0;background-color:#09090b;font-family:'Segoe UI',Arial,sans-serif;">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#09090b;padding:32px 16px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background-color:#18181b;border:1px solid #27272a;border-radius:12px;">
            <tr>
              <td style="padding:32px 32px 8px 32px;">
                <p style="margin:0;font-size:12px;font-weight:bold;letter-spacing:2px;color:#ef4444;text-transform:uppercase;">CyberGuard</p>
                <h1 style="margin:12px 0 0 0;font-size:22px;line-height:1.3;color:#fafafa;">
                  You&rsquo;re invited to join {org_name} on CyberGuard
                </h1>
              </td>
            </tr>
            <tr>
              <td style="padding:12px 32px 4px 32px;">
                <p style="margin:0;font-size:14px;line-height:1.6;color:#a1a1aa;">
                  You&rsquo;ve been invited to join <strong style="color:#e4e4e7;">{org_name}</strong>
                  as a <strong style="color:#e4e4e7;">{role}</strong>. Accept the invitation to
                  start collaborating in your organization&rsquo;s security workspace.
                </p>
              </td>
            </tr>
            <tr>
              <td align="center" style="padding:28px 32px;">
                <a href="{accept_url}"
                   style="display:inline-block;background-color:#dc2626;color:#ffffff;text-decoration:none;
                          font-size:14px;font-weight:bold;padding:12px 28px;border-radius:8px;">
                  Accept Invitation
                </a>
              </td>
            </tr>
            <tr>
              <td style="padding:0 32px 8px 32px;">
                <p style="margin:0;font-size:11px;line-height:1.6;color:#71717a;word-break:break-all;">
                  If the button doesn&rsquo;t work, paste this link into your browser:<br/>
                  <a href="{accept_url}" style="color:#ef4444;">{accept_url}</a>
                </p>
              </td>
            </tr>
            <tr>
              <td style="padding:16px 32px 28px 32px;border-top:1px solid #27272a;">
                <p style="margin:0;font-size:11px;color:#71717a;">
                  This invitation expires in {EXPIRY_DAYS} days.
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
"""


def _render_text(org_name: str, role: str, accept_url: str) -> str:
    return (
        f"You're invited to join {org_name} on CyberGuard\n\n"
        f"You've been invited to join {org_name} as a {role}.\n"
        f"Accept your invitation: {accept_url}\n\n"
        f"This invitation expires in {EXPIRY_DAYS} days.\n"
    )


def _send_sync(to_email: str, org_name: str, role: str, accept_url: str) -> None:
    """Blocking SMTP delivery (runs inside asyncio.to_thread)."""
    settings = get_settings()
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"You're invited to join {org_name} on CyberGuard"
    msg["From"] = settings.FROM_EMAIL
    msg["To"] = to_email
    msg.attach(MIMEText(_render_text(org_name, role, accept_url), "plain", "utf-8"))
    msg.attach(MIMEText(_render_html(org_name, role, accept_url), "html", "utf-8"))

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
        if settings.SMTP_USER:
            try:
                server.starttls()
            except smtplib.SMTPException:
                pass  # server may already be TLS (e.g. port 465 wrapper)
            server.login(settings.SMTP_USER, settings.SMTP_PASS)
        server.sendmail(settings.FROM_EMAIL, [to_email], msg.as_string())


async def send_invitation_email(to_email: str, org_name: str, role: str, accept_url: str) -> dict:
    """Send (or, in dev mode, log) an organization invitation email.

    Returns a status dict the caller may surface to the admin:
      {"sent": True}  or  {"sent": False, "reason": "<detail>"}
    Never raises for delivery problems — failures are logged and reported.
    """
    settings = get_settings()

    if not settings.SMTP_HOST:
        # Dev mode: make the accept link impossible to miss in the logs.
        logger.warning(
            "EMAIL NOT SENT (SMTP not configured): invitation for %s to join '%s' as %s — "
            "accept link: %s",
            to_email, org_name, role, accept_url,
        )
        return {"sent": False, "reason": "SMTP not configured (dev mode) — invitation link logged"}

    try:
        await asyncio.to_thread(_send_sync, to_email, org_name, role, accept_url)
        logger.info("invitation email sent to %s (org '%s', role %s)", to_email, org_name, role)
        return {"sent": True}
    except Exception as exc:  # noqa: BLE001 - delivery must never break the invite flow
        logger.error("invitation email delivery to %s failed: %s", to_email, exc)
        return {"sent": False, "reason": f"delivery failed: {type(exc).__name__}"}
