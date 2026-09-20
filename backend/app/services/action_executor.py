"""Executes enforcement actions (simulated for prototype)."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ActionExecution, Alert

logger = logging.getLogger("cyberguard.action_executor")


# Map generic policy actions -> module-specific enforcement actions.
# Policy verbs (block / warn_and_log / ...) are platform-agnostic; the actual
# enforcement depends on what kind of artifact the module detected.
_MODULE_ACTION_REFINEMENT: dict[tuple[str, str], str] = {
    # (policy_action, module) -> specific action
    ("block", "phishing"): "quarantine_email",
    ("block", "url"): "block_url",
    ("block", "impersonation"): "quarantine_email",
    ("block", "account_takeover"): "revoke_session",
    ("block", "network"): "block_ip",
    ("block", "api_abuse"): "rate_limit",
    ("block", "deepfake"): "flag_for_review",
    ("block_and_quarantine", "phishing"): "quarantine_email",
    ("block_and_quarantine", "url"): "block_url",
    ("block_and_quarantine", "impersonation"): "quarantine_email",
    ("block_and_quarantine", "account_takeover"): "revoke_session",
    ("block_and_quarantine", "network"): "block_ip",
    ("block_and_quarantine", "api_abuse"): "rate_limit",
    ("block_and_quarantine", "deepfake"): "flag_for_review",
    ("warn_and_log", "phishing"): "tag_and_warn",
    ("warn_and_log", "url"): "tag_and_warn",
    ("warn_and_log", "impersonation"): "tag_and_warn",
    ("warn_and_log", "account_takeover"): "require_mfa",
    ("warn_and_log", "network"): "rate_limit",
    ("warn_and_log", "api_abuse"): "rate_limit",
    ("warn_and_log", "deepfake"): "flag_for_review",
}


def refine_action_for_module(action_type: str, module: str) -> str:
    """Translate a generic policy action into the module-specific enforcement action.

    Unknown combinations pass through unchanged ("allow" always stays "allow").
    """
    return _MODULE_ACTION_REFINEMENT.get((action_type, module), action_type)


class ActionExecutor:
    """
    Executes enforcement actions.

    For the hackathon prototype, all actions are simulated:
    - Log the action
    - Generate a unique ID (quarantine_id, block_id, etc.)
    - Return success

    In production, these would call external APIs:
    - quarantine_email -> Microsoft Graph API / Gmail API
    - block_url -> Firewall API / DNS sinkhole
    - drop_packet -> SDN controller / firewall
    - revoke_session -> Identity provider (Okta, Azure AD)
    """

    async def execute(
        self,
        db: AsyncSession,
        alert: Alert,
        action_type: str,
        execution_mode: str,  # "client" | "server"
        raw_data: Optional[dict[str, Any]] = None,
        policy_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        event_id: Optional[str] = None,
        triggered_by: str = "api",
        triggered_by_id: Optional[str] = None,
        auto_execute: bool = False,
    ) -> ActionExecution:
        """
        Execute an enforcement action and persist the result.

        Returns the ActionExecution record (status: "success" if executed,
        "pending" if it requires approval, "skipped" in client mode).
        """

        # Determine initial status
        if execution_mode == "client":
            # Client mode: just a recommendation, no execution
            status = "skipped"
            requires_approval = False
            executed_at = None
            execution_result = {"reason": "client_mode_recommendation_only"}
        elif auto_execute or action_type == "allow":
            # "allow" is a no-op (traffic already flows); executing it needs no
            # approval even when the policy disables auto-execution for the band.
            status = "success"
            requires_approval = False
            executed_at = datetime.now(timezone.utc)
            execution_result = await self._simulate_action(action_type, alert)
        else:
            # Server mode + requires approval
            status = "pending"
            requires_approval = True
            executed_at = None
            execution_result = None

        # Create ActionExecution record
        # ORG-WIRE: fall back to the owner's active/personal org so the
        # org-branch RLS policies (migration 0018) keep the execution row
        # visible to org members even when the alert itself is un-stamped.
        org_stamp = organization_id or alert.organization_id
        if org_stamp is None:
            try:
                from app.services.org_context import resolve_org_id

                org_stamp = await resolve_org_id(db, alert.owner_user_id)
            except Exception:  # noqa: BLE001 - stamping is best-effort
                org_stamp = None
        execution = ActionExecution(
            id=str(uuid.uuid4()),
            organization_id=org_stamp,
            owner_user_id=alert.owner_user_id,  # inherit tenant owner (RLS)
            alert_id=alert.id,
            event_id=event_id or alert.event_id,
            action_type=action_type,
            target=self._build_target(action_type, alert, raw_data or {}),
            status=status,
            execution_mode=execution_mode,
            triggered_by=triggered_by,
            triggered_by_id=triggered_by_id,
            requires_approval=requires_approval,
            executed_at=executed_at,
            execution_result=execution_result,
            risk_score=alert.risk_score,
            severity=alert.severity,
            threat_type=alert.threat_type or alert.module,
            module=alert.module,
            policy_id=policy_id,
        )

        db.add(execution)
        await db.commit()
        await db.refresh(execution)

        logger.info(
            "ActionExecution created: id=%s, action=%s, status=%s, auto_execute=%s",
            execution.id, action_type, status, auto_execute,
        )

        return execution

    async def execute_simulated(self, action_type: str, alert: Alert) -> dict[str, Any]:
        """Public wrapper for post-approval execution: run the simulated action
        and return its result payload (used by the approval workflow)."""
        return await self._simulate_action(action_type, alert)

    async def _simulate_action(self, action_type: str, alert: Alert) -> dict[str, Any]:
        """
        Simulate an enforcement action.

        In production, this would call external APIs.
        For the prototype, we just log and return a success response with a unique ID.
        """

        simulation_id = f"sim_{uuid.uuid4().hex[:12]}"

        if action_type == "quarantine_email":
            logger.info("[SIMULATED] Quarantining email for alert %s", alert.id)
            return {
                "quarantine_id": f"q_{simulation_id}",
                "simulated": True,
                "message": "Email moved to quarantine (simulated)",
            }

        elif action_type == "block_url":
            logger.info("[SIMULATED] Blocking URL for alert %s", alert.id)
            return {
                "block_id": f"b_{simulation_id}",
                "simulated": True,
                "message": "URL added to blocklist (simulated)",
            }

        elif action_type == "drop_packet":
            logger.info("[SIMULATED] Dropping packets for alert %s", alert.id)
            return {
                "drop_id": f"d_{simulation_id}",
                "simulated": True,
                "message": "Packets dropped (simulated)",
            }

        elif action_type == "block_ip":
            logger.info("[SIMULATED] Blocking IP for alert %s", alert.id)
            return {
                "block_id": f"ip_{simulation_id}",
                "simulated": True,
                "message": "IP blocked (simulated)",
            }

        elif action_type == "revoke_session":
            logger.info("[SIMULATED] Revoking sessions for alert %s", alert.id)
            return {
                "revoke_id": f"r_{simulation_id}",
                "simulated": True,
                "message": "Active sessions revoked (simulated)",
            }

        elif action_type == "require_mfa":
            logger.info("[SIMULATED] Requiring MFA for alert %s", alert.id)
            return {
                "mfa_id": f"mfa_{simulation_id}",
                "simulated": True,
                "message": "MFA challenge issued (simulated)",
            }

        elif action_type == "rate_limit":
            logger.info("[SIMULATED] Rate-limiting for alert %s", alert.id)
            return {
                "rate_limit_id": f"rl_{simulation_id}",
                "simulated": True,
                "message": "Rate limit applied (simulated)",
            }

        elif action_type in ("warn_and_log", "tag_and_warn", "flag_for_review"):
            logger.info("[SIMULATED] Flagging for review: %s", action_type)
            return {
                "flag_id": f"f_{simulation_id}",
                "simulated": True,
                "message": f"Flagged for review: {action_type}",
            }

        elif action_type == "allow":
            logger.info("[SIMULATED] Allowing traffic for alert %s", alert.id)
            return {
                "allow_id": f"a_{simulation_id}",
                "simulated": True,
                "message": "Traffic allowed",
            }

        elif action_type == "block_and_quarantine":
            logger.info("[SIMULATED] Blocking and quarantining for alert %s", alert.id)
            return {
                "block_quarantine_id": f"bq_{simulation_id}",
                "simulated": True,
                "message": "Blocked and quarantined (simulated)",
            }

        else:
            logger.warning("Unknown action_type: %s", action_type)
            return {
                "unknown_action_id": f"u_{simulation_id}",
                "simulated": True,
                "message": f"Unknown action type: {action_type}",
            }

    def _build_target(
        self,
        action_type: str,
        alert: Alert,
        raw_data: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Build the target dict for the ActionExecution record.

        Extracts relevant identifiers from the analysis raw_data.
        """

        if action_type == "quarantine_email" or (
            # Soft actions keep the email context visible for reviewers.
            action_type in ("warn_and_log", "tag_and_warn", "flag_for_review")
            and raw_data.get("subject")
        ):
            return {
                "email_id": raw_data.get("email_id", alert.event_id),
                "sender": raw_data.get("sender"),
                "recipient": raw_data.get("recipient") or raw_data.get("target_user"),
                "subject": raw_data.get("subject"),
            }

        elif action_type == "block_url":
            return {
                "url": raw_data.get("url"),
                "domain": raw_data.get("domain"),
            }

        elif action_type in ("drop_packet", "block_ip", "rate_limit"):
            return {
                "source_ip": alert.source_ip or raw_data.get("source_ip"),
                "destination_ip": raw_data.get("destination_ip"),
                "port": raw_data.get("port"),
            }

        elif action_type == "revoke_session":
            return {
                "user_id": raw_data.get("user_id"),
                "session_id": raw_data.get("session_id"),
            }

        elif action_type == "require_mfa":
            return {
                "user_id": raw_data.get("user_id"),
                "login_attempt_id": raw_data.get("login_attempt_id"),
            }

        else:
            # Generic target
            return {
                "alert_id": alert.id,
                "module": alert.module,
            }


# Module-level singleton
action_executor = ActionExecutor()
