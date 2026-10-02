"""EMAIL-ACTION-MATRIX tests.

Covers the two halves of the mission:
1. Reliable weighted blending of the FINAL email risk score
   (0.62 heuristic + 1.0 ML must land at ~0.77, not 1.0).
2. The 4-tier action matrix mapped from the corrected 0.0-1.0 score:
   pass (<0.30) / notify (0.30-0.59) / quarantine (0.60-0.84) / block (>=0.85),
   including the provider-backed enforcement outcomes per tier.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.crypto import encrypt_secret
from app.db.models import (
    BlockedSender,
    EmailConnectorAccount,
    OrgBlockedIndicator,
    OrgOrganization,
    QuarantinedItem,
    User,
)
from app.db.session import async_session_maker
from app.schemas.email import NormalizedMessage
from app.schemas.scan_results import FeatureAnalysis, ScanResult as PydanticScanResult
from app.services.email_providers.mock_provider import MockEmailProvider

pytestmark = pytest.mark.http


# ---------------------------------------------------------------------------
# P1: blending math
# ---------------------------------------------------------------------------


def test_weighted_blend_mission_example():
    """The exact mission example: URL heuristic 0.62 + ML 1.0 -> 0.772 (High),
    NOT 1.0 (Critical) as the old monotonic max produced."""
    from app.services.gmail.analysis_service import weighted_blend

    assert weighted_blend(0.62, 1.0) == 0.772


def test_weighted_blend_without_ml_returns_heuristic():
    from app.services.gmail.analysis_service import weighted_blend

    assert weighted_blend(0.42, None) == 0.42


def test_weighted_blend_strictly_clamped_to_unit_interval():
    from app.services.gmail.analysis_service import weighted_blend

    assert 0.0 <= weighted_blend(1.0, 1.0) <= 1.0
    assert weighted_blend(1.0, 1.0) == 1.0
    assert weighted_blend(0.0, 0.0) == 0.0


def test_blend_engine_scores_ml_no_longer_saturates():
    """Regression for the reported bug: a single 1.0 ML score over a 0.62
    heuristic with safe phishing/impersonation engines must stay High, not
    saturate at 100/100."""
    from app.services.gmail.analysis_service import blend_engine_scores

    final = blend_engine_scores(
        combined_heur=0.62,
        text_heur=0.05,
        url_heur=0.62,
        impers_heur=0.0,
        max_ml=1.0,
    )
    assert final == pytest.approx(0.772, abs=0.001)
    assert final < 0.85, "0.62 heuristic + 1.0 ML must not reach the critical tier"


def test_blend_engine_scores_dominant_heuristic_still_wins():
    """Strong heuristics across all engines must keep the score high even
    without ML corroboration."""
    from app.services.gmail.analysis_service import blend_engine_scores

    final = blend_engine_scores(
        combined_heur=0.95,
        text_heur=0.9,
        url_heur=0.0,
        impers_heur=0.8,
        max_ml=None,
    )
    assert final == pytest.approx(0.95, abs=0.001)


# ---------------------------------------------------------------------------
# P2: 4-tier action matrix thresholds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "score,expected_tier",
    [
        (0.20, "pass"),        # mission P4 case
        (0.29, "pass"),
        (0.30, "notify"),      # lower boundary inclusive
        (0.50, "notify"),      # mission P4 case
        (0.59, "notify"),
        (0.60, "quarantine"),  # lower boundary inclusive
        (0.70, "quarantine"),  # mission P4 case
        (0.84, "quarantine"),
        (0.85, "block"),       # lower boundary inclusive
        (0.90, "block"),       # mission P4 case
        (1.0, "block"),
    ],
)
def test_get_recommended_action_tiers(score, expected_tier):
    from app.services.scoring_service import get_recommended_action

    assert get_recommended_action(score) == expected_tier


# ---------------------------------------------------------------------------
# P2: enforcement outcomes per tier (provider-backed, mock provider)
# ---------------------------------------------------------------------------


def _normalized_message(message_id: str) -> NormalizedMessage:
    return NormalizedMessage(
        provider_message_id=message_id,
        provider="mock",
        sender="Evil <phisher@evil-spam.tk>",
        recipients=["victim@example.com"],
        subject="URGENT: verify your account",
        body_text="Verify now: http://192.168.10.5/verify-login.php",
    )


def _fake_resolve_org_id(org_id: str):
    """Pin the org resolution to the harness org (Postgres-only raw SQL)."""

    async def _resolve(db, owner_user_id):
        return org_id

    return _resolve


def _scan_for_tier(score_0_1: float, recommended_action: str) -> PydanticScanResult:
    """Worker-equivalent ScanResult: both engines carry the tier severity so
    the block tier's corroboration gate is satisfied, mirroring how
    email_worker builds the enforcement scan."""
    severity = "critical" if recommended_action == "block" else "high"
    return PydanticScanResult(
        message_id="m-matrix",
        subject="URGENT: verify your account",
        sender="Evil <phisher@evil-spam.tk>",
        overall_severity=severity,
        overall_score=round(min(1.0, score_0_1), 3),
        overall_explanation="test verdict",
        feature_analyses=[
            FeatureAnalysis(engine="heuristics", severity=severity, score=score_0_1, explanation="test"),
            FeatureAnalysis(engine="ml_model", severity=severity, score=score_0_1, explanation="test"),
        ],
        recommended_action=recommended_action,
        provider_operation_status="pending",
    )


async def _connector(db, owner: str) -> EmailConnectorAccount:
    connector = EmailConnectorAccount(
        id=f"matrix-{uuid.uuid4().hex[:8]}",
        owner_user_id=owner,
        provider="mock",
        provider_email=f"{owner}@provider.test",
        status="connected",
        access_token_enc=encrypt_secret("tok"),
        access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(connector)
    await db.commit()
    await db.refresh(connector)
    return connector


async def _enforce_with_mock(monkeypatch, db, owner: str, scan: PydanticScanResult):
    from app.services.action_engine import enforce_scan_result

    provider = MockEmailProvider()
    provider.seed_message("m-matrix", sender="phisher@evil-spam.tk")

    import app.services.action_engine as action_engine

    orig = action_engine.get_provider
    action_engine.get_provider = lambda name: provider if name == "mock" else orig(name)
    try:
        connector = await _connector(db, owner)
        result = await enforce_scan_result(db, connector, _normalized_message("m-matrix"), scan)
        return result, provider
    finally:
        action_engine.get_provider = orig


@pytest.mark.http
async def test_pass_tier_performs_no_provider_action(initialized_db, monkeypatch):
    """Score 0.20 -> Pass: message delivered, nothing enforced."""
    from app.schemas.scan_results import ScanResult as Pyd

    scan = _scan_for_tier(0.20, "pass")
    scan = Pyd.model_validate(scan.model_dump(mode="json"))
    scan.provider_operation_status = "pending"

    uid = f"matrix-{uuid.uuid4().hex[:6]}"
    async with async_session_maker() as db:
        db.add(User(id=uid, email=f"{uid}@t.local", is_single_user=True))
        await db.commit()
        result, provider = await _enforce_with_mock(monkeypatch, db, uid, scan)

        assert result.provider_operation_status == "no_action_required"
        assert not provider.calls, "pass tier must not touch the provider"
        items = (await db.execute(select(QuarantinedItem))).scalars().all()
        assert items == []


@pytest.mark.http
async def test_notify_tier_warns_without_mailbox_change(initialized_db, monkeypatch):
    """Score 0.50 -> Notify: user warned, NO quarantine, NO sender block."""
    scan = _scan_for_tier(0.50, "notify")

    uid = f"matrix-{uuid.uuid4().hex[:6]}"
    async with async_session_maker() as db:
        db.add(User(id=uid, email=f"{uid}@t.local", is_single_user=True))
        await db.commit()
        result, provider = await _enforce_with_mock(monkeypatch, db, uid, scan)

        assert result.provider_operation_status == "notified"
        assert not provider.calls, "notify tier must not perform provider operations"
        items = (await db.execute(select(QuarantinedItem))).scalars().all()
        blocks = (await db.execute(select(BlockedSender))).scalars().all()
        assert items == [] and blocks == []


@pytest.mark.http
async def test_quarantine_tier_quarantines_without_blocking(initialized_db, monkeypatch):
    """Score 0.70 -> Quarantine: message moved, sender NOT blocked."""
    scan = _scan_for_tier(0.70, "quarantine")

    uid = f"matrix-{uuid.uuid4().hex[:6]}"
    async with async_session_maker() as db:
        db.add(User(id=uid, email=f"{uid}@t.local", is_single_user=True))
        await db.commit()
        result, provider = await _enforce_with_mock(monkeypatch, db, uid, scan)

        assert result.provider_operation_status == "success"
        assert any(
            call[0] == "quarantine_message" and call[1] == "m-matrix" for call in provider.calls
        )
        assert not any(call[0] == "create_sender_rule" for call in provider.calls), (
            "quarantine tier must NOT block the sender"
        )
        items = (await db.execute(select(QuarantinedItem))).scalars().all()
        assert len(items) == 1 and items[0].status == "quarantined"
        blocks = (await db.execute(select(BlockedSender))).scalars().all()
        assert blocks == []


@pytest.mark.http
async def test_block_tier_quarantines_and_blocks_sender(initialized_db, monkeypatch):
    """Score 0.90 -> Quarantine + Block: message moved, provider filter
    created, sender email + domain recorded in org_blocked_indicators."""
    scan = _scan_for_tier(0.90, "block")

    uid = f"matrix-{uuid.uuid4().hex[:6]}"
    async with async_session_maker() as db:
        db.add(User(id=uid, email=f"{uid}@t.local", is_single_user=True))
        # Org blocklist write requires a resolvable org for the owner. The
        # real resolver uses schema-qualified raw SQL that only exists on
        # Postgres, so the harness pins the resolved org directly.
        org_id = f"org-{uuid.uuid4().hex[:8]}"
        db.add(OrgOrganization(id=org_id, name="Matrix Org", owner_id=uid))
        await db.commit()

        import app.services.org_context as org_context

        monkeypatch.setattr(
            org_context, "resolve_org_id", _fake_resolve_org_id(org_id), raising=False
        )

        result, provider = await _enforce_with_mock(monkeypatch, db, uid, scan)

        assert result.provider_operation_status == "success"
        assert any(
            call[0] == "quarantine_message" and call[1] == "m-matrix" for call in provider.calls
        )
        assert any(call[0] == "create_sender_rule" for call in provider.calls), (
            "block tier must create a provider sender rule"
        )
        items = (
            await db.execute(
                select(QuarantinedItem).where(QuarantinedItem.owner_user_id == uid)
            )
        ).scalars().all()
        assert len(items) == 1
        blocks = (
            await db.execute(
                select(BlockedSender).where(BlockedSender.owner_user_id == uid)
            )
        ).scalars().all()
        assert len(blocks) == 1 and blocks[0].sender_email == "phisher@evil-spam.tk"

        indicators = (
            await db.execute(
                select(OrgBlockedIndicator).where(OrgBlockedIndicator.organization_id == org_id)
            )
        ).scalars().all()
        values = {(i.indicator_type, i.indicator_value) for i in indicators}
        assert ("email", "phisher@evil-spam.tk") in values, "sender email must be pure-blocked"
        assert ("domain", "evil-spam.tk") in values, "sender domain must be pure-blocked"
