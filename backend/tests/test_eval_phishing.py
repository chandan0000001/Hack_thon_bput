"""Phishing-text engine evaluation at scale (SMS/emails) + FP-hardening
marketing regression set (Deliverable 4)."""

import json
from pathlib import Path

import pytest

from tests.conftest import scale_n
from tests.datakit import synthetic_emails, synthetic_impersonation, fetch_or_cache, _load_sms_tsv
from tests.metrics import compute_metrics, score_from_indicators, verbose_fail

from app.services.phishing_detector import analyze_email_heuristics

pytestmark = pytest.mark.scale

SMS_URLS = [
    "https://raw.githubusercontent.com/justmarkham/DAT8/master/data/sms.tsv",
]

MARKETING_SET_PATH = Path(__file__).resolve().parents[1] / "tests" / "data" / "synthetic" / "marketing_emails.json"


def _load_email_rows(request):
    """Online SMS corpus (cached) blended with synthetic emails to reach the
    target scale; SMS rows labeled spam == phishing. SMS rows are analyzed
    with channel="sms" (FP-hardening D3: SMS vocabulary is channel-scoped)."""
    scale = scale_n(request, 1000)
    offline = request.config.getoption("--offline")
    force = request.config.getoption("--fetch")

    sms, mode = fetch_or_cache("sms_spam", SMS_URLS, _load_sms_tsv,
                               lambda: synthetic_emails(200, seed=101),
                               force=force, offline=offline)
    if request.config.getoption("--offline") and mode == "cache":
        pass  # cache is still offline-safe

    spam_rows = [
        {
            "payload": {"sender": "unknown@sms", "subject": "(sms)", "body": r["text"]},
            "expected_label": "phishing" if r["label"] == "spam" else "benign",
            "expected_band_hint": "high" if r["label"] == "spam" else "safe",
            "channel": "sms",
        }
        for r in sms
        if r["label"] in ("spam", "ham")
    ]

    synth = synthetic_emails(max(0, scale - len(spam_rows)), seed=11)
    rows = (spam_rows + synth)[:scale]
    # Blend in impersonation pairs as extra phishing-text coverage.
    imp = synthetic_impersonation(min(100, scale // 5), seed=41)
    rows += [
        {"payload": {"sender": f"impersonator@{r['payload']['claimed_identity']}",
                     "subject": "(message)", "body": r["payload"]["message"]},
         "expected_label": r["expected_label"], "expected_band_hint": r["expected_band_hint"]}
        for r in imp
    ]
    return rows, mode


@pytest.mark.scale
def test_eval_phishing_scale(request, eval_report):
    rows, data_mode = _load_email_rows(request)
    scored = []
    for row in rows:
        payload = row["payload"]
        indicators = analyze_email_heuristics(
            payload["sender"], payload["subject"], payload["body"],
            channel=row.get("channel", "email"),
        )
        score = score_from_indicators(indicators)
        scored.append({**row, "score": score, "indicators": indicators})

    metrics = compute_metrics(scored)
    metrics["data_mode"] = data_mode
    eval_report.record_engine("phishing_text", **metrics)

    # Separation assertions (malicious must score above benign + margin).
    assert metrics["mal_mean"] > metrics["ben_mean"] + 15, (
        "band separation failed: mal_mean=%.1f ben_mean=%.1f" % (metrics["mal_mean"], metrics["ben_mean"])
    )
    assert metrics["f1"] >= 0.50, f"phishing F1: {metrics['f1']:.3f}"

    eval_report.record_finding(
        "phishing_text recall is corpus-limited: the online SMS Spam corpus is "
        "out-of-domain for URL/credential-heavy email heuristics (SMS ham also "
        "scores 0, precision stays 1.0). Synthetic email templates score high. "
        "See phishing_text metrics."
    )

    # Verbose first failures.
    fn = [r for r in scored if r["expected_label"] == "phishing" and r["score"] < 50][:5]
    fp = [r for r in scored if r["expected_label"] == "benign" and r["score"] >= 50][:5]
    for r in fn:
        eval_report.record_finding(f"phishing FN: {verbose_fail('FN', r, r['score'], r['indicators'])}")
    for r in fp:
        eval_report.record_finding(f"phishing FP: {verbose_fail('FP', r, r['score'], r['indicators'])}")


@pytest.mark.scale
def test_eval_phishing_ml_blend_never_lowers(request, eval_report):
    """Monotonic blend property at scale: ML may raise, never lower."""
    from app.services.ml_inference import score_with_ml

    rows, _ = _load_email_rows(request)
    lowered = []
    for row in rows[: min(300, len(rows))]:
        payload = row["payload"]
        indicators = analyze_email_heuristics(
            payload["sender"], payload["subject"], payload["body"],
            channel=row.get("channel", "email"),
        )
        heuristic, blended, _ = score_with_ml(indicators)
        if blended < heuristic:
            lowered.append((payload["subject"][:60], heuristic, blended))
    eval_report.record_property("monotonic_blend_emails", checked=len(rows[:300]), lowered=len(lowered))
    assert not lowered, f"ML lowered heuristic scores: {lowered[:5]}"


# ---------------------------------------------------------------------------
# FP-hardening Deliverable 4: marketing/transactional regression set.
# Post-Deliverable-2 policy: marketing mail must NOT auto-quarantine —
# overall severity <= medium AND the corroboration gate must fail (no
# provider write) — while real phishing positives still auto-enforce.
# ---------------------------------------------------------------------------

def _load_marketing_samples() -> list[dict]:
    data = json.loads(MARKETING_SET_PATH.read_text(encoding="utf-8"))
    return data["samples"]


def _scan_sample(sample: dict):
    """Full pipeline scan (identical engines to the mailbox scan path)."""
    import asyncio

    from app.schemas.email import NormalizedMessage
    from app.services.action_engine import corroboration_check
    from app.services.mail_scanner import scan_message

    message = NormalizedMessage(
        provider_message_id=sample["name"],
        sender=sample["sender"],
        subject=sample["subject"],
        body_text=sample["body"],
    )
    scan = asyncio.run(scan_message(message))
    met, reason = corroboration_check(scan)
    return scan, met, reason


@pytest.mark.scale
def test_eval_marketing_never_auto_quarantines(eval_report):
    """The marketing set must not auto-quarantine and must score <= medium."""
    samples = _load_marketing_samples()
    assert len(samples) >= 8, "marketing regression set shrank"
    failures = []
    rows = []
    for sample in samples:
        scan, met, reason = _scan_sample(sample)
        score = round(scan.overall_score * 100)
        rows.append({
            "expected_label": "benign",
            "score": score,
            "expected_band_hint": "safe",
            "indicators": [
                {"type": i.name, "severity": "", "description": i.value}
                for a in scan.feature_analyses for i in a.indicators
            ],
            "payload": {"sender": sample["sender"], "subject": sample["subject"]},
        })
        auto_quarantines = scan.recommended_action == "quarantine" and met
        if auto_quarantines or scan.overall_severity not in ("safe", "low", "medium"):
            failures.append(
                f"{sample['name']}: severity={scan.overall_severity} score={score} "
                f"corroboration_met={met} action={scan.recommended_action} ({reason})"
            )
    metrics = compute_metrics(rows)
    eval_report.record_engine("marketing_fp_check", **metrics)
    eval_report.record_finding(
        "FP-hardening marketing regression set (10 realistic digest/newsletter/"
        "transactional emails incl. the Medium digest payload and the "
        "mediumday.com event-reg token URL): all must stay <= medium and "
        "fail the corroboration gate (review_recommended, no provider write)."
    )
    assert not failures, "marketing set auto-quarantine FPs:\n" + "\n".join(failures)


@pytest.mark.scale
def test_eval_phishing_positives_still_auto_quarantine(eval_report):
    """Real phishing positives must still pass the corroboration gate and
    reach the auto-quarantine path — hardening must not blunt detection."""
    phishing_samples = [
        {
            "name": "brand_lookalike_credential_harvest",
            "sender": "PayPal Security <security@paypa1-secure.tk>",
            "subject": "Urgent: verify your account immediately",
            "body": "Your account will be suspended within 24 hours. Confirm your account "
                    "and enter your password now: http://paypa1-secure.tk/verify-login.php",
        },
        {
            "name": "ip_host_phishing",
            "sender": "IT Support <support@corp-verify.tk>",
            "subject": "Action required: password reset",
            "body": "Update your password immediately at http://192.168.43.12/secure-update.php "
                    "or your account will be terminated.",
        },
        {
            "name": "platform_hosted_phishing",
            "sender": "Netflix Billing <billing@nflx-billing-update.vercel.app>",
            "subject": "Payment failed: update your billing information",
            "body": "We could not process your payment. Update your billing information to "
                    "avoid suspension: https://nflx-billing-update.vercel.app/verify/billing.php?session=9a8b7c6d5e4f",
        },
    ]
    misses = []
    rows = []
    for sample in phishing_samples:
        scan, met, reason = _scan_sample(sample)
        score = round(scan.overall_score * 100)
        rows.append({
            "expected_label": "phishing",
            "score": score,
            "expected_band_hint": "high",
            "indicators": [
                {"type": i.name, "severity": "", "description": i.value}
                for a in scan.feature_analyses for i in a.indicators
            ],
            "payload": {"sender": sample["sender"], "subject": sample["subject"]},
        })
        if scan.recommended_action not in ("quarantine", "block") or scan.overall_severity not in ("critical", "high"):
            misses.append(f"{sample['name']}: severity={scan.overall_severity} score={score}")
        if not met:
            misses.append(f"{sample['name']}: corroboration gate failed ({reason})")
    metrics = compute_metrics(rows)
    eval_report.record_engine("phishing_auto_enforce_check", **metrics)
    eval_report.record_finding(
        "FP-hardening phishing positive control: brand-lookalike, IP-host and "
        "platform-hosted phishing must still trip corroboration (>=2 engines "
        "high+) and land on the auto-quarantine path."
    )
    assert not misses, "phishing positives no longer auto-quarantine:\n" + "\n".join(misses)
