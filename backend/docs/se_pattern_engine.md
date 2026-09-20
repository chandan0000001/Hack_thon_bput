# Social-Engineering Pattern Engine (SE-HARDENING)

Branch `se-hardening` · Suite 37 (`tests/test_se_patterns.py`, 12 checks) · 2026-09-21

## 1. Why this engine exists — the false negative auth-verify cannot fix

The screenshot sample (`security-alert@cyberguard.com`, fixture
`tests/data/synthetic/se_phishing_attachment_lure.txt`) arrived through the
manual/paste path: sender + subject + body, **no SMTP headers**. AUTH-VERIFY
made that blindness *honest* (`auth_headers_missing` indicator + warning), but
honesty is not detection — with no headers there is nothing to verify, so the
content engines alone must carry the verdict. The existing content heuristics
scored the sample only 20/100: one `urgency` indicator. The email's real
attack is narrative-level — "we are your security team, something happened,
prove your identity via the attached document, deadline" — which no single
keyword captures. `SEPatternEngine` models that narrative explicitly.

## 2. Pattern taxonomy

| Pattern | Severity | Points/match | Regex vocabulary |
|---|---|---|---|
| `security_alert_framing` | high | +15 | "we detected a (recent) sign-in", "unrecognized (activity\|device\|location)", "account protection", "security verification", "authentication event" |
| `attachment_lure` | high | +15 | "review the attached", "see attached document", "attached verification", "open the attachment" |
| `bureaucratic_urgency` | medium | +10 | "(may) expire within N hours", "as soon as possible", "may expire" |
| `authority_impersonation` | medium | +10 | "(account\|security\|protection) team", "(IT\|security) department" |
| `vague_threat` | medium | +10 | "unrecognized activity", "suspicious activity", "unusual sign-in" |

Each indicator carries `match_count` (every occurrence, for the analyst).
Scoring counts at most **2 matches per pattern** toward the risk (repetition
cannot out-argue content) and the total is capped at 100.

## 3. The combination rule (the story beats the phrases)

`security_alert_framing` **AND** (`attachment_lure` **OR** `bureaucratic_urgency`)
→ `se_combination_rule` (high) **+45**.

Rationale: each family is individually survivable — banks send real security
notices, real mail says "see attached". The attack is the *composition*: an
unrequested security alert that also gives you a reason and a deadline to open
a document. Individually weak signals become decisive only together, so the
bonus is deliberately larger than any single pattern (+45 vs +15/+10). A
message can reach the combination only by matching at least two independent
families, which legitimate mail rarely does.

## 4. Monotonic merge (safety contract)

`blend_se(heuristic, se_risk) = max(heuristic, 0.7·heuristic + 0.3·se_risk)`

- SE risk is the **sole** scoring contribution of the SE engine — its
  indicators join the display/indicator list but are deliberately excluded
  from `calculate_score`, so nothing is double-counted.
- The blend can raise a verdict, never lower one (`max`); a strong heuristic
  (0.8) with weak SE (0.3) stays 0.8; a weak heuristic (0.2) with strong SE
  (0.7) rises to ~0.35.
- Applied **after** the AUTH-VERIFY section in both paths (realtime
  `analysis_service`, manual `routes_analysis`), on the pre-SE heuristic.

## 5. Confidence fix (D3)

`assess_confidence(heuristic, ml, url_indicator_count, body)`:

- heuristic < 0.5 **and** ML < 0.5 → `confidence: "low"` + explanation
  *"Low confidence: weak heuristic and ML signals. Manual review recommended."*
- heuristic < 0.3, **zero URL indicators**, body references attachments →
  appends *"attachment-lure pattern detected; verify attachment content
  separately."*

The second rule is the screenshot scenario in miniature: nothing malicious in
the text, no URLs to analyze, but the message wants an attachment opened —
the engine refuses to let that look like a confident "safe". ML=None (model
unavailable) never triggers the low label alone; the rule requires both
signals weak.

## 6. Manual-path warning coordination (D4)

The manual route now emits both warnings through the **same** `warnings` array
(additive, de-duplicated by membership check):

1. `SPF/DKIM/DMARC cannot be verified: manual text scan carries no message headers` (auth-verify)
2. `Email references attachments; attachment content not scanned in manual mode unless raw_headers supplied` (SE-HARDENING, fired when the body references an attachment)

## 7. Screenshot email: before vs after

| | before SE-HARDENING | after |
|---|---|---|
| Content heuristic | 20/100 (one `urgency`) | 20/100 (unchanged) |
| Auth | unavailable (no headers) | unavailable — honestly reported, not masking |
| SE risk | — | 100 (framing ×4→30, lure ×2→30, urgency, authority, vague, combination +45) |
| Final risk | ~44 floor (suspicious-ish, below eval bar) | **75 — suspicious/high** |
| Indicators | 2 | 9 (5 patterns + combination rule + auth/ML) |

## 8. False-positive posture

Benign mail legitimately says "attached": the eval case
*"review the attached invoice, payment due in 30 days"* scores lure +15 only →
blend keeps the email **safe (<40)**. The combination rule requires the
security-alert framing to co-occur, which invoice mail never has. The
attachment-reference warning is informational and fires regardless of verdict.

## 9. Wiring map

- `analysis_service.process_email_analysis`: SE section after the auth
  monotonic merge → `blend_se` into `combined_heur_score`; indicators into
  `indicators_summary`; `signals.se_patterns` + `signals.confidence` recorded;
  confidence notes appended to the explanation.
- `routes_analysis.analyze_email` (manual): SE section after auth section;
  SE blend contributes via the `min_score` floor (monotonic, same formula);
  attachment-reference warning appended to the shared warnings array;
  confidence notes appended to the alert explanation.
- Config: `SE_PATTERN_ENABLED=True`. Tests: Suite 37 (12 pytest checks) +
  12 runner checks; eval case registry `tests/data/synthetic/se_eval_cases.json`
  evaluated end-to-end through the real manual pipeline without raw_headers.
