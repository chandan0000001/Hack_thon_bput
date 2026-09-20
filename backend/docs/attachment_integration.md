# Attachment Integration & Explainable Verdicts — Phase 4 (ATTACH-SCAN-4)

Phase 4 connects the scanner to the live email pipeline and produces the
final, explainable verdict users see. Chain: `fetch_service` captures
attachment metadata (no bytes) → `analysis_service` streams and scans each
attachment after the body engines → `AttachmentRiskScorer` and
`VerdictBuilder` produce the final score and explanation.

## Integration points

**1. Fetch (`app/services/gmail/fetch_service.py`)** —
`extract_attachments_meta(payload)` walks MIME parts recursively and
records `{attachment_id, filename, mime_type, size_bytes, scan_status:
"pending"}` into `processed_emails.attachments_meta`. **No attachment
bytes are downloaded at fetch time** — Gmail metadata only; streaming
happens in the analysis worker (memory safety, Phase 1 guarantees).

**2. Analysis (`app/services/gmail/analysis_service.py`)** — after the
phishing/URL/impersonation/auth engines compute the body risk:
- `scan_email_attachments(...)` loads the Gmail account tokens, then scans
  each pending attachment via `AttachmentScanner.scan_attachment` and
  fills `scan_results` (status, risk_score, verdict, severity, indicators,
  sha256, detected_mime, scan_duration_ms, explanation) in place.
- `aggregate_attachment_risk(...)` folds attachment risk into the email
  risk on a common 0–100 scale (the body pipeline scores 0–1; conversion
  happens at the boundary).
- `VerdictBuilder().build_explainable_verdict(...)` produces the final
  `verdict` / `severity` / `explanation` stored on the processed email.

## Risk scoring algorithm

**Attachment level** (`AttachmentRiskScorer.score`): the engine pipeline
hands over its already-capped total (Levels 1–3) plus the indicator list.

| Condition | Verdict / severity |
| --- | --- |
| Any critical-severity indicator, or type in {executable_disguise, zip_bomb_suspected, clamav_signature} | **malicious / critical** (forced) |
| risk ≥ 80 | malicious / critical |
| risk ≥ 40 | suspicious / high |
| risk ≥ 20 | suspicious / medium |
| else | safe / low |

`explanation` names the top-3 indicators by severity (with descriptions),
e.g. "Attachment scored 80/100 (malicious). Strongest evidence:
pdf_javascript (…); mime_mismatch (…); yara_match (…)."

**Email level** (`VerdictBuilder`): verdict malicious ≥ 80, suspicious ≥ 40,
else safe; severity critical ≥ 80, high ≥ 60, medium ≥ 40, else low.

## Monotonic safety (attachments raise, never lower)

`aggregate_attachment_risk` returns `max(body_risk, max_attachment_risk)`.
A clean attachment can never dilute a phishing verdict; a malicious
attachment always elevates it (with verdict override malicious ≥ 80 /
suspicious ≥ 40). The same principle as the ML monotonic blend already
used by the body engines.

## Explainable verdict format

`processed_emails.verdict` / `.severity` / `.explanation` (new Phase-4
columns; `classification` keeps its legacy body-only semantics). The
explanation is plain language, e.g.:

> "Email body: 5 indicators detected 1 malicious attachment(s) detected
> (invoice.pdf)"

so a SOC analyst sees the count and names of flagged attachments without
opening scan_details. Per-attachment explanations live in
`attachments_meta[i].scan_results.explanation`.

## Failure isolation

- **Per-attachment**: a scanner crash records `scan_status: "failed"` with
  the error in `scan_results` and the loop continues — one broken
  attachment never blinds the rest of the email. Attachments without an
  `attachment_id` are `skipped`.
- **Per-engine**: unchanged from Phases 2–3 (engine_error info indicators).
- **Scan failure contributes risk 0**, it never aborts the email analysis
  and never blocks body-only verdicts.
- **Gmail context unavailable** (no tokens/account): pending attachments
  stay pending; analysis completes on body signals alone.

## Implementation note (SQLAlchemy JSON mutation)

The scanned metadata is written back via a **deep copy** of
`attachments_meta`. Because the scanner mutates entries in place, a
shallow copy would share dicts with the loaded attribute value; SQLAlchemy
then compares the assignment against an already-mutated snapshot, sees
`old == new`, and silently skips the UPDATE. The deep copy guarantees the
pre-scan and post-scan values genuinely differ.

## Test coverage

`tests/test_attachment_integration.py` (Suite 34, 12 assertions): scorer
thresholds/forcing/explanation; fetch metadata (pending, recursive, empty);
scanner invocation per attachment; monotonic aggregation both directions;
two end-to-end pipeline runs (malicious PDF → email verdict malicious with
attachment named in the explanation; benign PDF → verdict unchanged);
VerdictBuilder explanation; scanner-crash isolation.
