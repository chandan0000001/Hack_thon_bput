# Independent SPF/DKIM/DMARC Verification (AUTH-VERIFY)

Branch `auth-verify` · Suite 36 (`tests/test_auth_verification.py`, 14 checks) · 2026-09-21

## 1. Audit result — what existed before this change

| Location | What it did | Classification | Path coverage |
|---|---|---|---|
| `app/services/gmail/fetch_service.py:91-131` (`parse_auth_headers`) | Regex-read `Authentication-Results`, `Received-SPF`, presence of `DKIM-Signature` into signals | **(a) header-PARSE only** | realtime (fetch → analysis) |
| `app/services/gmail/analysis_service.py:256-258, 301-327` | Substring `"fail"` match on parsed spf/dkim/dmarc strings → `spf_fail`/`dkim_fail`/`dmarc_fail` indicators | **(c) scoring only** | realtime (analysis worker) |
| `app/services/gmail/analysis_service.py:416-418, 446` | Echoed the parsed strings into `signals` / `scan_details.engine_results.auth` | **(c) scoring only** | realtime |
| `app/api/routes_analysis.py` (`POST /analysis/email`, Log Analysis paste-box) | `EmailAnalysisRequest` = sender + subject + body only; `analyze_email_heuristics(sender, subject, body)` — auth never entered the pipeline | **absent** | manual/paste — structurally blind |

Independent DNS/crypto verification existed **nowhere** in the codebase (classification (b): zero hits).

## 2. Diagnosis — why the sample scan got zero auth signal

- **The manual/paste path receives body + subject + sender only.** `POST /analysis/email` never carried SMTP headers, and a pasted email body contains no `Authentication-Results` — there is literally nothing to parse on that path.
- **The sample is synthetic.** The screenshot scan (event fallback: latest manual `phishing_email` event `051da97e-fc4b-4139-b76a-a92ca3a83c8e`, source `gateway`) has `raw_data` keys exactly `[body, sender, subject]`; its alert (`e79da52d…`, risk 70/high) carried 5 indicators (lookalike_domain, urgency×3, ml_model) and **zero** auth indicators. No receiving MX ever computed Authentication-Results for this message.
- **The realtime logic was PARSE-only.** Even for connector-received mail, `fetch_service` trusted whatever the MX wrote into `Authentication-Results`; nothing re-checked DNS or re-validated signatures. **Parse-only ≠ verification**; the manual path was **structurally blind**.

## 3. What was built

### New modules
- **`app/services/dns_resolver.py`** — `DNSResolver`: dnspython wrapper with `DNS_TIMEOUT_S` (3s) lifetime per query; LRU cache (`DNS_CACHE_MAX`=512 entries, TTL-bounded 300s, negative answers cached too); per-domain circuit breaker (5 failures / 60s window → open 120s; NXDOMAIN/NoAnswer are *valid negative answers* and never trip it); injectable transport for tests; `DNS_OFFLINE=true` raises `DNSUnavailable` before any I/O; `LookupBudget` implements the RFC 7208 cap of 10 DNS lookups per SPF check (violations → `permerror`, never a fake verdict).
- **`app/services/auth_verifier.py`** — `verify_spf` (pyspf when the default dnspython transport is in use, else a limited ip4/ip6/a/mx/include/exists/redirect/all evaluator), `verify_dkim` (dkimpy crypto verify with key retrieval through our resolver), `verify_dmarc` (`_dmarc.<domain>` with org-domain fallback, p= parsing, RFC 7489 relaxed/strict alignment for SPF envelope-from and DKIM d=), `verify_all`, `verify_or_parse` (realtime entry), `manual_auth_section` (manual entry).

### Scoring (independent source)

| Signal | Risk |
|---|---|
| SPF fail / softfail | +30 / +15 |
| DKIM fail (crypto) | +25 |
| DMARC fail, p=reject / p=quarantine / p=none | +35 / +25 / +10 |
| Alignment fail (enforcing policies p=reject/quarantine only) | +20 |
| All pass | 0 |

### The two rules that matter

1. **unavailable ≠ pass.** Offline mode, DNS failure, circuit breaker open, missing deps (`dnspython`/`dkimpy`/`pyspf` guarded imports), no sender IP, no headers — every one yields `status: "unavailable"`, risk 0, and an `auth_<x>_unavailable` **info** indicator. Risk 0 from "couldn't check" is semantically different from risk 0 from "verified clean", and the indicator list makes that visible.
2. **pass ≠ safe.** Any verification pass appends to the explanation: *"auth pass does not prove benign — compromised legitimate accounts pass SPF/DKIM/DMARC."* A CEO-fraud wire request from the real mail server passes every check.

### Wiring
- **Realtime** (`analysis_service.process_email_analysis`): runs `verify_or_parse` in a thread; `source="independent"` results merge their indicators and raise `combined_heur_score` monotonically (`max()`, can never lower). If independent verification is unavailable, the fetch-time Authentication-Results parse is used and marked `source="mx_parsed"` (visible in `signals.auth_verification.source` and `scan_details.engine_results.auth.verification`). The mx_parsed fallback applies the same scoring table (dmarc fail at the worst-case +35 because the policy is unknown at parse time).
- **Manual** (`POST /analysis/email`): optional `raw_headers` field. Supplied → full `verify_all` against the header block (raw bytes = headers + body) and the verification risk raises the alert score via `min_score` (monotonic). Absent → `auth_headers_missing` info indicator, explanation + `AlertResponse.warnings` flag *"SPF/DKIM/DMARC cannot be verified: manual text scan carries no message headers"*. **Absence is never treated as a pass.**
- **DKIM reconstruction caveat**: the realtime path only has normalized headers + sanitized body text. A signature that fails against the *reconstructed* message is reported `unavailable` ("normalization may have altered signed bytes"), never `fail` — otherwise every legit Gmail email would score a false +25. `fail` is only issued when the actual raw bytes were available (manual `raw_headers`, or tests).
- **Alignment bonus scope**: +20 only when DMARC policy enforces (p=reject/quarantine). p=none domains opted out of enforcement, so their misalignment is fully covered by the +10.

### Config (`app/core/config.py`)
`AUTH_VERIFY_ENABLED=True`, `DNS_TIMEOUT_S=3`, `DNS_CACHE_MAX=512`, `DNS_OFFLINE=False`, `SPF_MAX_DNS_LOOKUPS=10`, `DNS_CB_FAILURE_THRESHOLD=5`, `DNS_CB_WINDOW_S=60`, `DNS_CB_OPEN_S=120`.

The pytest harness (`tests/conftest.py`) sets `DNS_OFFLINE=true` by default: the whole suite runs with zero DNS I/O and realtime analysis exercises the mx_parsed fallback. Auth-specific tests inject fake transports and override offline per-resolver.

### Dependencies (`pyproject.toml`)
New optional extra `auth` = `dnspython`, `dkimpy`, `pyspf`, **mirrored into the `dev` dependency group** because `uv run` prunes optional extras. All three imports are guarded; any missing library degrades that check to `unavailable`.

## 4. Why the manual path is structurally blind without raw_headers

SPF verifies the connecting IP against the envelope-from domain's DNS policy; DKIM re-computes body/header hashes and validates the signature; DMARC needs the From domain plus those two results. All three inputs (IP, envelope-from, signed byte stream) exist only in the SMTP layer. A paste-box request that carries `subject`, `sender`, `body` has **none** of them — no code path, however clever, can verify authentication from message content alone. The design consequence is not "skip auth checks silently" but to *surface the blindness*: the `auth_headers_missing` indicator and response warning tell the analyst that this scan type cannot authenticate the sender, so content verdicts must carry the decision alone.
