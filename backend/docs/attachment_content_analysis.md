# Attachment Content Analysis — Phase 3 (ATTACH-SCAN-3)

Phase 3 adds the Level-3 content engines: PDF structural analysis, Office
macro/OLE inspection, URL extraction with hand-off to the platform's
existing URL engine, and text phishing analysis. All run inside
`AttachmentScanner._level3_content_analysis`, each individually guarded.

## Engines

| Engine | File | Dependency | Degrades to |
| --- | --- | --- | --- |
| PDF | `app/services/pdf_analyzer.py` | pypdf (read-only) | raw byte-stream keyword scan still runs; corrupt docs → `pdf_corrupt` +15 |
| Office | `app/services/office_analyzer.py` | stdlib zipfile; oletools optional | raw VBA-stream heuristic for legacy OLE |
| URLs | `app/services/attachment_url_extractor.py` | stdlib re | hand-off failure per-URL → unflagged with `error` |
| Text | `app/services/attachment_text_analyzer.py` | pypdf; bs4 optional (regex tag-strip fallback) | empty text → zero indicators |

## What each engine looks for

**PDF** (never executes anything): raw byte-stream scan for `/JavaScript`,
`/EmbeddedFile`, `/OpenAction` `/AA` `/Launch` (+25 / +20 / +25), page cap
(`MAX_PAGES_IN_PDF=100`, +10 above), and URL harvest from URI annotations,
URI actions, and visible text. A document pypdf cannot parse gets
`pdf_corrupt` (+15) instead of crashing the scan — obfuscation that breaks
parsers is itself a signal.

**Office**: OOXML packages are opened as zips — `vbaProject.bin` (+30,
`has_macros`), macro-enabled extensions (.docm/.xlsm/.pptm +15), external
relationship targets (hyperlink URLs harvested; OLE/package rels flagged
`office_external_object` +20). Legacy OLE docs: `office_encrypted` (+20) if
an EncryptionInfo stream is present (uninspectable content is a signal, not
a pass), VBA detection via oletools' `VBA_Parser.detect_vba_macros()` when
available, else the `_VBA_PROJECT`/`VBA`/`Macros` raw-stream heuristic.

**URLs**: deobfuscation (hxxp→http, `[.]`/`(.)`→`.`, one %-decode pass),
dedupe, cap `MAX_URLS_PER_ATTACHMENT=50`. Every URL is then handed to
`app.services.url_detector.analyze_url_heuristics` — the SAME engine that
scores URLs in email bodies — and weighted with
`scoring_service.calculate_score`. Flagged URLs become
`attachment_url_flagged` indicators (high if engine risk ≥ 25, else
medium); the URL channel's total contribution is capped at +30.

**Text**: visible text extraction capped at `MAX_TEXT_EXTRACT_CHARS=200_000`
(pypdf per page for PDF, XML text nodes for OOXML, BeautifulSoup tag-strip
for HTML with a regex fallback, raw for txt). Analysis imports the shared
phishing vocabulary from `app.services.phishing_detector`
(`CREDENTIAL_REQUEST_PHRASES`, `URGENCY_KEYWORDS`, `THREAT_LANGUAGE_PHRASES`,
`FINANCIAL_VOCABULARY`) — no duplicated keyword lists. Credential requests
weigh 10, other hits 5, and the whole text channel caps at +30.

## Reuse policy

Two existing engines are deliberately reused instead of rewritten:

1. **URL scoring** — `url_detector.analyze_url_heuristics` +
   `scoring_service.calculate_score`. Attachment URLs and body URLs now
   share one heuristic set, one ML blend, and one verdict vocabulary;
   future URL-engine improvements apply to attachments for free.
2. **Phishing vocabulary** — the keyword/phrase constants from
   `phishing_detector`. One tuning surface for analysts; attachment text
   cannot drift from email-body behavior.

## Risk caps (why text/URL cannot dominate)

| Channel | Cap | Rationale |
| --- | --- | --- |
| Text phishing | +30 | A page-long rant is *evidence*, not execution; structural signals (macros, JS) must outrank prose |
| URL hand-off | +30 | One attachment can carry 50 URLs; without a cap URL spam would auto-malicious everything |

Structural signals (ClamAV +90, disguise forced-malicious, macros +30,
PDF JS +25) stay uncapped: they are content, not prose.

## Isolation

Every sub-engine is wrapped in its own `try/except` inside
`_level3_content_analysis`; a crash records
`{type: "engine_error", engine, severity: "info"}` and the scan completes
with the surviving signals. The verdict is never downgraded by Level 3 — it
can only rise from the Level-2 verdict (`safe < suspicious < malicious`).

## Dependencies

`attachments` optional group (and dev group, since `uv run` prunes extras):
`pypdf>=4.0.0`, `oletools>=0.60.0` (optional at runtime), `beautifulsoup4>=4.12.0`
(optional at runtime). All engines degrade gracefully when a library is absent.

## Test coverage

`tests/test_content_analysis.py` (Suite 33, 15 assertions): PDF JS /
EmbeddedFile / OpenAction indicators, corrupt-PDF graceful handling, URI
annotation URL harvest; OOXML vbaProject, macro extension, external OLE
object, hyperlink URLs; hxxp/[.] deobfuscation; URL hand-off invoking the
real engine (mocked in test); credential+urgency text indicators; 200k-char
cap; engine isolation; full-pipeline malicious PDF verdict.
