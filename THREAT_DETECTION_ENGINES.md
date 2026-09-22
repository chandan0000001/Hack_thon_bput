# CYBERGUARD — Threat Detection Engines

CYBERGUARD ships **six enterprise detection engines** behind one shared analytical spine: transparent heuristics, high-performance ML models, a monotonic fusion rule, severity banding, and Explainable-AI (XAI) threat intelligence. This document details each engine's inputs, signals, algorithms, thresholds, failure modes, and mitigation strategies.

**Related documents:** [ARCHITECTURE.md](ARCHITECTURE.md) · [ML_MODELS.md](ML_MODELS.md) · [API_DOCUMENTATION.md](API_DOCUMENTATION.md) · [DATA_MODEL.md](DATA_MODEL.md) · [DECISIONS.md](DECISIONS.md)

## Table of Contents

1. [The Shared Detection Spine](#1-the-shared-detection-spine)
2. [Engine 1 — Phishing & Social Engineering](#2-engine-1--phishing--social-engineering)
3. [Engine 2 — Malicious URL Forensics](#3-engine-2--malicious-url-forensics)
4. [Engine 3 — BEC & Impersonation](#4-engine-3--bec--impersonation)
5. [Engine 4 — ATO & Identity Defense](#5-engine-4--ato--identity-defense)
6. [Engine 5 — Network Flow & API Abuse](#6-engine-5--network-flow--api-abuse)
7. [Engine 6 — Deepfake & Media Forensics](#7-engine-6--deepfake--media-forensics)
8. [Confidence Scoring & Severity Bands](#8-confidence-scoring--severity-bands)
9. [False-Positive Mitigation](#9-false-positive-mitigation)
10. [Explainable AI (XAI) Layer](#10-explainable-ai-xai-layer)
11. [Engine Comparison Matrix](#11-engine-comparison-matrix)
12. [FAQ](#12-faq)

---

## 1. The Shared Detection Spine

Every engine, regardless of entry point (interactive API, mailbox scanning, real-time workers, org gateway), passes through the same pipeline. This is why a verdict is always reproducible: the same message submitted twice — via any route — produces the same score.

```mermaid
flowchart TB
    IN(["Raw telemetry"]) --> NORM["Normalization<br/>(NormalizedMessage / typed schemas)"]

    NORM --> HEUR["Heuristic Engine<br/>transparent, severity-tagged indicators"]
    NORM --> ML["ML Predictor<br/>(where a trained model exists)"]

    HEUR --> SPLIT["split_ml_indicator<br/>ML signals scored separately"]
    ML --> SPLIT

    SPLIT --> FUSE["Monotonic Hybrid Fusion<br/>final = max(heuristic,<br/>round(0.45·heuristic + 0.55·ml_prob·100))"]

    FUSE --> BAND["Severity Bands<br/>safe ≤20 · low ≤40 · medium ≤60 ·<br/>high ≤80 · critical ≤100"]

    BAND --> XAI["XAI Layer<br/>(Groq → Gemini → OpenRouter → rules)"]
    BAND --> PERSIST["Event → ScanResult → Alert<br/>+ RecommendedActions"]

    XAI --> PERSIST
    PERSIST --> SOAR{"Corroboration gate:<br/>critical AND ≥2 engines high/critical?"}
    SOAR -->|Yes| ACT["Auto-enforcement"]
    SOAR -->|No| REC["Recommend-only"]
```

### Fusion Semantics

```mermaid
flowchart LR
    subgraph Cases["Worked Examples"]
        A["heuristic 60 · ML 90<br/>→ max(60, 0.45·60+0.55·90) = <b>76</b><br/>ML lifts weak heuristics"]
        B["heuristic 90 · ML 40<br/>→ max(90, 0.45·90+0.55·40) = <b>90</b><br/>ML can never lower a verdict"]
        C["heuristic 10 · ML 5<br/>→ max(10, 7) = <b>10</b><br/>benign stays benign"]
    end
```

**Why monotonic blending?** Heuristics are transparent and auditable but miss novel attacks; ML generalizes but can confidently hallucinate. The `max()` rule keeps the safety property "a crisp rule-based verdict (IP-hosted credential form) can never be overruled by a model's false negative" while still letting genuine model strength raise weak heuristic scores. Decision record: [DECISIONS.md](DECISIONS.md), invariant I1.

---

## 2. Engine 1 — Phishing & Social Engineering

**Module:** `phishing` · **Service:** `app/services/phishing_detector.py` · **ML:** `email_phishing_xgb_v2.pkl` + `email_tfidf_v2.pkl` · **Endpoint:** `POST /api/v1/analysis/email` · **MITRE:** T1566.001 (Spearphishing Attachment), T1566.002 (Spearphishing Link)

### Pipeline

```mermaid
flowchart TB
    IN["sender · subject · body<br/>channel: email (default) | sms"] --> BRAND["Brand Lookalike Analysis<br/>11 brands: microsoft · paypal · google · amazon ·<br/>apple · facebook · netflix · dhl · fedex · hsbc · wellsfargo<br/>leet-tolerant regexes: o→[o0] i→[i1l!|] …"]
    IN --> URGENCY["Urgency keywords<br/>urgent · immediately · suspend · verify"]
    IN --> CRED["Credential request phrases<br/>(7 phrases, e.g. 'verify password')"]
    IN --> THREAT["Threat language<br/>(6 phrases, e.g. 'account will be terminated')"]
    IN --> FIN["Financial vocabulary<br/>payment · wire transfer (FP-hardened)"]
    IN --> BODYURL["Body URL forensics"]
    IN --> SMS["SMS-only heuristics<br/>(gated on channel == 'sms')"]

    BODYURL --> B1["ip_url_in_body (critical)"]
    BODYURL --> B2["suspicious_tld_in_body (critical)<br/>xyz · top · zip · click · link · work · loan · cam · rest"]
    BODYURL --> B3["insecure_link (high)<br/>vs insecure_link_hygiene (low)<br/>when host is Umbrella top-1M"]

    SMS --> S1["sms_shortcode (5–6 digit)"]
    SMS --> S2["sms_spam_keyword (UCI-style vocab)"]
    SMS --> S3["high_digit_ratio (>0.15, ≥5 digits)"]
    SMS --> S4["all_caps_text (4+ consecutive caps words)"]

    BRAND & URGENCY & CRED & THREAT & FIN & BODYURL & SMS --> SPLIT
    IN --> ML["XGBoost v2 over char n-gram (2–4) TF-IDF<br/>multilingual: en + hi + te + or + romanised"]
    SPLIT --> FUSE["monotonic blend"] --> OUT["risk_score · severity · indicators<br/>→ XAI with T1566 mapping"]
```

### Indicator Catalog

| Indicator | Severity | Trigger |
|---|---|---|
| `lookalike_domain` | critical | Sender domain matches a leet-tolerant pattern of a protected brand (e.g. `micr0soft-verify.xyz`) |
| `credential_request` | critical | Any of 7 credential-harvesting phrases |
| `ip_url_in_body` | critical | Body links to a raw IP host |
| `suspicious_tld_in_body` | critical | Body link uses a high-abuse TLD |
| `urgency` | high | Urgency keyword present |
| `threat_language` | high | Termination/suspension phrasing |
| `insecure_link` | high | http:// link not on the top-1M whitelist |
| `financial_vocabulary` | medium | Payment/wire language (deliberately FP-hardened) |
| `insecure_link_hygiene` | low | http:// on a whitelisted top-1M host |
| `sms_*` family | varies | Only for `channel="sms"` — shortcode, phone number, spam vocab, digit ratio, caps |

**Strengths / limitations:** the heuristic layer catches evasive lookalikes that fool token-level ML (leet substitutions), while the multilingual char-n-gram model covers novel phrasing and four Indic languages plus romanised Hinglish. Evaluation: hybrid F1 **0.9842** on 24,000 held-out emails; the SMS corpus is documented as out-of-domain for the text model.

---

## 3. Engine 2 — Malicious URL Forensics

**Module:** `url` · **Service:** `app/services/url_detector.py` · **ML:** `url_xgb_v3.1.pkl` (served version selected via `calibration.json → url_model_version`) · **Endpoint:** `POST /api/v1/analysis/url` · **Features:** `ml/url_features_v3.py` (shared training + serving)

### Pipeline

```mermaid
flowchart TB
    URL(["URL string"]) --> LEX["Lexical Heuristics (11)"]
    URL --> REP["Reputation & Shape Layer"]
    URL --> V3["19-Feature v3 Vector"]

    subgraph LEX
        L1["ip_host (critical)"]
        L2["brand_in_subdomain (critical) — 12 brand names"]
        L3["suspicious_tld (high) · insecure_scheme (high)"]
        L4["executable_extension (high) — exe · zip · scr · php · js · IoT arch"]
        L5["urlhaus_pattern (high) — ru/cn/top/xyz + path >20 chars"]
        L6["url_length >75 (medium) · entropy >4.0 (medium)"]
        L7["suspicious_path_keyword (medium) — login · verify · secure · signin · update · account"]
        L8["random_path_segment (medium, ≥10 mixed alnum, entropy>3.0)"]
        L9["excessive_digits (medium, ratio>0.3, ≥5 digits)"]
    end

    subgraph REP
        R1["Cisco Umbrella top-1M whitelist<br/>(ml/data/url_whitelist/top1m.txt)"]
        R2["Path-shape classifier:<br/>uuid-like | hex32-like | short-id | homepage | other"]
    end

    V3 --> XGB["XGBoost v3.1<br/>AUC 0.9985 · F1 0.9795 (n=109,000)"]
    LEX --> SPLIT
    XGB --> SPLIT
    SPLIT --> FUSE["monotonic blend"] --> OUT
```

The 19 v3 features (`FEATURE_COLUMNS_V3`): `is_top_1m, domain_entropy, path_entropy, query_entropy, domain_length, path_length, query_length, total_length, has_tracking_params, num_query_params, has_ip, num_dots, num_subdomains, has_at_symbol, suspicious_tld, http_only, domain_digit_ratio, domain_hyphens, has_suspicious_path_keyword`.

**Why shared feature code matters:** training and serving import the *same* `url_features_v3.py` and `url_reputation.py`, eliminating training-serving skew by construction rather than by process discipline.

**Version lineage:** v1 (8 lexical features) → v2 (+ top-1M reputation + path-shape, 14 features) → v3 (19 features, trained on the mitchellkrogza active phishing feed with 50k real Umbrella benign domains) → v3.1 (+ brand-secondary benign augmentation to cut false positives on legit deep links). Rollback = edit `url_model_version` in `calibration.json`; the loader falls back gracefully if an artifact is missing.

---

## 4. Engine 3 — BEC & Impersonation

**Module:** `impersonation` · **Service:** `app/services/impersonation_detector.py` · **ML:** none (deliberately heuristic-only) · **Endpoint:** `POST /api/v1/analysis/impersonation`

```mermaid
flowchart LR
    MSG["message + claimed_identity"] --> C1["authority_identity (high)<br/>CEO · CFO · director · principal · bank ·<br/>IRS · IT support + acronyms on word boundaries"]
    MSG --> C2["pressure_language (high)<br/>urgent · immediately · do not question ·<br/>confidential · asap"]
    MSG --> C3["unusual_request (critical)<br/>gift card · wire transfer · bitcoin ·<br/>bypass procedure · share codes"]
    MSG --> C4["secrecy_request (high)<br/>'don't tell anyone' · 'keep this between us'"]
    C1 & C2 & C3 & C4 --> SCORE["scoring_service (heuristic-only)"] --> OUT["severity + XAI<br/>(heuristic fallback explanation on the ingest path)"]
```

**Why no ML here?** BEC volume is low and payloads are short; the four request-shaped signals are near-deterministic and fully explainable. A model trained on tiny BEC corpora would add opacity without recall. On the log-ingest path the detector runs **without any LLM call** — provider latency must never delay ingestion (ORG-2 decision); explanations use the deterministic fallback.

Calibration keyword sets (including `request_indicators` for the org gateway: payment_request, status_confirmation, urgency, secrecy, channel_change) live in the hot-reloaded `ml/calibration.json` under the `impersonation` key.

---

## 5. Engine 4 — ATO & Identity Defense

**Module:** `account_takeover` · **Service:** `app/services/account_takeover_detector.py` · **ML:** none (stream logic) · **Endpoint:** `POST /api/v1/analysis/account-takeover`

```mermaid
flowchart TB
    EVENTS(["auth events grouped per user,<br/>sorted by timestamp"]) --> T1["failed_login_burst (high)<br/>≥3 failures (FAILED_BURST_THRESHOLD)"]
    EVENTS --> T2["impossible_travel (critical)<br/>two successful logins from different locations<br/><60 min apart (IMPOSSIBLE_TRAVEL_WINDOW_MINUTES)"]
    EVENTS --> T3["success_after_failures (high)<br/>≥2 consecutive failures then success<br/>(CONSECUTIVE_FAILURES_BEFORE_SUCCESS)"]
    EVENTS --> T4["new_device (medium) · suspicious_device (medium)<br/>device tokens: 'linux' · 'unknown'"]
    T1 & T2 & T3 & T4 --> OUT["indicators → policy verbs:<br/>block → revoke_session<br/>warn_and_log → require_mfa<br/>(action_executor refinement map)"]
```

**Input shape:** a list of auth-event dicts (timestamp, user, ip, location, device, outcome) — the same shape the org log plane auto-detects from pasted auth logs (`user`+`ip`(+`status`/`location`) field signature). MITRE mapping: T1110 (Brute Force).

**Why stream logic instead of ML?** The signals are temporal relations (velocity, sequencing) that a per-event classifier cannot see; grouping and ordering *is* the model. Thresholds are calibration knobs, not learned weights, so a SOC can tighten them per deployment via enforcement policies.

---

## 6. Engine 5 — Network Flow & API Abuse

**Module:** `network` (flows) / `api_abuse` (API logs) · **Service:** `app/services/network_threat_detector.py` · **ML:** `network_xgb.pkl` + `network_scaler.pkl` (KDD99-SF, 4 features) · **Endpoint:** `POST /api/v1/analysis/network`

```mermaid
flowchart TB
    IN(["flows[] + api_logs[]"]) --> H1["potential_exfiltration (high)<br/>bytes > 10 MB (EXFIL_BYTES_THRESHOLD)"]
    IN --> H2["suspicious_port (critical)<br/>4444 · 8888 · 1337 · 31337 · 6667"]
    IN --> H3["api_rate_abuse (high)<br/>>50 requests per source IP"]
    IN --> H4["repeated_api_auth_failures (high)<br/>>5 HTTP 401s per source IP"]

    IN --> MAP["KDD99-SF 4-feature mapping per flow:<br/>f1 = service from PORT_TO_SERVICE map<br/>(80/443/8080→http · 25/587/465→smtp · 22→ssh …)<br/>+ log-scaled duration/bytes with documented constants"]
    MAP --> XGB["network_xgb.pkl probability per flow<br/>max flow probability drives the ML indicator"]
    H1 & H2 & H3 & H4 --> SPLIT
    XGB --> SPLIT --> FUSE["monotonic blend"] --> OUT
```

**Known calibration finding (recorded, not hidden):** per-flow heuristics are blind to low-and-slow beaconing, and the KDD99-SF feature vector uses documented constants for fields the platform does not ingest (duration → ln(0.1)); flows lacking `bytes_out` produce an `ml_warning` indicator instead of a silent guess. The evaluation harness measures this honestly (P 1.0 / R 0.666 on scenario data) rather than masking the gap.

---

## 7. Engine 6 — Deepfake & Media Forensics

**Module:** `deepfake` · **Services:** `deepfake_detector.py` + `media_forensics/` (image/video/audio analyzers) · **ML:** `deepfake_cnn_v2.pt` (MobileNetV3-Small, 128 px), `audio_cnn_v1.pt` (LCNN log-Mel) · **Endpoint:** `POST /api/v1/analysis/media` (multipart, max 25 MB) · **Storage:** Supabase `cyberguard-media` (private, 1-hour signed URLs) with local-disk fallback

### Forensic Pipeline

```mermaid
flowchart TB
    UPLOAD(["media file ≤25 MB"]) --> TYPE{"Modality"}

    TYPE -->|image| IMG["ImageAnalyzer — Error Level Analysis:<br/>JPEG q90 re-encode · 8×8 block error map →<br/>mean_error · block_variance · splice_score<br/>(max of top-5%/median ratio, bottom-block ratio)"]
    TYPE -->|video| VID["VideoAnalyzer — 10 evenly spaced frames:<br/>per-frame ELA · temporal variance (>20 abnormal) ·<br/>mean ELA (>8.0 high) · FPS sanity (5–120)"]
    TYPE -->|audio| AUD["AudioAnalyzer — WAV signal stats:<br/>clipping >2% at 99.9% full scale (high) ·<br/>ZCR variance <1e-4 (medium) ·<br/>spectral holes ratio >0.6 (60 dB floor) · flatness <0.05<br/>non-WAV → deterministic SHA-256 simulated score<br/>(flagged simulated=true)"]

    UPLOAD --> CNN["CNN branch:<br/>deepfake_cnn_v2 (GenImage: SD v1.4 + Midjourney fakes<br/>vs clean + messenger-degraded reals)<br/>audio LCNN (ASVspoof 2019 LA crops)<br/>video: CNN averaged over ≤5 frames"]

    IMG --> POL
    CNN --> POL{"CNN vs ELA disagreement policy"}

    POL -->|"CNN real (<0.10) + weak ELA (splice<4.0)"| CAP["cap probability 0.35 ·<br/>indicator ela_weak_splice_unconfirmed (low)"]
    POL -->|"CNN real + strong ELA (≥4.0)"| OVR["ELA overrides CNN"]
    POL -->|"CNN suspicious (≥0.10)"| BLEND["max(ela, 0.5·ela + 0.5·cnn)"]

    CAP & OVR & BLEND --> FINAL["probability → risk_score =<br/>max(round(prob·100), heuristic indicator score)<br/>CNN-real + no strong splice → risk capped at 40"]
    FINAL --> OUT["indicators + XAI<br/>(deepfake prompt requires<br/>'Flag multimedia for manual verification'<br/>when manipulation_probability > 0.5)"]
```

### Image Probability Composition

```
P = 0.05 (base)
  + min(0.55, (splice_score / 3.0)² × 0.40)   — block-variance term
  + 0.20 (container mismatch: extension ≠ decoded format)
  + 0.10 (uniform error map: mean<0.2 AND block_var<0.005)
  → capped at 0.95
```

**Why the disagreement policy matters:** the CNN was trained on GenImage generators; a real photo compressed by a messaging app (the `real_messenger` training subclass, FPR 2.2%) can still look synthetic to the CNN, and conversely a strong splice is forensic evidence no CNN sees. Capping CNN-real verdicts at risk 40 and letting strong ELA override prevents the two failure modes documented in `deepfake_v2_metrics.json` (per-generator recall: StableDiffusion 91.9%, Midjourney 74.3%).

**Audio domain-shift caveat (documented in the XAI prompt):** the LCNN was trained on ASVspoof 2019 attacks; modern neural TTS (ElevenLabs-class) is partly out of domain — the prompt instructs the LLM to state this caveat, and the non-speech tone cap limits model contribution to 0.35 on tonal content.

---

## 8. Confidence Scoring & Severity Bands

```mermaid
flowchart LR
    IND["indicators<br/>(severity-tagged)"] --> W["Weighted sum<br/>SEVERITY_WEIGHTS:<br/>critical 25 · high 15 · medium 5<br/>(calibration.json variant: 25/16/5)"]
    W --> CAP["capped at 100"]
    CAP --> BAND{"Band"}
    BAND -->|"0–20"| SAFE["safe"]
    BAND -->|"21–40"| LOW["low"]
    BAND -->|"41–60"| MED["medium"]
    BAND -->|"61–80"| HIGH["high"]
    BAND -->|"81–100"| CRIT["critical"]
```

- The **adaptive positive threshold** (midpoint of class means) is used by the evaluation harness for engines whose score ranges sit below 50; threshold-free AUC is the headline metric.
- The `ml_model` indicator itself carries `probability` (0–1) and does not contribute to the heuristic sum — it enters only through the monotonic blend.
- Deepfake/media uses `manipulation_probability ≥ 0.5` as its flag threshold (evaluation convention).

**Enforcement thresholds** (per-module, from `enforcement_policies`): phishing/url high 75 · medium 40; deepfake 70/50; ATO 60/40; network 70/50; impersonation 70/40. Default policy: critical → `block_and_quarantine`, high → `block`, medium → `warn_and_log`, low → `allow`.

---

## 9. False-Positive Mitigation

| Mechanism | Engines | How It Works |
|---|---|---|
| Umbrella top-1M whitelist | URL, phishing body links | Legit top-1M hosts demote `insecure_link` → low-severity hygiene signal; v3/v3.1 models train on 50–59k real benign domains |
| Path-shape features | URL | `uuid-like`/`hex32-like` deep links on benign platforms stop looking like random malicious paths (v3.1's brand-secondary augmentation targeted exactly this FP class) |
| FP-hardened vocabularies | Phishing | `financial_vocabulary` downgraded to medium; hygiene vs threat split for insecure links |
| Leet-tolerant brand regexes | Phishing | Only *lookalike* brand domains fire (critical) — the real brand domain never matches |
| Trusted-sender feedback loop | All email vectors | Release + Trust adds the sender to `trusted_senders`; future mail from them is recommend-only with the annotation "You previously released a message from this sender." |
| Corroboration gate | Auto-enforcement | A single engine's critical score never triggers a real mailbox write — critical severity AND ≥2 engines high/critical is required |
| Disagreement caps | Deepfake/audio | CNN-real verdicts cap risk at 40 absent strong ELA; non-speech audio caps model contribution at 0.35 |
| Honest simulation flags | Org mail connectors | `SimulationTransport` results always carry `"simulated": true` — a detection is never laundered into a false enforcement claim |
| Evaluation harness | All | Findings (URL v2 top-1m FPs, low-and-slow blindness, SMS out-of-domain) are recorded in reports, not silently patched |

---

## 10. Explainable AI (XAI) Layer

The XAI layer turns a numeric verdict into an analyst-readable explanation with MITRE ATT&CK mapping — and it can never contradict the verdict:

```mermaid
flowchart TB
    VERDICT(["module + risk_score +<br/>severity + indicators"]) --> PROMPT["prompt_templates<br/>7 system prompts (strict JSON output:<br/>{explanation, mitre_techniques[], recommended_actions[]})<br/>+ 'EVALUATED VERDICT: RISK SCORE x/100'<br/>alignment block + severity-prefix rules"]
    PROMPT --> ROTATE["Provider chain (key rotator):<br/>Groq → Gemini → OpenRouter<br/>per-provider model fallbacks ·<br/>temperature 0.1 · 10–20 s timeouts"]
    ROTATE --> CHECK{"Severity-consistency check"}
    CHECK -->|"verdict safe"| WIPE["MITRE wiped · contradictory<br/>explanation rewritten"]
    CHECK -->|"consistent"| PASS["explanation accepted"]
    ROTATE -->|"all keys down / timeout"| RULES["Deterministic rule-based generator<br/>module-specific MITRE + actions<br/>(phishing → T1566.001/.002)"]
    WIPE & PASS & RULES --> OUT["explanation on Alert / ScanResult<br/>rendered by ExplanationPanel in the UI"]
```

Key guarantees:

1. **Deterministic fallback** — if every LLM key is down (circuit breaker state), `generate_heuristic_explanation` produces a module-specific explanation. Platform availability does not depend on any external provider.
2. **Severity consistency enforcement** — a `safe` verdict can never ship with MITRE techniques attached; the layer rewrites contradictory LLM output.
3. **Key rotation with circuit breaking** — 429/401/402/403 → key quarantined (60 s cooldown); background probes every 30 s re-release recovered keys; up to 10 keys per provider round-robin.
4. **Ingest-path honesty** — the org log plane never calls the LLM during ingestion; only promoted alerts get (fallback) explanations.

---

## 11. Engine Comparison Matrix

| Engine | ML Model | Heuristic Signals | MITRE Mapping | Latency (p95) | Notable Limitation |
|---|---|---|---|---|---|
| Phishing | XGBoost v2 + char-n-gram TF-IDF (multilingual) | 10+ incl. SMS-only family | T1566.001/.002 | <10 ms (heuristics) | SMS corpus out-of-domain for the text model |
| URL Forensics | XGBoost v3.1 (19 features, AUC 0.9985) | 11 lexical + reputation/shape | T1566.002, T1071 | 3.7 ms | documented single FN on shortened lookalike (`lnk.ink`) |
| BEC / Impersonation | none | 4 request-shaped checks | T1534 / internal mapping | <10 ms | relies on explicit phrasing; terse BEC may score low |
| ATO | none | 5 temporal-stream rules | T1110 | <10 ms | needs location/device fields in auth events |
| Network / API Abuse | XGBoost (KDD99-SF, 4 features) | 4 + per-flow ML | T1071, T1041-class | 33.9 ms | no low-and-slow beaconing detection |
| Deepfake / Media | MobileNetV3-Small v2 + LCNN audio | ELA / frame-sampling / spectral | manual-verification recommendation | seconds (frame sampling) | Midjourney recall 74.3%; ASVspoof domain shift vs modern TTS |

---

## 12. FAQ

**Q: Which engines feed the auto-quarantine decision?**
Any engine producing a ScanResult can, but the corroboration gate requires critical severity **and** ≥2 engines at high/critical. In the real-time email pipeline, the analysis worker auto-enforces when classification is `phishing` or risk ≥ 0.7, then the same gate applies.

**Q: Can I add my own heuristic without touching ML?**
Yes — indicators are data. Append a severity-tagged indicator to the engine's output list; scoring, fusion, XAI, alerting, and policy evaluation pick it up automatically.

**Q: How do I tune thresholds without code changes?**
Two knobs: `ml/calibration.json` (hot-reloaded: keyword sets, deepfake thresholds, scoring weights) and `enforcement_policies` rows (per-module high/medium thresholds and per-band actions) via `PUT /api/v1/policies/{id}`.

**Q: Why does the URL model default to v2 in `calibration.json` when v3.1 exists?**
`url_model_version` is a rollout control. v3/v3.1 artifacts are trained and validated (AUC 0.9987/0.9985); switching the key is a one-line, instantly reversible promotion. The served model falls back down the version chain if an artifact is missing.

**Q: Are detection results deterministic?**
Yes for heuristics + ML (temperature-independent, fixed artifacts). The LLM explanation is generation-varied but always post-validated for severity consistency; with all providers down, the fallback is fully deterministic.
