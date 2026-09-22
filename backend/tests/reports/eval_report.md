# CYBERGUARD Evaluation Harness Report

- Generated: 2026-09-22T17:08:27.978574+00:00
- Git tip: a488a1f
- Scale option: default
- Data mode: auto

## Per-engine metrics

| Engine | Cases | Positives | Precision | Recall | F1 | AUC | Malicious mean | Benign mean | Band gap | MW p-value |
|---|---|---|---|---|---|---|---|---|---|---|
| account_takeover | 2000 | 1000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 24.19 | 0.00 | 24.19 | 0.0000 |
| impersonation | 600 | 300 | 0.7236 | 0.8900 | 0.7982 | 0.8577 | 24.42 | 5.10 | 19.32 | 0.0000 |
| media_forensics | 400 | 200 | 1.0000 | 0.9350 | 0.9664 | 0.9350 | 68.55 | 46.00 | 22.55 | 0.0000 |
| network | 2000 | 1000 | 1.0000 | 0.6660 | 0.7995 | 0.8330 | 13.38 | 0.00 | 13.38 | 0.0000 |
| phishing_text | 1100 | 202 | 1.0000 | 0.3663 | 0.5362 | 0.9055 | 37.60 | 2.61 | 34.99 | 0.0000 |
| marketing_fp_check | 10 | 0 | 0.0000 | 0.0000 | 0.0000 | nan | nan | 30.00 | nan | nan |
| phishing_auto_enforce_check | 3 | 3 | 1.0000 | 1.0000 | 1.0000 | nan | 100.00 | nan | nan | nan |
| url_detector_blended | 800 | 300 | 0.8845 | 0.8933 | 0.8889 | 0.9548 | 34.17 | 6.59 | 27.58 | 0.0000 |
| url_detector_heuristic_only | 800 | 300 | 0.6930 | 0.5267 | 0.5985 | 0.7659 | 11.40 | 3.63 | 7.77 | 0.0000 |

## Property tests

- http_analysis_requests: requests=60, ok=60
- monotonic_blend_emails: checked=300, lowered=0
- monotonic_blend_urls: checked=1000, violations=0
- split_ml_round_trip: cases=1000, mismatches=0

## HTTP latency (sampled analysis requests)

- `/api/v1/analysis/email`: n=20 p50=20.6ms p95=28.5ms p99=28.5ms
- `/api/v1/analysis/url`: n=20 p50=1109.2ms p95=6453.0ms p99=6453.0ms
- `/api/v1/analysis/account-takeover`: n=10 p50=16.4ms p95=23.0ms p99=23.0ms
- `/api/v1/analysis/network`: n=10 p50=19.2ms p95=29.4ms p99=29.4ms

## Data provenance

| Source | Mode | Rows | SHA256 | Fetched at |
|---|---|---|---|---|
| sms_spam | cache | 5572 | —… | 2026-09-22T17:09:40.986569+00:00 |
| sms_spam | cache | 5572 | —… | 2026-09-22T17:09:43.027589+00:00 |
| phishing_urls | cache | 300 | —… | 2026-09-22T17:10:19.847195+00:00 |

## Findings (bugs discovered by the harness — NOT fixed)

- honesty: provider 403 correctly surfaced as insufficient_scope
- impersonation FN: FN payload={'message': 'This is HR department. Email me the employee payroll list right away, do not tell anyone.', 'claimed_identity': 'HR department'} score=0 indicators=[]
- impersonation FN: FN payload={'message': 'This is HR department. Email me the employee payroll list right away, do not tell anyone.', 'claimed_identity': 'HR department'} score=0 indicators=[]
- impersonation FN: FN payload={'message': 'This is the IT helpdesk. Email me the employee payroll list right away, do not tell anyone.', 'claimed_identity': 'the IT helpdesk'} score=0 indicators=[]
- impersonation FN: FN payload={'message': 'This is HR department. Email me the employee payroll list right away, do not tell anyone.', 'claimed_identity': 'HR department'} score=0 indicators=[]
- impersonation FN: FN payload={'message': 'This is HR department. Email me the employee payroll list right away, do not tell anyone.', 'claimed_identity': 'HR department'} score=0 indicators=[]
- phishing_text recall is corpus-limited: the online SMS Spam corpus is out-of-domain for URL/credential-heavy email heuristics (SMS ham also scores 0, precision stays 1.0). Synthetic email templates score high. See phishing_text metrics.
- phishing FN: FN payload={'sender': 'unknown@sms', 'subject': '(sms)', 'body': "FreeMsg Hey there darling it's been 3 week's now and no word back! I'd like some fun you up for it still?… score=0 indicators=['ml_model:safe']
- phishing FN: FN payload={'sender': 'unknown@sms', 'subject': '(sms)', 'body': 'England v Macedonia - dont miss the goals/team news. Txt ur national team to 87077 eg ENGLAND to 87077 Tr… score=35 indicators=['sms_shortcode:high', 'sms_spam_keyword:high', 'high_digit_ratio:medium', 'ml_model:safe']
- phishing FN: FN payload={'sender': 'unknown@sms', 'subject': '(sms)', 'body': 'Thanks for your subscription to Ringtone UK your mobile will be charged £5/month Please confirm by replyi… score=45 indicators=['sms_spam_keyword:high', 'sms_spam_keyword:high', 'sms_spam_keyword:high', 'ml_model:low']
- phishing FN: FN payload={'sender': 'unknown@sms', 'subject': '(sms)', 'body': 'SMS. ac Sptv: The New Jersey Devils and the Detroit Red Wings play Ice Hockey. Correct or Incorrect? End?… score=0 indicators=['ml_model:safe']
- phishing FN: FN payload={'sender': 'unknown@sms', 'subject': '(sms)', 'body': 'As a valued customer, I am pleased to advise you that following recent review of your Mob No. you are awa… score=30 indicators=['sms_phone_number:high', 'sms_spam_keyword:high', 'ml_model:low']
- FP-hardening marketing regression set (10 realistic digest/newsletter/transactional emails incl. the Medium digest payload and the mediumday.com event-reg token URL): all must stay <= medium and fail the corroboration gate (review_recommended, no provider write).
- FP-hardening phishing positive control: brand-lookalike, IP-host and platform-hosted phishing must still trip corroboration (>=2 engines high+) and land on the auto-quarantine path.
- FIXED (url_xgb_v3): v2 scored benign top-1m domains at phishing probability ~0.76 (long tracking URLs). v3 retrains on 50k top-1M benign URLs (10k tracking-augmented) + 50k real Phishing.Database URLs with domain/path/query entropy split features — benign domains with long tracking query strings now score <0.05.
- Real OpenPhish URLs hosted on legitimate platforms (vercel.app, godaddysites.com) are structurally plain and score low on URL heuristics (heuristic-only AUC ~0.77); the v2 ML model detects them (blended AUC higher). This validates the hybrid design for platform-hosted phishing.
- url FN: FN payload=https://kqid7e1vkh3d0r88k3d.vercel.app/nsvw35re4hbarefsdbvzxcv score=35 indicators=['url_entropy:medium', 'random_path_segment:medium', 'ml_model:critical']
- url FN: FN payload=https://www.welcome-trezor-bridge.godaddysites.com/ score=20 indicators=['url_entropy:medium', 'ml_model:high']
- url FN: FN payload=https://iamivanaalawicash.blogspot.com/ score=25 indicators=['ml_model:critical']
- url FN: FN payload=https://www.iamivanaalawicash.blogspot.com/ score=25 indicators=['ml_model:critical']
- url FN: FN payload=https://lnk.ink/AQDO7 score=25 indicators=['ml_model:critical']
