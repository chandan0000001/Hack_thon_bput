# CYBERGUARD Evaluation Harness Report

- Generated: 2026-10-09T12:01:02.788687+00:00
- Git tip: 2fdc7da
- Scale option: default
- Data mode: auto

## Per-engine metrics

| Engine | Cases | Positives | Precision | Recall | F1 | AUC | Malicious mean | Benign mean | Band gap | MW p-value |
|---|---|---|---|---|---|---|---|---|---|---|
| phishing_text | 1100 | 202 | 1.0000 | 0.3663 | 0.5362 | 0.9055 | 37.60 | 2.61 | 34.99 | 0.0000 |
| marketing_fp_check | 10 | 0 | 0.0000 | 0.0000 | 0.0000 | nan | nan | 19.00 | nan | nan |
| phishing_auto_enforce_check | 3 | 3 | 1.0000 | 1.0000 | 1.0000 | nan | 96.67 | nan | nan | nan |

## Property tests

- monotonic_blend_emails: checked=300, lowered=0

## HTTP latency (sampled analysis requests)

- (no HTTP samples recorded)

## Data provenance

| Source | Mode | Rows | SHA256 | Fetched at |
|---|---|---|---|---|
| sms_spam | cache | 5572 | —… | 2026-10-09T12:01:04.773430+00:00 |
| sms_spam | cache | 5572 | —… | 2026-10-09T12:01:07.972735+00:00 |

## Findings (bugs discovered by the harness — NOT fixed)

- phishing_text recall is corpus-limited: the online SMS Spam corpus is out-of-domain for URL/credential-heavy email heuristics (SMS ham also scores 0, precision stays 1.0). Synthetic email templates score high. See phishing_text metrics.
- phishing FN: FN payload={'sender': 'unknown@sms', 'subject': '(sms)', 'body': "FreeMsg Hey there darling it's been 3 week's now and no word back! I'd like some fun you up for it still?… score=0 indicators=['ml_model:safe']
- phishing FN: FN payload={'sender': 'unknown@sms', 'subject': '(sms)', 'body': 'England v Macedonia - dont miss the goals/team news. Txt ur national team to 87077 eg ENGLAND to 87077 Tr… score=35 indicators=['sms_shortcode:high', 'sms_spam_keyword:high', 'high_digit_ratio:medium', 'ml_model:safe']
- phishing FN: FN payload={'sender': 'unknown@sms', 'subject': '(sms)', 'body': 'Thanks for your subscription to Ringtone UK your mobile will be charged £5/month Please confirm by replyi… score=45 indicators=['sms_spam_keyword:high', 'sms_spam_keyword:high', 'sms_spam_keyword:high', 'ml_model:low']
- phishing FN: FN payload={'sender': 'unknown@sms', 'subject': '(sms)', 'body': 'SMS. ac Sptv: The New Jersey Devils and the Detroit Red Wings play Ice Hockey. Correct or Incorrect? End?… score=0 indicators=['ml_model:safe']
- phishing FN: FN payload={'sender': 'unknown@sms', 'subject': '(sms)', 'body': 'As a valued customer, I am pleased to advise you that following recent review of your Mob No. you are awa… score=30 indicators=['sms_phone_number:high', 'sms_spam_keyword:high', 'ml_model:low']
- FP-hardening marketing regression set (10 realistic digest/newsletter/transactional emails incl. the Medium digest payload and the mediumday.com event-reg token URL): all must stay <= medium and fail the corroboration gate (review_recommended, no provider write).
- FP-hardening phishing positive control: brand-lookalike, IP-host and platform-hosted phishing must still trip corroboration (>=2 engines high+) and land on the auto-quarantine path.
