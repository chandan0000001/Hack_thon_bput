# CYBERGUARD Evaluation Harness Report

- Generated: 2026-10-05T13:23:37.898084+00:00
- Git tip: fdca953
- Scale option: default
- Data mode: auto

## Per-engine metrics

| Engine | Cases | Positives | Precision | Recall | F1 | AUC | Malicious mean | Benign mean | Band gap | MW p-value |
|---|---|---|---|---|---|---|---|---|---|---|

## Property tests

- http_analysis_requests: requests=61, ok=61

## HTTP latency (sampled analysis requests)

- `/api/v1/analysis/email`: n=20 p50=22.8ms p95=1395.9ms p99=1395.9ms
- `/api/v1/analysis/url`: n=21 p50=916.7ms p95=5011.2ms p99=10036.5ms
- `/api/v1/analysis/account-takeover`: n=10 p50=15.0ms p95=19.0ms p99=19.0ms
- `/api/v1/analysis/network`: n=10 p50=17.9ms p95=24.0ms p99=24.0ms

## Data provenance

| Source | Mode | Rows | SHA256 | Fetched at |
|---|---|---|---|---|

## Findings (bugs discovered by the harness — NOT fixed)

- None recorded this run.
