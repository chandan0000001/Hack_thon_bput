# URL model — honest evaluation report

_Generated 2026-10-03 01:22:16 UTC. Stratified-holdout metrics are NOT real-world numbers (domain leakage)._

## external
```json
{
  "v3.1": {
    "artifact": "url_xgb_v3.1.pkl",
    "benign_source": "umbrella-top1m-committed (same source as training, held-out domains)",
    "at_0.5": {
      "threshold": 0.5,
      "n": 45000,
      "positives": 20000,
      "precision": 0.713,
      "recall": 0.9758,
      "f1": 0.8239,
      "roc_auc": 0.9553,
      "pr_auc": 0.9328,
      "fpr": 0.3142,
      "fnr": 0.0242,
      "confusion": {
        "tn": 17144,
        "fp": 7856,
        "fn": 484,
        "tp": 19516
      },
      "ece": 0.1682,
      "reliability": [
        {
          "bin": "0.0-0.1",
          "n": 10977,
          "mean_p": 0.0293,
          "empirical_phish_rate": 0.0133
        },
        {
          "bin": "0.1-0.2",
          "n": 1777,
          "mean_p": 0.1477,
          "empirical_phish_rate": 0.0512
        },
        {
          "bin": "0.2-0.3",
          "n": 1592,
          "mean_p": 0.2532,
          "empirical_phish_rate": 0.0546
        },
        {
          "bin": "0.3-0.4",
          "n": 1486,
          "mean_p": 0.3426,
          "empirical_phish_rate": 0.0498
        },
        {
          "bin": "0.4-0.5",
          "n": 1796,
          "mean_p": 0.4535,
          "empirical_phish_rate": 0.0479
        },
        {
          "bin": "0.5-0.6",
          "n": 1769,
          "mean_p": 0.5531,
          "empirical_phish_rate": 0.0627
        },
        {
          "bin": "0.6-0.7",
          "n": 1812,
          "mean_p": 0.6494,
          "empirical_phish_rate": 0.0861
        },
        {
          "bin": "0.7-0.8",
          "n": 1525,
          "mean_p": 0.7517,
          "empirical_phish_rate": 0.099
        },
        {
          "bin": "0.8-0.9",
          "n": 1403,
          "mean_p": 0.8473,
          "empirical_phish_rate": 0.2409
        },
        {
          "bin": "0.9-1.0",
          "n": 20863,
          "mean_p": 0.9954,
          "empirical_phish_rate": 0.8992
        }
      ]
    },
    "benign_fpr_segments": {
      "benign_bare": {
        "n": 20000,
        "fp": 5845,
        "fpr": 0.2923
      },
      "benign_hard": {
        "n": 5000,
        "fp": 2011,
        "fpr": 0.4022
      }
    },
    "at_best_f1": {
      "threshold": 0.85,
      "f1": 0.9147,
      "precision": 0.8833,
      "recall": 0.9485,
      "fpr": 0.1002,
      "fnr": 0.0516
    },
    "latency": {
      "p50_ms": 0.144,
      "p95_ms": 0.32,
      "p99_ms": 0.896,
      "note": "model predict only \u2014 feature extraction adds ~0.5-2 ms/URL (Python)"
    },
    "feature_latency": {
      "p_mean_ms": 0.022,
      "schema": "v3"
    }
  },
  "v4": {
    "artifact": "url_xgb_v4.pkl",
    "benign_source": "umbrella-top1m-committed (same source as training, held-out domains)",
    "at_0.5": {
      "threshold": 0.5,
      "n": 45000,
      "positives": 20000,
      "precision": 0.9905,
      "recall": 0.9668,
      "f1": 0.9785,
      "roc_auc": 0.9959,
      "pr_auc": 0.9962,
      "fpr": 0.0074,
      "fnr": 0.0332,
      "confusion": {
        "tn": 24815,
        "fp": 185,
        "fn": 663,
        "tp": 19337
      },
      "ece": 0.0058,
      "reliability": [
        {
          "bin": "0.0-0.1",
          "n": 23417,
          "mean_p": 0.0142,
          "empirical_phish_rate": 0.0111
        },
        {
          "bin": "0.1-0.2",
          "n": 1217,
          "mean_p": 0.1439,
          "empirical_phish_rate": 0.0994
        },
        {
          "bin": "0.2-0.3",
          "n": 415,
          "mean_p": 0.2448,
          "empirical_phish_rate": 0.2337
        },
        {
          "bin": "0.3-0.4",
          "n": 246,
          "mean_p": 0.3475,
          "empirical_phish_rate": 0.3577
        },
        {
          "bin": "0.4-0.5",
          "n": 183,
          "mean_p": 0.4525,
          "empirical_phish_rate": 0.5301
        },
        {
          "bin": "0.5-0.6",
          "n": 155,
          "mean_p": 0.5479,
          "empirical_phish_rate": 0.6774
        },
        {
          "bin": "0.6-0.7",
          "n": 160,
          "mean_p": 0.6507,
          "empirical_phish_rate": 0.7063
        },
        {
          "bin": "0.7-0.8",
          "n": 208,
          "mean_p": 0.7532,
          "empirical_phish_rate": 0.8702
        },
        {
          "bin": "0.8-0.9",
          "n": 370,
          "mean_p": 0.8554,
          "empirical_phish_rate": 0.9351
        },
        {
          "bin": "0.9-1.0",
          "n": 18629,
          "mean_p": 0.9965,
          "empirical_phish_rate": 0.998
        }
      ]
    },
    "benign_fpr_segments": {
      "benign_bare": {
        "n": 20000,
        "fp": 63,
        "fpr": 0.0032
      },
      "benign_hard": {
        "n": 5000,
        "fp": 122,
        "fpr": 0.0244
      }
    },
    "at_best_f1": {
      "threshold": 0.45,
      "f1": 0.9792,
      "precision": 0.9887,
      "recall": 0.9699,
      "fpr": 0.0088,
      "fnr": 0.0301
    },
    "latency": {
      "p50_ms": 0.148,
      "p95_ms": 0.484,
      "p99_ms": 1.566,
      "note": "model predict only \u2014 feature extraction adds ~0.5-2 ms/URL (Python)"
    },
    "feature_latency": {
      "p_mean_ms": 0.351,
      "schema": "v4"
    }
  }
}
```
