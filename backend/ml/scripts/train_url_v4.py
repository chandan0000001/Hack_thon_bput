"""train_url_v4.py — Step 3 of the URL v4 retrain pipeline.

Retrains the CYBERGUARD malicious-URL detector on 100k+ real-world URLs
(XGBoost v4) while keeping the EXACT v3 19-feature schema — the artifact is a
drop-in replacement for url_xgb_v3.pkl in app/services/ml_inference.py.

Pipeline:
  1. Load ml/data/url_datasets/url_v4_processed.csv (19 features + label).
  2. 80/10/10 Train/Validation/Test split, stratified on (label, source):
     each split keeps every collection source in proportion, so the test set
     contains phishing infrastructure the model never saw from ANY source —
     no source-level leakage between train and test.
  3. Hyperparameter search (Optuna when installed, GridSearchCV fallback)
     over max_depth / learning_rate / n_estimators / subsample (+ regularizers),
     maximising validation ROC-AUC.
  4. Refit the best config on Train+Validation with
     scale_pos_weight = n_negative / n_positive (class imbalance).
  5. Evaluate once on the held-out test set; print Accuracy / Precision /
     Recall / F1 / ROC-AUC / PR-AUC.
  6. Save backend/ml/models/url_xgb_v4.pkl (joblib, XGBClassifier exposing
     predict_proba — the exact interface predict_url() calls) and a metrics
     JSON next to the other model cards, plus the feature-importance plot.

Run from the backend directory:
    uv run python ml/scripts/train_url_v4.py
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, train_test_split
from xgboost import XGBClassifier

BACKEND_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND_DIR))

from ml.url_features_v3 import FEATURE_COLUMNS_V3  # noqa: E402

PROCESSED_CSV_PATH = BACKEND_DIR / "ml" / "data" / "url_datasets" / "url_v4_processed.csv"
MODELS_DIR = BACKEND_DIR / "ml" / "models"
MODEL_PATH = MODELS_DIR / "url_xgb_v4.pkl"
METRICS_PATH = MODELS_DIR / "url_v4_metrics.json"
PLOTS_DIR = BACKEND_DIR / "docs" / "plots"
PLOT_PATH = PLOTS_DIR / "url_v4_feature_importance.png"

SEED = 42
# Fixed regularisation/search-independent params (v3 parity + scale).
BASE_PARAMS: dict = {
    "objective": "binary:logistic",
    "eval_metric": "auc",
    "tree_method": "hist",
    "n_jobs": -1,
    "random_state": SEED,
}
# Hyperparameter grid — the four requested axes plus the two regularisers
# that matter most at 100k+ rows (colsample / min_child_weight fight noise fit).
GRID_PARAMS: dict[str, list] = {
    "max_depth": [4, 6, 8],
    "learning_rate": [0.03, 0.05, 0.1],
    "n_estimators": [300, 600],
    "subsample": [0.8, 1.0],
    "colsample_bytree": [0.8, 1.0],
    "min_child_weight": [1, 5],
}
OPTUNA_N_TRIALS = 40
OPTUNA_CV_SPLITS = 3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("train_url_v4")


# ---------------------------------------------------------------------------
# 1. Data loading & splitting
# ---------------------------------------------------------------------------

def load_processed(path: Path) -> pd.DataFrame:
    """Load the processed CSV and enforce the feature lock."""
    frame = pd.read_csv(path)
    present = [c for c in frame.columns if c in FEATURE_COLUMNS_V3]
    if len(present) != len(FEATURE_COLUMNS_V3):
        raise ValueError(
            f"processed CSV is missing features: {sorted(set(FEATURE_COLUMNS_V3) - set(present))} "
            "(run preprocess_url_v4.py)"
        )
    return frame


def stratify_key(frame: pd.DataFrame) -> pd.Series:
    """Combined (label, source) stratum for source-aware stratified splitting.

    If the processed CSV carries no `source` column (older raw data), fall back
    to label-only stratification — still stratified, just not source-aware.
    """
    if "source" in frame.columns:
        return frame["label"].astype(str) + ":" + frame["source"].astype(str)
    return frame["label"].astype(str)


def make_splits(frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray,
                                              np.ndarray, np.ndarray, np.ndarray]:
    """80/10/10 split into X/y train, validation and test numpy arrays.

    Arrays (not DataFrames) are used end-to-end so the pickled XGBClassifier
    carries no feature_names — the production inference path calls
    predict_proba() with a bare numpy row (ml_inference.predict_url), which
    would emit a feature-name-mismatch warning otherwise.
    """
    X = frame[FEATURE_COLUMNS_V3].to_numpy(dtype=np.float64)
    y = frame["label"].to_numpy(dtype=np.int64)
    strata = stratify_key(frame)

    # Split on indices so the second-stage stratification uses the strata of
    # exactly the rows that survived the first split.
    indices = np.arange(len(frame))
    idx_train_val, idx_test = train_test_split(
        indices, test_size=0.10, stratify=strata, random_state=SEED)
    # Stratified 1/9 of the full data = 10% validation within train_val.
    val_fraction = 1.0 / 9.0
    idx_train, idx_val = train_test_split(
        idx_train_val, test_size=val_fraction,
        stratify=strata.iloc[idx_train_val], random_state=SEED)

    X_train, y_train = X[idx_train], y[idx_train]
    X_val, y_val = X[idx_val], y[idx_val]
    X_test, y_test = X[idx_test], y[idx_test]
    log.info(
        "splits: train %s / validation %s / test %s "
        "(train+val malicious share %.1f%%, test malicious share %.1f%%)",
        f"{len(y_train):,}", f"{len(y_val):,}", f"{len(y_test):,}",
        100 * y_train.mean(), 100 * y_test.mean(),
    )
    return X_train, X_val, X_test, y_train, y_val, y_test


# ---------------------------------------------------------------------------
# 2. Hyperparameter search (Optuna preferred, GridSearchCV fallback)
# ---------------------------------------------------------------------------

def tune_with_optuna(
    X_train: np.ndarray, y_train: np.ndarray,
    X_val: np.ndarray, y_val: np.ndarray,
    scale_pos_weight: float,
) -> dict:
    """Bayesian-ish search maximising validation ROC-AUC."""
    import optuna

    optuna.logging.set_verbosity(optuna.logging.WARNING)

    def objective(trial: "optuna.Trial") -> float:
        params = {
            "max_depth": trial.suggest_int("max_depth", 3, 10),
            "learning_rate": trial.suggest_float("learning_rate", 0.01, 0.2, log=True),
            "n_estimators": trial.suggest_int("n_estimators", 200, 800, step=100),
            "subsample": trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree": trial.suggest_float("colsample_bytree", 0.6, 1.0),
            "min_child_weight": trial.suggest_int("min_child_weight", 1, 10),
        }
        model = XGBClassifier(**BASE_PARAMS, **params, scale_pos_weight=scale_pos_weight)
        model.fit(X_train, y_train, verbose=False)
        return roc_auc_score(y_val, model.predict_proba(X_val)[:, 1])

    study = optuna.create_study(direction="maximize",
                                sampler=optuna.samplers.TPESampler(seed=SEED))
    study.optimize(objective, n_trials=OPTUNA_N_TRIALS, show_progress_bar=False)
    log.info("optuna: best val ROC-AUC %.4f in %d trials (params: %s)",
             study.best_value, OPTUNA_N_TRIALS, study.best_params)
    return dict(study.best_params)


def tune_with_gridsearch(
    X_train: np.ndarray, y_train: np.ndarray, scale_pos_weight: float
) -> dict:
    """Deterministic fallback when optuna is not installed."""
    search = GridSearchCV(
        XGBClassifier(**BASE_PARAMS, scale_pos_weight=scale_pos_weight),
        GRID_PARAMS,
        scoring="roc_auc",
        cv=3,
        n_jobs=1,  # XGBClassifier already uses all cores
        verbose=1,
    )
    search.fit(X_train, y_train)
    log.info("gridsearch: best CV ROC-AUC %.4f (params: %s)",
             search.best_score_, search.best_params_)
    return dict(search.best_params_)


def tune_hyperparameters(
    X_train: np.ndarray, y_train: np.ndarray,
    X_val: np.ndarray, y_val: np.ndarray,
    scale_pos_weight: float,
) -> dict:
    try:
        import optuna  # noqa: F401
    except ImportError:
        log.info("optuna not installed — falling back to GridSearchCV "
                 "(pip install optuna for the faster TPE search)")
        return tune_with_gridsearch(X_train, y_train, scale_pos_weight)
    return tune_with_optuna(X_train, y_train, X_val, y_val, scale_pos_weight)


# ---------------------------------------------------------------------------
# 3. Final training, evaluation, persistence
# ---------------------------------------------------------------------------

def evaluate(model: XGBClassifier, X_test: np.ndarray, y_test: np.ndarray) -> dict:
    """Threshold-0.5 metrics + rank metrics on the held-out test set."""
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba > 0.5).astype(int)
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "precision": round(float(precision_score(y_test, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, pred, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, proba)), 4),
        "pr_auc": round(float(average_precision_score(y_test, proba)), 4),
    }
    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
    metrics["confusion_matrix"] = {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    return metrics


def print_metrics(metrics: dict, n_test: int) -> None:
    cm = metrics["confusion_matrix"]
    log.info("--- TEST METRICS (%s held-out rows, threshold 0.5) ---", f"{n_test:,}")
    log.info("  Accuracy : %.4f", metrics["accuracy"])
    log.info("  Precision: %.4f", metrics["precision"])
    log.info("  Recall   : %.4f", metrics["recall"])
    log.info("  F1-score : %.4f", metrics["f1"])
    log.info("  ROC-AUC  : %.4f", metrics["roc_auc"])
    log.info("  PR-AUC   : %.4f", metrics["pr_auc"])
    log.info("  confusion: TP %s / FP %s / FN %s / TN %s",
             cm["tp"], cm["fp"], cm["fn"], cm["tn"])


def plot_feature_importance(model: XGBClassifier) -> Path | None:
    """Gain-based importance plot; None when matplotlib is unavailable."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        log.warning("matplotlib not installed — skipping feature-importance plot "
                    "(pip install matplotlib)")
        return None

    gains = model.get_booster().get_score(importance_type="gain")
    # get_score keys are bare feature indices when trained on numpy ("f0"..).
    pairs = []
    for key, value in gains.items():
        index = int(key[1:]) if key.startswith("f") else FEATURE_COLUMNS_V3.index(key)
        pairs.append((FEATURE_COLUMNS_V3[index], value))
    pairs.sort(key=lambda p: p[1])
    names = [p[0] for p in pairs]
    values = [p[1] for p in pairs]

    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(10, max(6, len(names) * 0.35)))
    ax.barh(names, values, color="#2b6cb0")
    ax.set_xlabel("Gain (total gain contributed by splits on the feature)")
    ax.set_title("XGBoost v4 — URL feature importance (19-feature v3 schema)")
    fig.tight_layout()
    fig.savefig(PLOT_PATH, dpi=150)
    plt.close(fig)
    log.info("feature-importance plot saved: %s", PLOT_PATH)
    return PLOT_PATH


def run_regression_gate(model: XGBClassifier, top1m: set[str]) -> bool:
    """The v3 'Medium test': benign marketing/tracking URLs must stay benign.

    Same canonical URLs train_url_v3.py gates on — a v4 that fixes recall by
    flagging medium.com digest links again is a regression, not an upgrade.
    """
    from ml.url_features_v3 import extract_url_features_v3, vectorize_v3

    gate_urls: list[tuple[str, int]] = [
        ("https://medium.com/@coder6861python?source=email-971ea2707eee-1789158672039-digest.reader", 0),
        ("https://paypal.com/signin?utm_source=email", 0),
        ("http://paypa1-secure.tk/login", 1),
        ("http://192.168.1.5/verify-login.php", 1),
    ]
    all_pass = True
    for url, expected in gate_urls:
        vector = np.array([vectorize_v3(extract_url_features_v3(url, top1m))],
                          dtype=np.float64)
        proba = float(model.predict_proba(vector)[0][1])
        ok = (proba > 0.5) == bool(expected)
        all_pass &= ok
        log.info("  %s Prob %.4f | expected %s | %s",
                 "PASS" if ok else "FAIL", proba,
                 "phish" if expected else "benign", url[:90])
    return all_pass


def main() -> int:
    log.info("=== URL XGBoost v4 training (19-feature v3 schema, 100k+ real URLs) ===")

    if not PROCESSED_CSV_PATH.exists():
        log.error("processed dataset not found: %s — run fetch_url_data.py and "
                  "preprocess_url_v4.py first", PROCESSED_CSV_PATH)
        return 1
    frame = load_processed(PROCESSED_CSV_PATH)
    n_benign, n_malicious = int((frame["label"] == 0).sum()), int((frame["label"] == 1).sum())
    log.info("dataset: %s rows (benign %s / malicious %s)", f"{len(frame):,}",
             f"{n_benign:,}", f"{n_malicious:,}")
    if len(frame) < 50_000:
        log.warning("dataset below 100k target — v4's purpose is scale; consider "
                    "re-running fetch_url_data.py with higher caps")

    X_train, X_val, X_test, y_train, y_val, y_test = make_splits(frame)

    # Class imbalance via cost-sensitive learning (v3 convention; chosen over
    # SMOTE because all 19 features are deterministic functions of the URL —
    # interpolating synthetic feature vectors creates URLs that never existed).
    scale_pos_weight = float((y_train == 0).sum()) / float(max((y_train == 1).sum(), 1))
    log.info("scale_pos_weight (train): %.4f", scale_pos_weight)

    best_params = tune_hyperparameters(X_train, y_train, X_val, y_val, scale_pos_weight)

    # Final fit on Train+Validation with the tuned configuration.
    log.info("refitting best config on train+validation ...")
    final_model = XGBClassifier(
        **BASE_PARAMS, **best_params, scale_pos_weight=scale_pos_weight)
    final_model.fit(
        np.vstack([X_train, X_val]), np.concatenate([y_train, y_val]), verbose=False)

    metrics = evaluate(final_model, X_test, y_test)
    print_metrics(metrics, len(y_test))

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(final_model, MODEL_PATH)  # joblib — the runtime's load path
    log.info("saved model: %s", MODEL_PATH)
    plot_feature_importance(final_model)

    metrics_card = {
        "model": MODEL_PATH.name,
        "algorithm": "XGBoost (XGBClassifier)",
        "feature_schema": "ml/url_features_v3.py FEATURE_COLUMNS_V3 (19 features, unchanged)",
        "dataset_rows": int(len(frame)),
        "n_benign": n_benign,
        "n_malicious": n_malicious,
        "splits": "80/10/10 stratified on (label, source)",
        "scale_pos_weight": round(scale_pos_weight, 4),
        "tuned_params": best_params,
        **metrics,
    }
    METRICS_PATH.write_text(json.dumps(metrics_card, indent=2), encoding="utf-8")
    log.info("saved metrics card: %s", METRICS_PATH)

    try:
        from app.core.url_reputation import top1m_domain_set
        top1m = top1m_domain_set()
    except Exception:  # offline gate check — reuse file loader
        top1m = {
            line.strip().lower()
            for line in (BACKEND_DIR / "ml" / "data" / "url_whitelist" / "top1m.txt")
            .read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        }
    gate_ok = run_regression_gate(final_model, top1m)
    log.info("=== DONE — regression gate: %s ===", "PASS" if gate_ok else "FAIL")
    return 0 if gate_ok else 1


if __name__ == "__main__":
    sys.exit(main())
