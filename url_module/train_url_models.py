from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path
import sys

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

try:
    from url_module.url_features import extract_features, feature_names
except ImportError:  # Support direct script execution.
    sys.path.append(str(Path(__file__).resolve().parent.parent))
    from url_module.url_features import extract_features, feature_names

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "urls" / "phishing_site_urls_clean.csv"
REPORT_PATH = BASE_DIR / "reports" / "urls" / "url_model_report.txt"
LOG_MODEL_PATH = BASE_DIR / "models" / "urls" / "url_model_logistic.joblib"
RF_MODEL_PATH = BASE_DIR / "models" / "urls" / "url_model_random_forest.joblib"
BEST_MODEL_PATH = BASE_DIR / "models" / "urls" / "url_model_best.joblib"
THRESHOLD_PATH = BASE_DIR / "models" / "urls" / "url_model_threshold.txt"

LABEL_MAP = {"good": 0, "bad": 1}


def load_dataset(path: str) -> tuple[np.ndarray, np.ndarray]:
    features = []
    labels = []

    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            label = row.get("label", "").strip().lower()
            clean_url = row.get("clean_url", "").strip()
            if label not in LABEL_MAP or not clean_url:
                continue
            features.append(extract_features(clean_url))
            labels.append(LABEL_MAP[label])

    return np.array(features, dtype=float), np.array(labels, dtype=int)


def evaluate_model(name: str, model, X_val, y_val) -> dict:
    preds = model.predict(X_val)
    proba = model.predict_proba(X_val)[:, 1]
    report = classification_report(y_val, preds, target_names=["good", "bad"], digits=4)
    auc = roc_auc_score(y_val, proba)

    # F1 for the bad class is the key metric.
    bad_line = [line for line in report.splitlines() if line.strip().startswith("bad")]
    bad_f1 = None
    if bad_line:
        parts = bad_line[0].split()
        bad_f1 = float(parts[3]) if len(parts) >= 4 else None

    return {
        "name": name,
        "report": report,
        "auc": auc,
        "bad_f1": bad_f1,
    }


def find_best_threshold(y_true: np.ndarray, proba: np.ndarray) -> tuple[float, float]:
    best_threshold = 0.5
    best_f1 = 0.0

    for threshold in np.linspace(0.1, 0.99, 90):
        preds = (proba >= threshold).astype(int)
        score = f1_score(y_true, preds, pos_label=1)
        if score > best_f1:
            best_f1 = score
            best_threshold = float(threshold)

    return best_threshold, best_f1


def main() -> None:
    X, y = load_dataset(DATA_PATH)
    if X.size == 0:
        raise ValueError("No data loaded. Check the cleaned CSV path and columns.")

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    class_counts = Counter(y_train)

    logistic_model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            solver="liblinear",
            random_state=42,
        )),
    ])

    rf_model = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )

    logistic_model.fit(X_train, y_train)
    rf_model.fit(X_train, y_train)

    log_eval = evaluate_model("Logistic Regression", logistic_model, X_val, y_val)
    rf_eval = evaluate_model("Random Forest", rf_model, X_val, y_val)

    rf_proba = rf_model.predict_proba(X_val)[:, 1]
    best_threshold, best_threshold_f1 = find_best_threshold(y_val, rf_proba)
    best_model = rf_model

    joblib.dump(logistic_model, LOG_MODEL_PATH)
    joblib.dump(rf_model, RF_MODEL_PATH)
    joblib.dump(best_model, BEST_MODEL_PATH)

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("URL Model Training Report\n")
        f.write("=========================\n")
        f.write(f"Train size: {len(X_train)}\n")
        f.write(f"Validation size: {len(X_val)}\n")
        f.write(f"Class distribution (train): {class_counts}\n")
        f.write("\nFeatures:\n")
        for name in feature_names():
            f.write(f"- {name}\n")

        f.write("\nLogistic Regression\n")
        f.write(log_eval["report"] + "\n")
        f.write(f"ROC-AUC: {log_eval['auc']:.4f}\n")

        f.write("\nRandom Forest\n")
        f.write(rf_eval["report"] + "\n")
        f.write(f"ROC-AUC: {rf_eval['auc']:.4f}\n")

        f.write("\nBest Model\n")
        f.write("Selected: Random Forest\n")
        f.write(f"Bad-class F1: {rf_eval['bad_f1']}\n")
        f.write(f"Recommended threshold: {best_threshold:.2f}\n")
        f.write(f"Bad-class F1 at threshold: {best_threshold_f1:.4f}\n")

    with open(THRESHOLD_PATH, "w", encoding="utf-8") as f:
        f.write(f"{best_threshold:.4f}\n")


if __name__ == "__main__":
    main()
