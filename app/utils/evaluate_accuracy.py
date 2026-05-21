from __future__ import annotations

import csv
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from app.config import MODEL_PATH, VECTORIZER_PATH
from app.services.multimodal_features import analyze_multimodal_features
from email_module.decision_logic import evaluate_email
from url_module.url_features import extract_features
from url_module.url_guard import BEST_MODEL_PATH, THRESHOLD_PATH


BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
REPORT_DIR = BASE_DIR / "evaluation_reports"
EMAIL_DATA_PATH = DATA_DIR / "labeled_emails.csv"
URL_DATA_PATH = BASE_DIR / "url_module" / "data" / "urls" / "phishing_site_urls_clean.csv"
EMAIL_LABELS = ["SAFE", "SPAM", "PHISHING"]
URL_LABEL_MAP = {"good": 0, "bad": 1}


def normalize_text(text: Any) -> str:
    text = "" if text is None else str(text)
    text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _write_section(lines: list[str], title: str) -> None:
    lines.extend(["", title, "=" * len(title)])


def _safe_report(y_true, y_pred, labels=None, target_names=None) -> str:
    return classification_report(
        y_true,
        y_pred,
        labels=labels,
        target_names=target_names,
        digits=4,
        zero_division=0,
    )


def _load_email_dataset() -> pd.DataFrame:
    df = pd.read_csv(EMAIL_DATA_PATH)
    required = {"subject", "body", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Email dataset missing columns: {sorted(missing)}")

    df = df.copy()
    df["subject"] = df["subject"].fillna("").astype(str)
    df["body"] = df["body"].fillna("").astype(str)
    df["sender"] = df.get("sender", "").fillna("").astype(str) if "sender" in df else ""
    df["label"] = df["label"].astype(str).str.upper().str.strip()
    df = df[df["label"].isin(EMAIL_LABELS)]
    df["text"] = (df["subject"] + " " + df["body"]).map(normalize_text)
    df = df[df["text"].str.len() > 0]
    return df


def evaluate_email_model(lines: list[str]) -> dict[str, Any]:
    _write_section(lines, "Email Model Evaluation")
    df = _load_email_dataset()
    _, test_df = train_test_split(
        df,
        test_size=0.2,
        random_state=42,
        stratify=df["label"],
    )

    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    features = vectorizer.transform(test_df["text"])
    y_true = test_df["label"].to_numpy()
    y_pred = model.predict(features)
    proba = model.predict_proba(features)

    accuracy = accuracy_score(y_true, y_pred)
    weighted_precision = precision_score(y_true, y_pred, labels=EMAIL_LABELS, average="weighted", zero_division=0)
    weighted_recall = recall_score(y_true, y_pred, labels=EMAIL_LABELS, average="weighted", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, labels=EMAIL_LABELS, average="weighted", zero_division=0)
    macro_f1 = f1_score(y_true, y_pred, labels=EMAIL_LABELS, average="macro", zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=EMAIL_LABELS)

    lines.extend(
        [
            f"Dataset rows used: {len(df)}",
            f"Holdout rows: {len(test_df)}",
            f"Label distribution: {dict(Counter(df['label']))}",
            f"Accuracy: {accuracy:.4f}",
            f"Precision weighted: {weighted_precision:.4f}",
            f"Recall weighted: {weighted_recall:.4f}",
            f"F1 weighted: {weighted_f1:.4f}",
            f"F1 macro: {macro_f1:.4f}",
            "Confusion matrix rows=true cols=pred, order SAFE, SPAM, PHISHING:",
            str(cm),
            "",
            _safe_report(y_true, y_pred, labels=EMAIL_LABELS),
        ]
    )

    phishing_idx = list(model.classes_).index("PHISHING") if "PHISHING" in model.classes_ else None
    phishing_auc = None
    if phishing_idx is not None:
        phishing_auc = roc_auc_score((y_true == "PHISHING").astype(int), proba[:, phishing_idx])
        lines.append(f"PHISHING one-vs-rest ROC-AUC: {phishing_auc:.4f}")

    decision_sample = test_df.sample(n=min(10000, len(test_df)), random_state=7)
    decision_preds = []
    decision_errors = 0
    for row in decision_sample.itertuples(index=False):
        raw_features = vectorizer.transform([row.text])
        raw_probs = model.predict_proba(raw_features)[0]
        best_idx = int(raw_probs.argmax())
        raw_label = str(model.classes_[best_idx])
        try:
            result = evaluate_email(
                subject=row.subject,
                sender=getattr(row, "sender", ""),
                body=row.body,
                ml_label=raw_label,
                confidence=float(raw_probs[best_idx]),
            )
            decision_preds.append(str(result["label"]))
        except Exception:
            decision_errors += 1
            decision_preds.append("SUSPICIOUS")

    decision_true = decision_sample["label"].replace({"SPAM": "SUSPICIOUS"}).to_numpy()
    decision_labels = ["SAFE", "SUSPICIOUS", "PHISHING"]
    decision_accuracy = accuracy_score(decision_true, decision_preds)
    lines.extend(
        [
            "",
            "Email Decision Layer Evaluation",
            f"Sample rows: {len(decision_sample)}",
            "Note: SPAM is mapped to SUSPICIOUS because API output has SAFE/SUSPICIOUS/PHISHING.",
            f"Decision-layer parser errors counted as SUSPICIOUS: {decision_errors}",
            f"Decision-layer accuracy: {decision_accuracy:.4f}",
            _safe_report(decision_true, decision_preds, labels=decision_labels),
        ]
    )

    return {
        "rows": len(df),
        "holdout_rows": len(test_df),
        "accuracy": accuracy,
        "weighted_f1": weighted_f1,
        "macro_f1": macro_f1,
        "phishing_auc": phishing_auc,
        "decision_accuracy_sample": decision_accuracy,
        "decision_errors_sample": decision_errors,
    }


def _load_url_dataset() -> tuple[np.ndarray, np.ndarray]:
    features = []
    labels = []
    with URL_DATA_PATH.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            label = str(row.get("label", "")).strip().lower()
            clean_url = str(row.get("clean_url", "")).strip()
            if label not in URL_LABEL_MAP or not clean_url:
                continue
            features.append(extract_features(clean_url))
            labels.append(URL_LABEL_MAP[label])
    return np.array(features, dtype=float), np.array(labels, dtype=int)


def _load_threshold() -> float:
    try:
        return float(THRESHOLD_PATH.read_text(encoding="utf-8").strip())
    except Exception:
        return 0.5


def evaluate_url_model(lines: list[str]) -> dict[str, Any]:
    _write_section(lines, "URL Model Evaluation")
    X, y = _load_url_dataset()
    _, X_test, _, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    model = joblib.load(BEST_MODEL_PATH)
    threshold = _load_threshold()
    proba = model.predict_proba(X_test)[:, 1]
    y_pred_default = model.predict(X_test)
    y_pred_threshold = (proba >= threshold).astype(int)

    def metrics_for(preds: np.ndarray) -> dict[str, float]:
        return {
            "accuracy": accuracy_score(y_test, preds),
            "precision_bad": precision_score(y_test, preds, pos_label=1, zero_division=0),
            "recall_bad": recall_score(y_test, preds, pos_label=1, zero_division=0),
            "f1_bad": f1_score(y_test, preds, pos_label=1, zero_division=0),
            "macro_f1": f1_score(y_test, preds, average="macro", zero_division=0),
        }

    default_metrics = metrics_for(y_pred_default)
    threshold_metrics = metrics_for(y_pred_threshold)
    auc = roc_auc_score(y_test, proba)

    lines.extend(
        [
            f"Dataset rows used: {len(y)}",
            f"Holdout rows: {len(y_test)}",
            f"Label distribution: {dict(Counter(y))} where 0=good, 1=bad",
            f"ROC-AUC: {auc:.4f}",
            "",
            "Default model predict():",
            json.dumps(default_metrics, indent=2),
            _safe_report(y_test, y_pred_default, labels=[0, 1], target_names=["good", "bad"]),
            "",
            f"Configured threshold: {threshold:.4f}",
            json.dumps(threshold_metrics, indent=2),
            _safe_report(y_test, y_pred_threshold, labels=[0, 1], target_names=["good", "bad"]),
        ]
    )

    return {
        "rows": len(y),
        "holdout_rows": len(y_test),
        "roc_auc": auc,
        "default": default_metrics,
        "threshold": threshold_metrics,
        "threshold_value": threshold,
    }


def evaluate_multimodal_rules(lines: list[str]) -> dict[str, Any]:
    _write_section(lines, "Multimodal Rule Checks")
    cases = [
        (
            "safe sender",
            "SAFE",
            {"sender": "team@google.com", "body": "Normal update"},
        ),
        (
            "brand spoof sender",
            "SUSPICIOUS",
            {"sender": "PayPal Support <notice@random-example.com>"},
        ),
        (
            "risky attachment",
            "SUSPICIOUS",
            {"attachments": ["update.exe"]},
        ),
        (
            "credential webpage",
            "SUSPICIOUS",
            {"webpage_text": "<form><input type='password'></form>"},
        ),
        (
            "qr image",
            "SUSPICIOUS",
            {"image_indicators": ["QR code asks user to verify account"], "qr_text": "QR code"},
        ),
        (
            "combined high risk",
            "PHISHING",
            {
                "sender": "PayPal Support <notice@random-example.com>",
                "reply_to": "reply@other-domain.com",
                "attachments": ["scan-qr.png", "update.exe"],
                "webpage_text": "<form><input type='password'></form>",
                "image_indicators": ["QR code"],
            },
        ),
    ]

    rows = []
    passed = 0
    rank = {"SAFE": 0, "SUSPICIOUS": 1, "PHISHING": 2}
    for name, minimum_label, payload in cases:
        result = analyze_multimodal_features(**payload)
        actual = str(result["label"])
        ok = rank[actual] >= rank[minimum_label]
        passed += int(ok)
        rows.append(
            {
                "case": name,
                "minimum_expected": minimum_label,
                "actual": actual,
                "ok": ok,
                "reasons": result.get("reasons", []),
            }
        )

    lines.extend(
        [
            "These checks evaluate the rule-based non-dataset features.",
            f"Passed: {passed}/{len(cases)}",
            json.dumps(rows, indent=2),
        ]
    )
    return {"passed": passed, "total": len(cases), "cases": rows}


def main() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_path = REPORT_DIR / f"accuracy_evaluation_{timestamp}.txt"
    latest_path = REPORT_DIR / "latest_accuracy_evaluation.txt"
    summary_path = REPORT_DIR / "latest_accuracy_summary.json"

    lines = [
        "Phishing Detection Accuracy Evaluation",
        "======================================",
        f"Generated UTC: {datetime.now(timezone.utc).isoformat()}",
        f"Project root: {BASE_DIR}",
        "Note: This evaluates current saved artifacts and rule checks; it does not retrain models.",
    ]

    summary = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "email": evaluate_email_model(lines),
        "url": evaluate_url_model(lines),
        "multimodal_rules": evaluate_multimodal_rules(lines),
    }

    report_text = "\n".join(lines) + "\n"
    report_path.write_text(report_text, encoding="utf-8")
    latest_path.write_text(report_text, encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Saved report: {report_path}")
    print(f"Saved latest report: {latest_path}")
    print(f"Saved summary: {summary_path}")


if __name__ == "__main__":
    main()
