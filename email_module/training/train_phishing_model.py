import re
import sys
from pathlib import Path
from typing import Dict, Tuple

import joblib
import pandas as pd
try:
    from email_module.decision_logic import apply_decision_layer, extract_domain_from_sender
except ImportError:  # Support direct script execution.
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from email_module.decision_logic import apply_decision_layer, extract_domain_from_sender
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split


BASE_DIR = Path(__file__).resolve().parents[2]
DATA_PATH = BASE_DIR / "data" / "labeled_emails.csv"
FEEDBACK_PATH = BASE_DIR / "data" / "feedback_training_rows.csv"
REPORT_PATH = BASE_DIR / "email_module" / "reports" / "email_model_report.txt"
MODEL_PATH = BASE_DIR / "app" / "models" / "model.pkl"
VECTORIZER_PATH = BASE_DIR / "app" / "models" / "vectorizer.pkl"
LABELS = ["SAFE", "SPAM", "PHISHING"]


def normalize_text(text: str) -> str:
    if text is None:
        return ""
    text = str(text)
    text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def build_input_text(df: pd.DataFrame) -> pd.Series:
    subject = df.get("subject", "").fillna("").astype(str)
    body = df.get("body", "").fillna("").astype(str)
    combined = (subject + " " + body).map(normalize_text)
    return combined


def load_dataset(csv_path: Path) -> Tuple[pd.Series, pd.Series]:
    if not csv_path.exists():
        raise FileNotFoundError(f"Input dataset not found: {csv_path}")

    df = pd.read_csv(csv_path)
    if FEEDBACK_PATH.exists():
        feedback_df = pd.read_csv(FEEDBACK_PATH)
        df = pd.concat([df, feedback_df], ignore_index=True)

    required_cols = {"subject", "body", "label"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    df = df.copy()
    df["label"] = df["label"].astype(str).str.upper().str.strip()
    df = df[df["label"].isin(LABELS)]

    x_text = build_input_text(df)
    y = df["label"]

    # Drop rows with no useful text.
    mask = x_text.str.len() > 0
    return x_text[mask], y[mask]


def train_and_evaluate() -> None:
    x_text, y = load_dataset(DATA_PATH)

    x_train_text, x_test_text, y_train, y_test = train_test_split(
        x_text,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    vectorizer = TfidfVectorizer(
        lowercase=True,
        strip_accents="unicode",
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.98,
        max_features=200000,
    )

    x_train = vectorizer.fit_transform(x_train_text)
    x_test = vectorizer.transform(x_test_text)

    model = LogisticRegression(
        max_iter=1000,
        solver="lbfgs",
        class_weight="balanced",
        n_jobs=-1,
    )
    model.fit(x_train, y_train)

    y_pred = model.predict(x_test)

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, labels=LABELS, average="weighted", zero_division=0)
    recall = recall_score(y_test, y_pred, labels=LABELS, average="weighted", zero_division=0)
    f1 = f1_score(y_test, y_pred, labels=LABELS, average="weighted", zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=LABELS)

    report = [
        f"Dataset rows: {len(x_text)}",
        f"Feedback rows included: {FEEDBACK_PATH.exists()}",
        f"Accuracy: {accuracy:.4f}",
        f"Precision (weighted): {precision:.4f}",
        f"Recall (weighted): {recall:.4f}",
        f"F1 (weighted): {f1:.4f}",
        "Confusion Matrix [rows=true, cols=pred] in order SAFE, SPAM, PHISHING:",
        str(cm),
        "",
        classification_report(y_test, y_pred, labels=LABELS, zero_division=0),
    ]
    report_text = "\n".join(report)
    print(report_text)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(report_text, encoding="utf-8")
    print(f"Saved model to: {MODEL_PATH}")
    print(f"Saved vectorizer to: {VECTORIZER_PATH}")
    print(f"Saved report to: {REPORT_PATH}")


_loaded_model = None
_loaded_vectorizer = None


def _load_artifacts() -> Tuple[LogisticRegression, TfidfVectorizer]:
    global _loaded_model, _loaded_vectorizer

    if _loaded_model is None or _loaded_vectorizer is None:
        if not MODEL_PATH.exists() or not VECTORIZER_PATH.exists():
            raise FileNotFoundError("Artifacts not found. Train the model first to create model.pkl and vectorizer.pkl.")
        _loaded_model = joblib.load(MODEL_PATH)
        _loaded_vectorizer = joblib.load(VECTORIZER_PATH)

    return _loaded_model, _loaded_vectorizer


def predict_email(subject: str, body: str, sender: str = "") -> Dict[str, float | str]:
    model, vectorizer = _load_artifacts()

    combined = normalize_text(f"{subject} {body}")
    features = vectorizer.transform([combined])

    probabilities = model.predict_proba(features)[0]
    best_idx = int(probabilities.argmax())
    raw_label = str(model.classes_[best_idx])
    confidence = float(probabilities[best_idx])

    return apply_decision_layer(
        raw_label=raw_label,
        confidence=confidence,
        subject=subject,
        sender_domain=extract_domain_from_sender(sender),
        body=body,
        sender=sender,
    )


if __name__ == "__main__":
    train_and_evaluate()
