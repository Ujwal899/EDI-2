import re
from typing import Dict

import joblib

from app.config import MODEL_PATH, VECTORIZER_PATH
from email_module.decision_logic import evaluate_email


class EmailService:
    def __init__(self) -> None:
        self.model = None
        self.vectorizer = None

    def load_artifacts(self) -> None:
        if not MODEL_PATH.exists() or not VECTORIZER_PATH.exists():
            missing = [str(p) for p in (MODEL_PATH, VECTORIZER_PATH) if not p.exists()]
            raise FileNotFoundError(f"Missing model artifacts: {missing}")

        self.model = joblib.load(MODEL_PATH)
        self.vectorizer = joblib.load(VECTORIZER_PATH)

    @staticmethod
    def normalize_text(text: str) -> str:
        text = text or ""
        text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", " ", str(text))
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def predict_email(self, subject: str, body: str, sender: str = "") -> Dict[str, float | str | list[str]]:
        if self.model is None or self.vectorizer is None:
            self.load_artifacts()

        combined_text = self.normalize_text(f"{subject} {body}")
        if not combined_text:
            return {
                "label": "SAFE",
                "confidence": 0.5,
                "risk_level": "LOW",
                "reasons": ["Empty content after normalization"],
            }

        features = self.vectorizer.transform([combined_text])
        probabilities = self.model.predict_proba(features)[0]

        best_idx = int(probabilities.argmax())
        label = str(self.model.classes_[best_idx])
        confidence = float(probabilities[best_idx])

        if label not in {"SAFE", "SPAM", "PHISHING"}:
            raise RuntimeError(f"Unexpected model label: {label}")

        return evaluate_email(
            subject=subject,
            sender=sender,
            body=body,
            ml_label=label,
            confidence=confidence,
        )


email_service = EmailService()
