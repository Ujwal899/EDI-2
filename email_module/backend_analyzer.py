import logging
import time
from typing import Dict

import requests


logger = logging.getLogger(__name__)


class BackendAnalyzer:
    def __init__(self, api_url: str, timeout_seconds: int = 15, max_retries: int = 3) -> None:
        self.api_url = api_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._session = requests.Session()

    def analyze_email(self, subject: str, body: str, sender: str = "") -> Dict[str, float | str]:
        endpoint = f"{self.api_url}/analyze-email"
        payload = {"subject": subject or "", "body": body or "", "sender": sender or ""}

        last_exception: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                response = self._session.post(endpoint, json=payload, timeout=self.timeout_seconds)
                response.raise_for_status()
                data = response.json()

                label = str(data.get("label", "SAFE")).upper().strip()
                confidence = float(data.get("confidence", 0.0))
                risk_level = str(data.get("risk_level", "LOW")).upper().strip()

                if label not in {"SAFE", "SUSPICIOUS", "PHISHING"}:
                    raise ValueError(f"Unexpected label from backend: {label}")
                if risk_level not in {"LOW", "MEDIUM", "HIGH"}:
                    raise ValueError(f"Unexpected risk_level from backend: {risk_level}")
                return {"label": label, "confidence": confidence, "risk_level": risk_level}
            except Exception as exc:
                last_exception = exc
                wait_seconds = min(2 ** attempt, 8)
                logger.warning(
                    "Analyze request failed (attempt %d/%d): %s. Retrying in %ds",
                    attempt,
                    self.max_retries,
                    exc,
                    wait_seconds,
                )
                time.sleep(wait_seconds)

        raise RuntimeError(f"Analyze request failed after {self.max_retries} retries: {last_exception}")
