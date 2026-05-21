import logging
import re
from typing import Dict, List

from app.config import CREDENTIALS_PATH, TOKEN_PATH
from app.services.decision_engine import combine_email_and_url
from app.services.email_service import email_service
from app.services.multimodal_features import analyze_multimodal_features, merge_multimodal_result
from app.services.url_service import analyze_url
from email_module.gmail_client import GmailClient


logger = logging.getLogger(__name__)
URL_PATTERN = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)


class GmailDashboardService:
    def __init__(self) -> None:
        self._client: GmailClient | None = None

    def _get_client(self, max_results: int) -> GmailClient:
        self._validate_auth_files()
        if self._client is None:
            self._client = GmailClient(
                credentials_path=CREDENTIALS_PATH,
                token_path=TOKEN_PATH,
                max_results=max_results,
            )
        self._client.max_results = max_results
        return self._client

    @staticmethod
    def _validate_auth_files() -> None:
        missing = []
        if not CREDENTIALS_PATH.exists():
            missing.append(str(CREDENTIALS_PATH))
        if not TOKEN_PATH.exists():
            missing.append(str(TOKEN_PATH))

        if missing:
            raise FileNotFoundError(
                "Missing Gmail auth files: " + ", ".join(missing)
            )

    @staticmethod
    def _extract_first_url(text: str) -> str:
        match = URL_PATTERN.search(text or "")
        if not match:
            return ""
        return match.group(0)

    @staticmethod
    def _to_snippet(text: str, limit: int = 180) -> str:
        cleaned = " ".join((text or "").split())
        if len(cleaned) <= limit:
            return cleaned
        return cleaned[: limit - 3] + "..."

    def fetch_analyzed_emails(self, limit: int = 20) -> List[Dict[str, float | str]]:
        max_results = max(1, min(limit, 100))
        logger.info("Starting Gmail fetch for /emails endpoint (limit=%d)", max_results)
        try:
            client = self._get_client(max_results=max_results)
            messages = client.fetch_latest_messages(known_ids=set())
            logger.info("Fetched %d emails from Gmail", len(messages))

            analyzed: List[Dict[str, float | str]] = []
            for msg in messages:
                email_result = email_service.predict_email(
                    subject=msg.subject,
                    body=msg.body,
                    sender=msg.sender,
                )

                combined_result = email_result
                first_url = self._extract_first_url(msg.body)
                if first_url:
                    try:
                        url_result = analyze_url(first_url)
                        combined_result = combine_email_and_url(email_result=email_result, url_result=url_result)
                    except Exception as exc:
                        logger.warning("URL analysis skipped for message %s: %s", msg.email_id, exc)

                multimodal_result = analyze_multimodal_features(
                    subject=msg.subject,
                    body=msg.body,
                    sender=msg.sender,
                    url=first_url,
                    attachments=msg.attachments or [],
                    reply_to=msg.reply_to,
                    return_path=msg.return_path,
                    webpage_text=msg.html_body,
                )
                combined_result = merge_multimodal_result(combined_result, multimodal_result)

                analyzed.append(
                    {
                        "subject": msg.subject or "(no subject)",
                        "sender": msg.sender or "(unknown)",
                        "snippet": self._to_snippet(msg.body),
                        "label": str(combined_result["label"]),
                        "confidence": float(combined_result["confidence"]),
                        "risk": str(combined_result["risk_level"]),
                        "reasons": list(combined_result.get("reasons", [])),
                    }
                )

            return analyzed
        except Exception as exc:
            logger.exception("Failed while fetching/analyzing Gmail emails: %s", exc)
            raise


gmail_dashboard_service = GmailDashboardService()
