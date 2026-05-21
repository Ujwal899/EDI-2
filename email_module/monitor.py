import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Set

try:
    from email_module.backend_analyzer import BackendAnalyzer
    from email_module.gmail_client import GmailClient
except ImportError:  # Support direct script execution.
    from backend_analyzer import BackendAnalyzer
    from gmail_client import GmailClient


POLL_INTERVAL_SECONDS = 15
MAX_PROCESSED_IDS = 10000
BASE_DIR = Path(__file__).resolve().parent.parent
PROCESSED_IDS_PATH = BASE_DIR / "processed_email_ids.json"
CREDENTIALS_PATH = BASE_DIR / "credentials.json"
TOKEN_PATH = BASE_DIR / "token.json"
BACKEND_URL = "http://127.0.0.1:8000"


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("gmail-monitor")


def load_processed_ids(path: Path) -> Set[str]:
    if not path.exists():
        return set()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return {str(item) for item in data if str(item).strip()}
    except Exception as exc:
        logger.warning("Could not load processed IDs from %s: %s", path, exc)

    return set()


def save_processed_ids(path: Path, ids: Set[str]) -> None:
    # Keep file bounded while preserving recent IDs.
    trimmed = list(ids)
    if len(trimmed) > MAX_PROCESSED_IDS:
        trimmed = trimmed[-MAX_PROCESSED_IDS:]

    path.write_text(json.dumps(trimmed, indent=2), encoding="utf-8")


def notify_phishing(subject: str, confidence: float, sender: str = "") -> None:
    warning = (
        "\n"
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        "PHISHING ALERT DETECTED\n"
        f"Subject: {subject or '(no subject)'}\n"
        f"Sender: {sender or '(unknown)'}\n"
        f"Confidence: {confidence:.2f}\n"
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
    )
    print(warning)

    # Optional audible alert on Windows.
    try:
        import winsound

        winsound.Beep(1500, 450)
        winsound.Beep(1800, 450)
    except Exception:
        pass


def format_subject(subject: str, limit: int = 90) -> str:
    clean = (subject or "").strip().replace("\n", " ")
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3] + "..."


def main() -> None:
    logger.info("Starting Gmail monitor")
    logger.info("Polling interval: %ss", POLL_INTERVAL_SECONDS)

    processed_ids = load_processed_ids(PROCESSED_IDS_PATH)
    logger.info("Loaded %d processed email IDs", len(processed_ids))

    gmail = GmailClient(credentials_path=CREDENTIALS_PATH, token_path=TOKEN_PATH)
    analyzer = BackendAnalyzer(api_url=BACKEND_URL)

    while True:
        try:
            new_messages = gmail.fetch_latest_messages(known_ids=processed_ids)

            if not new_messages:
                logger.info("No new emails")
            else:
                logger.info("Found %d new emails", len(new_messages))

            for msg in new_messages:
                try:
                    result = analyzer.analyze_email(subject=msg.subject, body=msg.body, sender=msg.sender)
                    label = result["label"]
                    confidence = float(result["confidence"])
                    risk_level = str(result["risk_level"])

                    now = datetime.now().strftime("%H:%M:%S")
                    print(f"[{now}] \"{format_subject(msg.subject)}\" -> {label} ({confidence:.2f}) [{risk_level}]")

                    if label == "PHISHING":
                        notify_phishing(msg.subject, confidence, msg.sender)

                    processed_ids.add(msg.email_id)
                except Exception as exc:
                    logger.error("Failed processing email %s: %s", msg.email_id, exc)

            save_processed_ids(PROCESSED_IDS_PATH, processed_ids)
        except KeyboardInterrupt:
            logger.info("Stopping monitor")
            save_processed_ids(PROCESSED_IDS_PATH, processed_ids)
            break
        except Exception as exc:
            logger.exception("Main loop error: %s", exc)
            time.sleep(5)

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
