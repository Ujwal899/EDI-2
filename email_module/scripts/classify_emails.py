import csv
import re
from dataclasses import dataclass
from email import policy
from email.parser import Parser
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


BASE_DIR = Path(__file__).resolve().parents[2]
DATASET_PATH = BASE_DIR / "data" / "emails.csv"
OUTPUT_PATH = BASE_DIR / "data" / "labeled_emails.csv"


@dataclass
class ClassificationResult:
    label: str
    confidence: int
    reasons: List[str]


PHISHING_PATTERNS: List[Tuple[re.Pattern, str, int]] = [
    (re.compile(r"\bverify\s+(?:your|account|identity)\b", re.IGNORECASE), "Requests account verification", 25),
    (re.compile(r"\b(?:password|pin|otp|ssn|social security|bank account|credit card)\b", re.IGNORECASE), "Asks for sensitive information", 25),
    (re.compile(r"\b(?:urgent|immediately|within\s+\d+\s*hours?|suspend(?:ed|ing)?|final\s+notice)\b", re.IGNORECASE), "Uses urgency or threats", 20),
    (re.compile(r"\b(?:click\s+here|confirm\s+now|update\s+payment|unlock\s+account)\b", re.IGNORECASE), "Pushes risky immediate action", 20),
    (re.compile(r"\b(?:wire\s+transfer|gift\s+card|crypto(?:currency)?\s+payment)\b", re.IGNORECASE), "Mentions scam-like payment request", 20),
    (re.compile(r"\b(?:dear\s+customer|dear\s+user|account\s+team|security\s+team)\b", re.IGNORECASE), "Generic impersonation greeting", 10),
]


SPAM_PATTERNS: List[Tuple[re.Pattern, str, int]] = [
    (re.compile(r"\b(?:sale|discount|limited\s+time|offer\s+ends|exclusive\s+deal)\b", re.IGNORECASE), "Promotional language", 20),
    (re.compile(r"\b(?:free|win|winner|prize|jackpot|bonus)\b", re.IGNORECASE), "Prize or freebie bait", 20),
    (re.compile(r"\b(?:buy\s+now|shop\s+now|order\s+now|subscribe|unsubscribe)\b", re.IGNORECASE), "Bulk marketing call-to-action", 15),
    (re.compile(r"\b(?:viagra|casino|loan|mortgage|debt\s+relief)\b", re.IGNORECASE), "Common spam topic", 20),
    (re.compile(r"\b(?:%\s*off|coupon|promo\s*code)\b", re.IGNORECASE), "Discount/coupon indicator", 15),
]


def normalize_text(text: str) -> str:
    if not text:
        return ""
    # Remove control chars except newlines/tabs, then normalize whitespace.
    text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_subject_and_body(raw_message: str) -> Tuple[str, str]:
    if not raw_message or not raw_message.strip():
        return "", ""

    subject = ""
    body = ""
    try:
        parsed = Parser(policy=policy.default).parsestr(raw_message)
        subject = str(parsed.get("Subject", "") or "")
        if parsed.is_multipart():
            parts: List[str] = []
            for part in parsed.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        parts.append(part.get_content())
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            parts.append(payload.decode(charset, errors="replace"))
            body = "\n".join(parts)
        else:
            try:
                body = parsed.get_content()
            except Exception:
                payload = parsed.get_payload(decode=True)
                if payload:
                    charset = parsed.get_content_charset() or "utf-8"
                    body = payload.decode(charset, errors="replace")
                else:
                    body = str(parsed.get_payload() or "")
    except Exception:
        # Fallback for malformed messages.
        subject_match = re.search(r"^Subject:\s*(.*)$", raw_message, flags=re.IGNORECASE | re.MULTILINE)
        if subject_match:
            subject = subject_match.group(1).strip()
        split_parts = re.split(r"\r?\n\r?\n", raw_message, maxsplit=1)
        body = split_parts[1] if len(split_parts) > 1 else raw_message

    return normalize_text(subject), normalize_text(body)


def _evaluate_patterns(text: str, patterns: Iterable[Tuple[re.Pattern, str, int]]) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    for pattern, reason, weight in patterns:
        if pattern.search(text):
            score += weight
            reasons.append(reason)
    return score, reasons


def classify_email(subject: str, body: str) -> ClassificationResult:
    combined = normalize_text(f"{subject} {body}").lower()
    if not combined:
        return ClassificationResult(label="SAFE", confidence=50, reasons=["Empty content after cleaning"])

    phish_score, phish_reasons = _evaluate_patterns(combined, PHISHING_PATTERNS)
    spam_score, spam_reasons = _evaluate_patterns(combined, SPAM_PATTERNS)

    if phish_score >= 25 and phish_score >= spam_score + 5:
        confidence = min(98, 55 + phish_score)
        return ClassificationResult(label="PHISHING", confidence=confidence, reasons=phish_reasons[:2] or ["Phishing-like intent indicators"])

    if spam_score >= 20:
        confidence = min(97, 50 + spam_score)
        return ClassificationResult(label="SPAM", confidence=confidence, reasons=spam_reasons[:2] or ["Bulk promotional indicators"])

    safe_confidence = 70
    if phish_score == 0 and spam_score == 0:
        safe_confidence = 92
    elif phish_score + spam_score < 10:
        safe_confidence = 80

    return ClassificationResult(label="SAFE", confidence=safe_confidence, reasons=["No strong phishing or spam indicators"])


def count_rows(csv_path: Path) -> int:
    total = 0
    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for _ in reader:
            total += 1
    return total


def process_dataset(dataset_path: Path, output_path: Path) -> None:
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    # Allow very large message fields.
    csv.field_size_limit(1024 * 1024 * 1024)

    total_rows = count_rows(dataset_path)
    processed = 0
    skipped = 0

    with dataset_path.open("r", encoding="utf-8", errors="replace", newline="") as in_f, output_path.open(
        "w", encoding="utf-8", newline=""
    ) as out_f:
        reader = csv.DictReader(in_f)
        writer = csv.writer(out_f)
        writer.writerow(["file_path", "subject", "body", "label", "confidence", "reasons"])

        for row in reader:
            processed += 1
            try:
                file_path = (row.get("file") or row.get("file_path") or "").strip()
                raw_message = row.get("message") or row.get("body") or ""

                if not raw_message or not raw_message.strip():
                    skipped += 1
                    continue

                subject, body = extract_subject_and_body(raw_message)
                if not subject and not body:
                    skipped += 1
                    continue

                result = classify_email(subject, body)
                writer.writerow(
                    [
                        file_path,
                        subject,
                        body,
                        result.label,
                        result.confidence,
                        " | ".join(result.reasons),
                    ]
                )
            except Exception:
                skipped += 1
                continue

            if processed % 1000 == 0 or processed == total_rows:
                if total_rows > 0:
                    pct = (processed / total_rows) * 100
                    print(f"Progress: {processed}/{total_rows} ({pct:.1f}%)")
                else:
                    print(f"Progress: processed {processed}")

    print(f"Done. Processed: {processed}, Skipped: {skipped}, Output: {output_path}")


def main() -> None:
    process_dataset(DATASET_PATH, OUTPUT_PATH)


if __name__ == "__main__":
    main()