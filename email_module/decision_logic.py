import ipaddress
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


TRUSTED_SENDER_DOMAINS = {
    "google.com",
    "discord.com",
    "adobe.com",
    "microsoft.com",
    "github.com",
}

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "shorturl.at",
}

COMMON_SECOND_LEVEL_SUFFIXES = {
    "co.uk",
    "org.uk",
    "com.au",
    "co.in",
    "co.jp",
}

URL_PATTERN = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
RANDOM_TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9]{18,}")
SUSPICIOUS_KEYWORDS = re.compile(
    r"login|verify|secure|update|password|confirm|billing|account|wallet|mfa|2fa|otp|invoice|payment|quarantine",
    re.IGNORECASE,
)
URGENCY_PATTERN = re.compile(
    r"urgent|immediately|suspend|final notice|within\s+\d+\s*hours|expires?\s+today|action\s+required|limited\s+time",
    re.IGNORECASE,
)
GENERIC_GREETING_PATTERN = re.compile(r"\b(dear customer|dear user|valued customer|hello user|sir/madam)\b", re.IGNORECASE)
BEC_PATTERN = re.compile(
    r"\b(gift cards?|wire transfer|bank details|are you available|are you at your desk|confidential|payment change|vendor update)\b",
    re.IGNORECASE,
)
QR_LURE_PATTERN = re.compile(r"\b(qr|qrcode|scan\s+code|barcode|use your phone)\b", re.IGNORECASE)


def _normalize_domain(domain: Optional[str]) -> str:
    return (domain or "").strip().lower().strip(".")


def _registered_domain(hostname: str) -> str:
    host = _normalize_domain(hostname)
    if not host:
        return ""

    parts = host.split(".")
    if len(parts) < 2:
        return host

    last_two = ".".join(parts[-2:])
    if len(parts) >= 3 and last_two in COMMON_SECOND_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def extract_domain_from_sender(sender_email: str) -> str:
    sender = (sender_email or "").strip().lower()
    if "@" not in sender:
        return ""
    domain = sender.split("@", 1)[1].strip()
    return _registered_domain(domain)


def _extract_domain_from_url(url: str) -> str:
    parsed = urlparse(url or "")
    host = _normalize_domain(parsed.hostname or "")
    return _registered_domain(host)


def _extract_urls(text: str) -> List[str]:
    return URL_PATTERN.findall(text or "")


def _risk_level_for(label: str) -> str:
    if label == "PHISHING":
        return "HIGH"
    if label == "SUSPICIOUS":
        return "MEDIUM"
    return "LOW"


def _is_ip_host(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def _is_shortener(url: str) -> bool:
    host = _normalize_domain(urlparse(url).hostname or "")
    return any(host == short or host.endswith("." + short) for short in URL_SHORTENERS)


def _is_trusted_host(host: str) -> bool:
    normalized = _normalize_domain(host)
    return any(normalized == domain or normalized.endswith("." + domain) for domain in TRUSTED_SENDER_DOMAINS)


def _looks_random(url: str) -> bool:
    tokens = RANDOM_TOKEN_PATTERN.findall(url or "")
    for token in tokens:
        vowels = sum(1 for ch in token.lower() if ch in "aeiou")
        if vowels <= max(1, len(token) // 10):
            return True
    return False


def _is_suspicious_sender_domain(sender_domain: str) -> bool:
    domain = _normalize_domain(sender_domain)
    if not domain or domain in TRUSTED_SENDER_DOMAINS:
        return False

    sld = domain.split(".")[0]
    digit_count = sum(ch.isdigit() for ch in sld)
    hyphen_count = sld.count("-")
    vowels = sum(ch in "aeiou" for ch in sld)

    if digit_count >= 2 or hyphen_count >= 2:
        return True
    if len(sld) >= 14 and vowels <= max(1, len(sld) // 12):
        return True
    return False


def _ml_base_risk(ml_label: str, confidence: float) -> float:
    label = (ml_label or "SAFE").upper().strip()
    conf = float(max(0.0, min(1.0, confidence)))

    if label == "PHISHING":
        return 0.95 + conf
    if label in {"SPAM", "SUSPICIOUS"}:
        return 0.65 + (0.65 * conf)
    return 0.15 + (0.25 * (1.0 - conf))


def _analyze_links(
    urls: List[str],
    sender_domain: str,
    sender_is_trusted: bool,
) -> Tuple[float, List[str], int, int, int, int]:
    score = 0.0
    reasons: List[str] = []
    mismatch_count = 0
    match_count = 0
    bad_link_count = 0
    keyword_hits = 0

    for url in urls:
        try:
            parsed = urlparse(url)
        except ValueError:
            score += 0.25
            reasons.append("Malformed link detected")
            bad_link_count += 1
            continue
        scheme = (parsed.scheme or "").lower()
        host = _normalize_domain(parsed.hostname or "")
        url_domain = _extract_domain_from_url(url)
        trusted_url_domain = _is_trusted_host(host)

        domain_matches_sender = False

        if sender_domain and url_domain:
            if url_domain == sender_domain or url_domain.endswith("." + sender_domain):
                match_count += 1
                domain_matches_sender = True
            else:
                # Links to other trusted domains are treated as slight anomalies,
                # not strong mismatches, to reduce false positives for real services.
                if trusted_url_domain and sender_is_trusted:
                    score += 0.08
                    reasons.append("Link points to another trusted domain")
                else:
                    mismatch_count += 1

        # Requirement: trusted URL domains should not receive generic link-risk penalties.
        if trusted_url_domain:
            if domain_matches_sender:
                reasons.append("Trusted service link matches sender domain")
            continue

        if _is_ip_host(url):
            score += 0.7
            reasons.append("Link uses raw IP address")
            bad_link_count += 1

        if _is_shortener(url):
            score += 0.6
            reasons.append("Link uses URL shortener")
            bad_link_count += 1

        if scheme == "http":
            score += 0.2
            reasons.append("Link uses HTTP instead of HTTPS")
            bad_link_count += 1

        if _looks_random(url):
            score += 0.22
            reasons.append("Link contains random-looking tokens")
            bad_link_count += 1

        if SUSPICIOUS_KEYWORDS.search(url):
            score += 0.2
            reasons.append("Link contains phishing-related keywords")
            keyword_hits += 1

    if mismatch_count > 0:
        score += min(1.2, mismatch_count * 0.55)
        reasons.append("Suspicious link mismatch with sender domain")

    if match_count > 0 and mismatch_count == 0:
        score -= 0.45
        reasons.append("Links match sender domain")

    return max(0.0, score), reasons, mismatch_count, match_count, bad_link_count, keyword_hits


def evaluate_email(
    subject: str,
    sender: str,
    body: str,
    ml_label: str,
    confidence: float,
) -> Dict[str, float | str | List[str]]:
    conf = float(max(0.0, min(1.0, confidence)))
    sender_domain = extract_domain_from_sender(sender)
    urls = _extract_urls(body)
    sender_is_trusted = sender_domain in TRUSTED_SENDER_DOMAINS
    sender_is_suspicious = bool(sender_domain and _is_suspicious_sender_domain(sender_domain))

    reasons: List[str] = []
    score = _ml_base_risk(ml_label, conf)

    if sender_is_trusted:
        score -= 0.62
        reasons.append("Trusted sender domain")
    elif sender_is_suspicious:
        score += 0.55
        reasons.append("Sender domain pattern appears suspicious")

    if URGENCY_PATTERN.search((subject or "") + " " + (body or "")):
        score += 0.2
        reasons.append("Urgency language detected")

    combined_text = f"{subject or ''} {body or ''}"
    if GENERIC_GREETING_PATTERN.search(combined_text):
        score += 0.15
        reasons.append("Generic greeting detected")

    if BEC_PATTERN.search(combined_text):
        score += 0.35
        reasons.append("Business-email-compromise style wording detected")

    if QR_LURE_PATTERN.search(combined_text) and SUSPICIOUS_KEYWORDS.search(combined_text):
        score += 0.45
        reasons.append("QR or scan-code lure combined with account-security language")

    link_score, link_reasons, mismatch_count, match_count, bad_link_count, keyword_hits = _analyze_links(
        urls,
        sender_domain,
        sender_is_trusted,
    )
    score += link_score
    reasons.extend(link_reasons)

    # Domain match should cancel most non-critical risk for trusted senders.
    if sender_is_trusted and urls and mismatch_count == 0 and match_count == len(urls):
        score -= 0.65
        reasons.append("Domain alignment confidence boost")

    normalized_ml = (ml_label or "SAFE").upper().strip()
    strong_phishing_signals = (
        mismatch_count > 0
        or sender_is_suspicious
        or (keyword_hits > 0 and bad_link_count > 0)
    )

    # Trust-priority override for known services with fully matching links.
    if (
        sender_is_trusted
        and len(urls) > 0
        and mismatch_count == 0
        and match_count == len(urls)
        and not (normalized_ml == "PHISHING" and conf > 0.99 and strong_phishing_signals)
    ):
        final_label = "SAFE"
        reasons.append("Trusted sender with fully matching link domains")
    elif normalized_ml == "PHISHING" and conf >= 0.85 and link_score >= 0.5 and mismatch_count > 0:
        final_label = "PHISHING"
    elif score >= 1.95 and strong_phishing_signals:
        final_label = "PHISHING"
    elif score >= 0.9:
        final_label = "SUSPICIOUS"
    else:
        final_label = "SAFE"

    # Trusted senders with slight anomalies should not jump to PHISHING.
    if sender_is_trusted and final_label == "PHISHING" and not sender_is_suspicious:
        if mismatch_count == 0 or (mismatch_count == 1 and bad_link_count <= 1):
            final_label = "SUSPICIOUS"
            reasons.append("Trusted sender with slight anomalies downgraded to suspicious")

    # Keep high-confidence phishing predictions from being blindly downgraded.
    if normalized_ml == "PHISHING" and conf >= 0.97 and final_label == "SAFE":
        final_label = "SUSPICIOUS"
        reasons.append("High-confidence ML phishing signal retained")

    # Positive trust signal when model is low risk and links align.
    if (
        normalized_ml == "SAFE"
        and conf >= 0.70
        and sender_is_trusted
        and mismatch_count == 0
    ):
        if final_label == "SUSPICIOUS":
            final_label = "SAFE"
        reasons.append("Trusted sender and matching domains")

    confidence_adjustment = max(-0.2, min(0.2, (score - 1.0) * 0.15))
    final_confidence = float(max(0.01, min(0.99, conf + confidence_adjustment)))

    unique_reasons = list(dict.fromkeys(reasons))
    if not unique_reasons:
        unique_reasons = ["No additional risk signals detected"]

    return {
        "label": final_label,
        "confidence": final_confidence,
        "risk_level": _risk_level_for(final_label),
        "reasons": unique_reasons,
    }


def apply_decision_layer(
    raw_label: str,
    confidence: float,
    subject: str,
    sender_domain: Optional[str] = None,
    body: str = "",
    sender: str = "",
) -> Dict[str, float | str | List[str]]:
    normalized_sender = sender or (f"unknown@{sender_domain}" if sender_domain else "")
    return evaluate_email(
        subject=subject,
        sender=normalized_sender,
        body=body,
        ml_label=raw_label,
        confidence=confidence,
    )
