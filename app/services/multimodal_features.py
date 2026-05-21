from __future__ import annotations

import re
from email.utils import parseaddr
from pathlib import PurePath
from typing import Any
from urllib.parse import urlparse


URL_PATTERN = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
HREF_PATTERN = re.compile(r"""href=["']([^"']+)["']""", re.IGNORECASE)
SRC_PATTERN = re.compile(r"""src=["']([^"']+)["']""", re.IGNORECASE)
FORM_PATTERN = re.compile(r"<form\b", re.IGNORECASE)
PASSWORD_PATTERN = re.compile(r"type=[\"']?password|password", re.IGNORECASE)
QR_PATTERN = re.compile(r"\b(qr|qrcode|scan\s+code|barcode)\b", re.IGNORECASE)
IMAGE_PATTERN = re.compile(r"\.(png|jpe?g|gif|webp|bmp|tiff?)$", re.IGNORECASE)
RISKY_ATTACHMENT_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".com",
    ".scr",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".wsf",
    ".ps1",
    ".iso",
    ".img",
    ".lnk",
    ".hta",
    ".jar",
}
SUSPICIOUS_ATTACHMENT_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".docm",
    ".xlsm",
    ".pptm",
    ".html",
    ".htm",
    ".pdf",
}
BRAND_WORDS = {
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "bank",
    "sbi",
    "hdfc",
    "icici",
}


def extract_urls(*texts: str) -> list[str]:
    found: list[str] = []
    for text in texts:
        found.extend(URL_PATTERN.findall(text or ""))
    return list(dict.fromkeys(url.strip().rstrip(".,;") for url in found if url.strip()))


def _registered_domain(value: str) -> str:
    host = (value or "").lower().strip().strip(".")
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if "://" in host:
        host = urlparse(host).hostname or ""
    parts = [part for part in host.split(".") if part]
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def _sender_parts(sender: str) -> tuple[str, str, str]:
    display, address = parseaddr(sender or "")
    address = (address or sender or "").strip().lower()
    return display.lower(), address, _registered_domain(address)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        lines = re.split(r"[\n,]+", value)
        return [line.strip() for line in lines if line.strip()]
    return [str(value).strip()]


def _attachment_name(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("filename") or item.get("name") or "").strip()
    return str(item or "").strip()


def _attachment_mime(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("mime_type") or item.get("mimeType") or "").lower()
    return ""


def _score_attachments(attachments: list[Any]) -> tuple[float, list[str], int, int]:
    score = 0.0
    reasons: list[str] = []
    image_count = 0
    qr_count = 0

    for item in attachments:
        name = _attachment_name(item)
        mime = _attachment_mime(item)
        ext = PurePath(name.lower()).suffix
        visible = name or mime or "attachment"

        if ext in RISKY_ATTACHMENT_EXTENSIONS:
            score += 1.0
            reasons.append(f"Risky attachment type found: {visible}")
        elif ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS:
            score += 0.35
            reasons.append(f"Attachment needs review: {visible}")

        if IMAGE_PATTERN.search(name) or mime.startswith("image/"):
            image_count += 1
            reasons.append(f"Image attachment detected: {visible}")

        if QR_PATTERN.search(name):
            qr_count += 1
            score += 0.55
            reasons.append(f"QR-code style attachment detected: {visible}")

    if len(attachments) >= 5:
        score += 0.2
        reasons.append("Email contains many attachments")

    return score, reasons, image_count, qr_count


def _score_sender(sender: str, reply_to: str = "", return_path: str = "") -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    display, address, domain = _sender_parts(sender)
    _, reply_address, reply_domain = _sender_parts(reply_to)
    _, return_address, return_domain = _sender_parts(return_path)

    if sender and "@" not in address:
        score += 0.25
        reasons.append("Sender address is incomplete or unusual")

    for brand in BRAND_WORDS:
        if brand in display and domain and brand not in domain:
            score += 0.65
            reasons.append("Sender display name imitates a known brand")
            break

    if reply_address and reply_domain and domain and reply_domain != domain:
        score += 0.5
        reasons.append("Reply-To domain differs from sender domain")

    if return_address and return_domain and domain and return_domain != domain:
        score += 0.35
        reasons.append("Return-Path domain differs from sender domain")

    return score, reasons


def _score_webpage(webpage_text: str, urls: list[str], sender_domain: str) -> tuple[float, list[str], list[str]]:
    html = webpage_text or ""
    html_lower = html.lower()
    page_urls = extract_urls(html, " ".join(HREF_PATTERN.findall(html)), " ".join(SRC_PATTERN.findall(html)))
    all_urls = list(dict.fromkeys(urls + page_urls))
    domains = {_registered_domain(url) for url in all_urls if _registered_domain(url)}
    score = 0.0
    reasons: list[str] = []

    if FORM_PATTERN.search(html) and PASSWORD_PATTERN.search(html):
        score += 0.75
        reasons.append("Webpage contains a password or credential form")

    if "display:none" in html_lower or "visibility:hidden" in html_lower:
        score += 0.25
        reasons.append("Webpage contains hidden visual elements")

    if sender_domain and domains:
        foreign = [domain for domain in domains if domain != sender_domain]
        if len(foreign) >= 2:
            score += 0.35
            reasons.append("Webpage references multiple external domains")

    if any(word in html_lower for word in ("verify account", "update password", "confirm identity")):
        score += 0.3
        reasons.append("Webpage text asks for account verification")

    return score, reasons, all_urls


def analyze_multimodal_features(
    *,
    subject: str = "",
    body: str = "",
    sender: str = "",
    url: str = "",
    links: list[str] | str | None = None,
    attachments: list[Any] | str | None = None,
    reply_to: str = "",
    return_path: str = "",
    webpage_text: str = "",
    image_indicators: list[str] | str | None = None,
    qr_text: str = "",
) -> dict[str, Any]:
    display, address, sender_domain = _sender_parts(sender)
    manual_links = _as_list(links)
    attachment_items = attachments if isinstance(attachments, list) else _as_list(attachments)
    image_notes = _as_list(image_indicators)
    urls = extract_urls(body, url, "\n".join(manual_links))

    score = 0.0
    reasons: list[str] = []

    if len(urls) >= 3:
        score += 0.25
        reasons.append("Multiple links found in message")

    link_domains = {_registered_domain(item) for item in urls if _registered_domain(item)}
    if sender_domain and len([domain for domain in link_domains if domain != sender_domain]) >= 2:
        score += 0.45
        reasons.append("Links point to domains different from sender")

    sender_score, sender_reasons = _score_sender(sender, reply_to, return_path)
    attachment_score, attachment_reasons, image_count, qr_count = _score_attachments(list(attachment_items))
    webpage_score, webpage_reasons, webpage_urls = _score_webpage(webpage_text, urls, sender_domain)

    score += sender_score + attachment_score + webpage_score
    reasons.extend(sender_reasons + attachment_reasons + webpage_reasons)

    image_text = " ".join(image_notes + [qr_text, subject, body])
    if image_notes:
        image_count += len(image_notes)
        reasons.append("Image-based content supplied for analysis")

    if QR_PATTERN.search(image_text):
        qr_count += 1
        score += 0.65
        reasons.append("QR code or scan-code language detected")

    if image_count and not urls and ("login" in image_text.lower() or "verify" in image_text.lower()):
        score += 0.35
        reasons.append("Image content carries login or verification wording")

    if score >= 1.25:
        label = "PHISHING"
        risk_level = "HIGH"
        confidence = min(0.96, 0.68 + score * 0.12)
    elif score >= 0.45:
        label = "SUSPICIOUS"
        risk_level = "MEDIUM"
        confidence = min(0.9, 0.55 + score * 0.15)
    else:
        label = "SAFE"
        risk_level = "LOW"
        confidence = 0.5

    return {
        "label": label,
        "confidence": float(confidence),
        "risk_level": risk_level,
        "score": round(score, 3),
        "reasons": list(dict.fromkeys(reasons)),
        "feature_summary": {
            "sender_address": address,
            "sender_domain": sender_domain,
            "link_count": len(urls),
            "unique_link_domains": sorted(domain for domain in link_domains if domain),
            "attachment_count": len(attachment_items),
            "image_count": image_count,
            "qr_signal_count": qr_count,
            "webpage_url_count": len(webpage_urls),
        },
    }


def merge_multimodal_result(base_result: dict[str, Any], multimodal_result: dict[str, Any]) -> dict[str, Any]:
    base_label = str(base_result.get("label", "SAFE")).upper()
    modal_label = str(multimodal_result.get("label", "SAFE")).upper()
    reasons = list(base_result.get("reasons", [])) + list(multimodal_result.get("reasons", []))
    base_conf = float(base_result.get("confidence", 0.0))
    modal_conf = float(multimodal_result.get("confidence", 0.0))

    rank = {"SAFE": 0, "SUSPICIOUS": 1, "PHISHING": 2}
    final_label = base_label if rank.get(base_label, 0) >= rank.get(modal_label, 0) else modal_label

    if base_label == "SAFE" and modal_label == "PHISHING":
        reasons.append("Multimodal signals upgraded a safe text result to phishing")
    elif base_label == "SAFE" and modal_label == "SUSPICIOUS":
        reasons.append("Multimodal signals require manual review")
    elif base_label == "SUSPICIOUS" and modal_label == "PHISHING":
        reasons.append("Multimodal signals strengthened suspicious result")

    risk_level = "HIGH" if final_label == "PHISHING" else "MEDIUM" if final_label == "SUSPICIOUS" else "LOW"
    confidence = max(base_conf, modal_conf)
    if final_label != base_label:
        confidence = max(confidence, 0.72 if final_label == "PHISHING" else 0.62)

    merged = dict(base_result)
    merged.update(
        {
            "label": final_label,
            "confidence": float(min(0.99, confidence)),
            "risk_level": risk_level,
            "reasons": list(dict.fromkeys(str(reason) for reason in reasons if str(reason).strip())),
            "feature_summary": multimodal_result.get("feature_summary", {}),
        }
    )
    return merged
