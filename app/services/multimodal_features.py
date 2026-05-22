from __future__ import annotations

import re
from email.utils import parseaddr
from html.parser import HTMLParser
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
CREDENTIAL_PATTERN = re.compile(
    r"\b(password|passcode|otp|mfa|2fa|login|sign\s*in|verify|confirm|account|wallet|seed phrase|private key)\b",
    re.IGNORECASE,
)
MALICIOUS_SCRIPT_PATTERN = re.compile(
    r"(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|document\.write|eval\s*\(|atob\s*\(|fromCharCode|"
    r"ActiveXObject|WScript\.Shell|CreateObject|Shell\.Application)",
    re.IGNORECASE,
)
OFFICE_MACRO_PATTERN = re.compile(
    r"\b(autoopen|document_open|workbook_open|vba|vbaproject|macros?|enable\s+editing|enable\s+content)\b",
    re.IGNORECASE,
)
HTML_ATTACHMENT_PATTERN = re.compile(r"<\s*(html|form|script|iframe|input|meta)\b", re.IGNORECASE)
BASE64_BLOB_PATTERN = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
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


class _DomSignalParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms = 0
        self.password_inputs = 0
        self.hidden_inputs = 0
        self.email_inputs = 0
        self.total_inputs = 0
        self.iframes = 0
        self.scripts = 0
        self.external_scripts = 0
        self.external_images = 0
        self.meta_refresh = 0
        self.autocomplete_off = 0
        self.event_handlers = 0
        self.inline_styles_hidden = 0
        self.form_actions: list[str] = []
        self.resource_urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attr_map = {name.lower(): (value or "") for name, value in attrs}

        if tag == "form":
            self.forms += 1
            action = attr_map.get("action", "").strip()
            if action:
                self.form_actions.append(action)

        if tag == "input":
            self.total_inputs += 1
            input_type = attr_map.get("type", "text").lower()
            input_name = " ".join([attr_map.get("name", ""), attr_map.get("id", ""), attr_map.get("placeholder", "")])
            if input_type == "password" or "password" in input_name.lower():
                self.password_inputs += 1
            if input_type == "hidden":
                self.hidden_inputs += 1
            if input_type == "email" or "email" in input_name.lower() or "user" in input_name.lower():
                self.email_inputs += 1

        if tag == "iframe":
            self.iframes += 1

        if tag == "script":
            self.scripts += 1
            src = attr_map.get("src", "").strip()
            if src:
                self.resource_urls.append(src)
                if src.startswith(("http://", "https://", "//")):
                    self.external_scripts += 1

        if tag in {"img", "iframe", "link"}:
            src = (attr_map.get("src") or attr_map.get("href") or "").strip()
            if src:
                self.resource_urls.append(src)
                if src.startswith(("http://", "https://", "//")):
                    self.external_images += 1

        if tag == "meta":
            http_equiv = attr_map.get("http-equiv", "").lower()
            content = attr_map.get("content", "").lower()
            if http_equiv == "refresh" or "url=" in content:
                self.meta_refresh += 1

        if attr_map.get("autocomplete", "").lower() == "off":
            self.autocomplete_off += 1

        if any(name.startswith("on") for name in attr_map):
            self.event_handlers += 1

        style = attr_map.get("style", "").replace(" ", "").lower()
        if any(token in style for token in ("display:none", "visibility:hidden", "opacity:0", "height:0", "width:0")):
            self.inline_styles_hidden += 1


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


def _attachment_size(item: Any) -> int:
    if not isinstance(item, dict):
        return 0
    try:
        return int(item.get("size") or 0)
    except (TypeError, ValueError):
        return 0


def _attachment_content(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("content_sample") or item.get("content") or item.get("text") or "")
    return str(item or "")


def _score_attachment_content(name: str, mime: str, content: str) -> tuple[float, list[str], int, int]:
    sample = content[:250000]
    sample_lower = sample.lower()
    visible = name or mime or "attachment"
    score = 0.0
    reasons: list[str] = []
    image_count = 0
    qr_count = 0

    if not sample:
        return score, reasons, image_count, qr_count

    if HTML_ATTACHMENT_PATTERN.search(sample):
        score += 0.45
        reasons.append(f"Attachment contains HTML or embedded webpage content: {visible}")

    if FORM_PATTERN.search(sample) and PASSWORD_PATTERN.search(sample):
        score += 0.9
        reasons.append(f"Attachment contains a credential form: {visible}")

    if CREDENTIAL_PATTERN.search(sample):
        score += 0.25
        reasons.append(f"Attachment content asks for credentials or verification: {visible}")

    if OFFICE_MACRO_PATTERN.search(sample):
        score += 0.75
        reasons.append(f"Attachment references macros or enable-content behavior: {visible}")

    if MALICIOUS_SCRIPT_PATTERN.search(sample):
        score += 0.8
        reasons.append(f"Attachment contains script or command-execution indicators: {visible}")

    if BASE64_BLOB_PATTERN.search(sample) and ("script" in sample_lower or "eval" in sample_lower):
        score += 0.45
        reasons.append(f"Attachment contains obfuscated encoded script content: {visible}")

    if QR_PATTERN.search(sample):
        qr_count += 1
        score += 0.65
        reasons.append(f"Attachment content mentions QR or scan-code flow: {visible}")

    if "captcha" in sample_lower and CREDENTIAL_PATTERN.search(sample):
        score += 0.35
        reasons.append(f"Attachment combines CAPTCHA language with credential collection: {visible}")

    urls = extract_urls(sample)
    if len(urls) >= 3:
        score += 0.25
        reasons.append(f"Attachment contains multiple embedded links: {visible}")

    if IMAGE_PATTERN.search(name) or mime.startswith("image/"):
        image_count += 1

    return score, reasons, image_count, qr_count


def _score_attachments(attachments: list[Any]) -> tuple[float, list[str], int, int]:
    score = 0.0
    reasons: list[str] = []
    image_count = 0
    qr_count = 0

    for item in attachments:
        name = _attachment_name(item)
        mime = _attachment_mime(item)
        size = _attachment_size(item)
        content = _attachment_content(item)
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

        if size and size > 15 * 1024 * 1024 and ext in {".zip", ".rar", ".7z", ".iso", ".img"}:
            score += 0.35
            reasons.append(f"Large archive or disk-image attachment needs review: {visible}")

        content_score, content_reasons, content_images, content_qr = _score_attachment_content(name, mime, content)
        score += content_score
        reasons.extend(content_reasons)
        image_count += content_images
        qr_count += content_qr

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
    dom = _DomSignalParser()
    try:
        dom.feed(html)
    except Exception:
        reasons.append("Webpage HTML is malformed or difficult to parse")
        score += 0.15

    if FORM_PATTERN.search(html) and PASSWORD_PATTERN.search(html):
        score += 0.75
        reasons.append("Webpage contains a password or credential form")

    if dom.forms and (dom.password_inputs or dom.email_inputs):
        score += 0.7
        reasons.append("DOM contains login-style form fields")

    if dom.form_actions:
        action_domains = {_registered_domain(action) for action in dom.form_actions if _registered_domain(action)}
        if sender_domain and any(domain and domain != sender_domain for domain in action_domains):
            score += 0.55
            reasons.append("Form submits credentials to a domain different from sender")
        elif len(action_domains) >= 2:
            score += 0.35
            reasons.append("Forms submit to multiple external domains")

    if dom.hidden_inputs >= 3:
        score += 0.25
        reasons.append("DOM contains many hidden form fields")

    if dom.iframes:
        score += min(0.45, dom.iframes * 0.2)
        reasons.append("Webpage embeds iframe content")

    if dom.meta_refresh:
        score += 0.35
        reasons.append("Webpage uses meta refresh redirect")

    if dom.external_scripts >= 3:
        score += 0.25
        reasons.append("Webpage loads several external scripts")

    if dom.event_handlers >= 4:
        score += 0.25
        reasons.append("DOM uses many inline event handlers")

    if "display:none" in html_lower or "visibility:hidden" in html_lower or dom.inline_styles_hidden:
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

    if MALICIOUS_SCRIPT_PATTERN.search(html):
        score += 0.55
        reasons.append("Webpage contains suspicious script or command patterns")

    if "captcha" in html_lower and CREDENTIAL_PATTERN.search(html):
        score += 0.35
        reasons.append("Webpage combines CAPTCHA flow with credential prompts")

    if any(brand in html_lower for brand in BRAND_WORDS) and domains:
        brand_domains = [brand for brand in BRAND_WORDS if brand in html_lower and not any(brand in domain for domain in domains)]
        if brand_domains:
            score += 0.3
            reasons.append("Webpage text imitates a known brand without matching domain evidence")

    all_urls = list(dict.fromkeys(all_urls + dom.form_actions + dom.resource_urls))
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
