import re
from typing import Dict
from urllib.parse import urlparse

from url_module.url_guard import score_url


def _normalize_for_display(url: str) -> str:
    value = (url or "").strip()
    if not value:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "http://" + value
    return value


def _domain_for_display(url: str) -> str:
    try:
        parsed = urlparse(_normalize_for_display(url))
        return (parsed.hostname or "").lower().strip(".")
    except ValueError:
        return ""


def analyze_url(url: str) -> Dict[str, float | str | bool | list[str]]:
    result = score_url(url or "")
    raw_label = str(result.get("label", "Legitimate")).strip().lower()
    confidence = float(result.get("confidence", 0.0))
    analyzed_url = _normalize_for_display(url)
    analyzed_domain = _domain_for_display(url)

    if raw_label == "phishing":
        label = "PHISHING"
        risk_level = "HIGH"
    elif raw_label == "suspicious":
        label = "SUSPICIOUS"
        risk_level = "MEDIUM"
    else:
        label = "SAFE"
        risk_level = "LOW"

    return {
        "label": label,
        "confidence": confidence,
        "risk_level": risk_level,
        "analyzed_url": analyzed_url,
        "analyzed_domain": analyzed_domain,
        "allowlisted": bool(result.get("allowlisted", False)),
        "raw_label": str(result.get("label", "")),
        "threshold": float(result.get("threshold", 0.0)),
        "reasons": list(result.get("reasons", [])),
    }
