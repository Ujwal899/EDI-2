from __future__ import annotations

import csv
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse
import sys

import joblib

try:
    from url_module.url_features import extract_features
except ImportError:  # Support direct script execution.
    sys.path.append(str(Path(__file__).resolve().parent.parent))
    from url_module.url_features import extract_features

BASE_DIR = Path(__file__).resolve().parent
BEST_MODEL_PATH = BASE_DIR / "models" / "urls" / "url_model_best.joblib"
THRESHOLD_PATH = BASE_DIR / "models" / "urls" / "url_model_threshold.txt"
PHISHTANK_CLEAN_PATH = BASE_DIR / "data" / "urls" / "phishing_site_urls_clean.csv"
PHISHTANK_RAW_PATH = BASE_DIR / "data" / "urls" / "phishing_site_urls.csv"

ALLOWLIST = {
    "google.com",
    "microsoft.com",
    "github.com",
    "adobe.com",
    "discord.com",
    "paypal.com",
    "apple.com",
    "amazon.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "chase.com",
}

_model = None
_threshold = None
_phishing_url_set = None

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "gq",
    "tk",
    "ml",
    "cf",
    "zip",
    "work",
    "country",
    "stream",
}

PHISHING_KEYWORDS = re.compile(r"login|verify|secure|update|password|confirm|signin|account", re.IGNORECASE)
RANDOM_TOKEN_RE = re.compile(r"[a-zA-Z0-9]{20,}")


def _load_threshold() -> float:
    global _threshold
    if _threshold is not None:
        return _threshold
    try:
        with open(THRESHOLD_PATH, "r", encoding="utf-8") as f:
            value = float(f.read().strip())
            _threshold = min(max(value, 0.0), 1.0)
            return _threshold
    except (OSError, ValueError):
        _threshold = 0.9
        return _threshold


def _load_model():
    global _model
    if _model is None:
        _model = joblib.load(BEST_MODEL_PATH)
    return _model


def _normalize_url(raw_url: str) -> str:
    value = (raw_url or "").strip()
    if not value:
        return ""

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "http://" + value

    try:
        parsed = urlparse(value)
    except ValueError:
        return ""

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return ""

    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        return ""

    path = re.sub(r"/+", "/", parsed.path or "/")
    query = (parsed.query or "").strip()
    normalized = f"{scheme}://{host}{path}"
    if query:
        normalized += f"?{query}"
    return normalized


def _load_phishing_url_set() -> set[str]:
    global _phishing_url_set
    if _phishing_url_set is not None:
        return _phishing_url_set

    data: set[str] = set()

    if PHISHTANK_CLEAN_PATH.exists():
        with PHISHTANK_CLEAN_PATH.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                label = str(row.get("label", "")).strip().lower()
                if label not in {"bad", "phishing"}:
                    continue
                candidate = _normalize_url(str(row.get("clean_url", "")))
                if candidate:
                    data.add(candidate)

    elif PHISHTANK_RAW_PATH.exists():
        with PHISHTANK_RAW_PATH.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                label = str(row.get("Label", row.get("label", ""))).strip().lower()
                if label not in {"bad", "phishing"}:
                    continue
                candidate = _normalize_url(str(row.get("URL", row.get("url", ""))))
                if candidate:
                    data.add(candidate)

    _phishing_url_set = data
    return _phishing_url_set


def _is_ip_host(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _count_subdomains(hostname: str) -> int:
    parts = [p for p in hostname.split(".") if p]
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


def _analyze_structure(url: str) -> tuple[float, list[str], int]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().strip(".")
    path_query = f"{parsed.path or ''}?{parsed.query or ''}"
    reasons: list[str] = []
    score = 0.0
    strong_count = 0

    if _is_ip_host(host):
        score += 1.1
        strong_count += 1
        reasons.append("URL uses IP address instead of domain")

    subdomain_count = _count_subdomains(host)
    if subdomain_count >= 3:
        score += 0.55
        reasons.append("URL has excessive subdomains")

    if RANDOM_TOKEN_RE.search(path_query):
        score += 0.45
        reasons.append("URL contains long random token")

    if PHISHING_KEYWORDS.search(url):
        score += 0.35
        reasons.append("URL contains phishing keywords")

    if (parsed.scheme or "").lower() == "http":
        score += 0.2
        reasons.append("URL uses HTTP instead of HTTPS")

    return score, reasons, strong_count


def _analyze_domain_reputation(hostname: str) -> tuple[float, list[str], int]:
    host = (hostname or "").lower().strip(".")
    reasons: list[str] = []
    score = 0.0
    strong_count = 0

    if not host:
        return 0.4, ["URL domain is missing or invalid"], 1

    domain_without_tld = host.rsplit(".", 1)[0] if "." in host else host
    tld = host.rsplit(".", 1)[-1] if "." in host else ""

    if len(host) >= 35:
        score += 0.5
        reasons.append("Domain name is unusually long")

    hyphen_count = host.count("-")
    number_count = sum(ch.isdigit() for ch in domain_without_tld)
    if hyphen_count >= 3:
        score += 0.45
        reasons.append("Domain contains many hyphens")
    if number_count >= 4:
        score += 0.4
        reasons.append("Domain contains many numeric characters")

    if tld in SUSPICIOUS_TLDS:
        score += 0.55
        strong_count += 1
        reasons.append("Domain uses suspicious TLD")

    return score, reasons, strong_count


def is_allowlisted(hostname: str) -> bool:
    if not hostname:
        return False
    host = hostname.lower().strip(".")
    return any(host == domain or host.endswith("." + domain) for domain in ALLOWLIST)


def score_url(url: str) -> dict:
    normalized_url = _normalize_url(url)
    if not normalized_url:
        return {
            "label": "Suspicious",
            "phishing": False,
            "confidence": 0.62,
            "allowlisted": False,
            "threshold": _load_threshold(),
            "reasons": ["Invalid or unsupported URL format"],
        }

    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    reasons: list[str] = []

    if is_allowlisted(hostname):
        return {
            "label": "Legitimate",
            "phishing": False,
            "confidence": 1.0,
            "allowlisted": True,
            "threshold": _load_threshold(),
            "reasons": ["URL domain is in allowlist"],
        }

    phishing_set = _load_phishing_url_set()
    if normalized_url in phishing_set:
        return {
            "label": "Phishing",
            "phishing": True,
            "confidence": 0.99,
            "allowlisted": False,
            "threshold": _load_threshold(),
            "reasons": ["URL found in PhishTank phishing dataset"],
        }

    model = _load_model()
    threshold = _load_threshold()
    features = [extract_features(normalized_url)]
    proba = model.predict_proba(features)[0]

    ml_risk = float(proba[1])
    ml_flagged = ml_risk >= threshold
    if ml_flagged:
        reasons.append("ML model predicts phishing with high probability")

    structure_score, structure_reasons, structure_strong = _analyze_structure(normalized_url)
    reputation_score, rep_reasons, rep_strong = _analyze_domain_reputation(hostname)
    reasons.extend(structure_reasons)
    reasons.extend(rep_reasons)

    total_score = (1.2 * ml_risk) + structure_score + reputation_score
    strong_indicators = structure_strong + rep_strong + (1 if ml_risk >= threshold else 0)
    suspicious_indicators = len(structure_reasons) + len(rep_reasons)

    if strong_indicators >= 2 or total_score >= 2.25:
        label = "Phishing"
        confidence = max(0.8, min(0.99, 0.55 + (total_score / 3.0)))
    elif suspicious_indicators >= 2 or total_score >= 1.15:
        label = "Suspicious"
        confidence = max(0.55, min(0.9, 0.45 + (total_score / 4.0)))
    else:
        label = "Legitimate"
        confidence = max(0.55, min(0.98, float(proba[0])))
        if not reasons:
            reasons.append("No strong phishing indicators detected")

    if label == "Legitimate" and ml_flagged:
        reasons = [
            r for r in reasons if r != "ML model predicts phishing with high probability"
        ]
        reasons.append("Model signal mitigated by low-risk URL structure and reputation")

    phishing = label == "Phishing"

    return {
        "label": label,
        "phishing": phishing,
        "confidence": float(confidence),
        "allowlisted": False,
        "threshold": threshold,
        "reasons": list(dict.fromkeys(reasons)),
    }
