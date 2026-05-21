from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "bank",
    "paypal",
    "account",
    "signin",
    "sign-in",
    "webscr",
    "confirm",
    "password",
    "billing",
    "support",
    "security",
    "session",
]


def _count_digits(value: str) -> int:
    return sum(ch.isdigit() for ch in value)


def _has_ip(hostname: str) -> int:
    if not hostname:
        return 0
    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0


def extract_features(url: str) -> list[float]:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    url_lower = url.lower()

    dot_count = url_lower.count(".")
    hyphen_count = url_lower.count("-")
    at_count = url_lower.count("@")
    slash_count = url_lower.count("/")
    qmark_count = url_lower.count("?")
    equal_count = url_lower.count("=")

    url_length = len(url_lower)
    hostname_length = len(hostname)
    path_length = len(path)
    query_length = len(query)

    digit_count = _count_digits(url_lower)
    digit_ratio = digit_count / max(1, url_length)

    host_parts = [p for p in hostname.split(".") if p]
    subdomain_count = max(0, len(host_parts) - 2) if len(host_parts) >= 2 else 0
    tld_length = len(host_parts[-1]) if host_parts else 0

    has_https = 1 if parsed.scheme.lower() == "https" else 0
    has_ip = _has_ip(hostname)
    https_token_in_host = 1 if "https" in hostname else 0

    kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    kw_flag = 1 if kw_count > 0 else 0

    return [
        url_length,
        hostname_length,
        path_length,
        query_length,
        has_https,
        dot_count,
        hyphen_count,
        at_count,
        slash_count,
        qmark_count,
        equal_count,
        digit_count,
        digit_ratio,
        subdomain_count,
        tld_length,
        has_ip,
        https_token_in_host,
        kw_count,
        kw_flag,
    ]


def feature_names() -> list[str]:
    return [
        "url_length",
        "hostname_length",
        "path_length",
        "query_length",
        "has_https",
        "dot_count",
        "hyphen_count",
        "at_count",
        "slash_count",
        "qmark_count",
        "equal_count",
        "digit_count",
        "digit_ratio",
        "subdomain_count",
        "tld_length",
        "has_ip",
        "https_token_in_host",
        "suspicious_kw_count",
        "suspicious_kw_flag",
    ]
