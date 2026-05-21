from typing import Dict, List


def combine_email_and_url(
    email_result: Dict[str, float | str | List[str]],
    url_result: Dict[str, float | str | bool],
) -> Dict[str, float | str | List[str]]:
    email_label = str(email_result.get("label", "SAFE")).upper()
    url_label = str(url_result.get("label", "SAFE")).upper()
    reasons: List[str] = list(email_result.get("reasons", []))
    url_conf = float(url_result.get("confidence", 0.0))
    email_conf = float(email_result.get("confidence", 0.0))

    if url_label == "PHISHING":
        reasons.append("URL analyzer flagged phishing link")
    elif url_label == "SUSPICIOUS":
        reasons.append("URL analyzer found suspicious link indicators")
    elif url_label == "SAFE" and url_result.get("allowlisted"):
        reasons.append("URL is allowlisted by URL analyzer")

    reasons.extend([str(r) for r in url_result.get("reasons", []) if str(r).strip()])

    if email_label == "PHISHING" and url_label == "PHISHING":
        return {
            "label": "PHISHING",
            "confidence": max(email_conf, url_conf),
            "risk_level": "HIGH",
            "reasons": list(dict.fromkeys(reasons)),
        }

    if email_label == "PHISHING" and url_label == "SAFE" and email_conf >= 0.96:
        reasons.append("High-confidence phishing signal from email model")
        return {
            "label": "PHISHING",
            "confidence": email_conf,
            "risk_level": "HIGH",
            "reasons": list(dict.fromkeys(reasons)),
        }

    if email_label == "PHISHING" and url_label == "SAFE":
        reasons.append("Email model flagged phishing, but URL signal is safer")
        return {
            "label": "SUSPICIOUS",
            "confidence": max(0.7, email_conf),
            "risk_level": "MEDIUM",
            "reasons": list(dict.fromkeys(reasons)),
        }

    if email_label == "SUSPICIOUS" and url_label == "PHISHING":
        reasons.append("Suspicious email plus phishing URL")
        return {
            "label": "PHISHING",
            "confidence": max(email_conf, url_conf),
            "risk_level": "HIGH",
            "reasons": list(dict.fromkeys(reasons)),
        }

    if email_label == "SUSPICIOUS" and url_label == "SUSPICIOUS":
        reasons.append("Both email and URL have suspicious signals")
        return {
            "label": "SUSPICIOUS",
            "confidence": max(0.7, max(email_conf, url_conf)),
            "risk_level": "MEDIUM",
            "reasons": list(dict.fromkeys(reasons)),
        }

    if email_label == "SAFE" and url_label == "PHISHING":
        reasons.append("Safe-looking email contains phishing URL")
        return {
            "label": "SUSPICIOUS",
            "confidence": max(0.65, url_conf),
            "risk_level": "MEDIUM",
            "reasons": list(dict.fromkeys(reasons)),
        }

    if email_label == "SAFE" and url_label == "SUSPICIOUS":
        reasons.append("Safe-looking email contains suspicious URL")
        return {
            "label": "SUSPICIOUS",
            "confidence": max(0.6, url_conf),
            "risk_level": "MEDIUM",
            "reasons": list(dict.fromkeys(reasons)),
        }

    if email_label == "SUSPICIOUS":
        return {
            "label": "SUSPICIOUS",
            "confidence": email_conf,
            "risk_level": "MEDIUM",
            "reasons": list(dict.fromkeys(reasons)),
        }

    return {
        "label": "SAFE",
        "confidence": max(email_conf, url_conf),
        "risk_level": "LOW",
        "reasons": list(dict.fromkeys(reasons)) or ["No high-risk signals detected"],
    }
