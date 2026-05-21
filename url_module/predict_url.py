from __future__ import annotations

import sys
from pathlib import Path

try:
    from url_module.url_guard import score_url
except ImportError:  # Support direct script execution.
    sys.path.append(str(Path(__file__).resolve().parent.parent))
    from url_module.url_guard import score_url


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python predict_url.py <url>")
        raise SystemExit(1)

    url = sys.argv[1].strip()
    if not url:
        print("URL cannot be empty")
        raise SystemExit(1)

    result = score_url(url)
    label = result["label"]
    confidence = result["confidence"]
    if result.get("allowlisted"):
        label = "Legitimate (allowlisted)"

    print(f"Classification: {label}")


if __name__ == "__main__":
    main()
