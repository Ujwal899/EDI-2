import csv
import html
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse, urlunparse

BASE_DIR = Path(__file__).resolve().parent
INPUT_PATH = BASE_DIR / "data" / "urls" / "phishing_site_urls.csv"
OUTPUT_PATH = BASE_DIR / "data" / "urls" / "phishing_site_urls_clean.csv"
REPORT_PATH = BASE_DIR / "reports" / "urls" / "phishing_site_urls_report.txt"

SCHEMES = {"http", "https"}
LABELS = {"good", "bad"}


def normalize_url(raw_url: str) -> str | None:
    url = raw_url.strip()
    if not url:
        return None

    # Trim common wrapping quotes and unescape HTML entities.
    if (url.startswith("'") and url.endswith("'")) or (url.startswith('"') and url.endswith('"')):
        url = url[1:-1].strip()
    url = html.unescape(url)
    url = url.replace("\\%", "%")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme.lower() not in SCHEMES or not parsed.netloc:
        return None

    # Normalize host and remove default ports.
    netloc = parsed.netloc.strip()
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
    else:
        userinfo, hostport = "", netloc

    host, sep, port = hostport.partition(":")
    host = host.lower().strip("[]")
    if port and ((parsed.scheme == "http" and port == "80") or (parsed.scheme == "https" and port == "443")):
        port = ""

    normalized_host = host
    if port:
        normalized_host = f"{host}:{port}"
    if userinfo:
        normalized_host = f"{userinfo}@{normalized_host}"

    path = re.sub(r"/+", "/", parsed.path or "/")
    normalized = urlunparse(
        (parsed.scheme.lower(), normalized_host, path, "", parsed.query, "")
    )
    return normalized


def main() -> None:
    total = 0
    dropped = 0
    bad_label = 0
    cleaned_rows: list[tuple[str, str, str]] = []
    issues = Counter()

    with open(INPUT_PATH, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header or [h.strip().lower() for h in header] != ["url", "label"]:
            f.seek(0)
            reader = csv.reader(f)

        for row in reader:
            total += 1
            if len(row) < 2:
                dropped += 1
                issues["row_too_short"] += 1
                continue

            raw_url, raw_label = row[0].strip(), row[1].strip().lower()
            if raw_label not in LABELS:
                bad_label += 1
                issues["invalid_label"] += 1
                continue

            normalized = normalize_url(raw_url)
            if not normalized:
                dropped += 1
                issues["invalid_url"] += 1
                continue

            cleaned_rows.append((raw_url, raw_label, normalized))

    label_map = defaultdict(Counter)
    for _, label, normalized in cleaned_rows:
        label_map[normalized][label] += 1

    conflicts = {u for u, counts in label_map.items() if len(counts) > 1}
    deduped: list[tuple[str, str, str]] = []
    seen = set()
    for raw_url, label, normalized in cleaned_rows:
        if normalized in conflicts:
            issues["label_conflict"] += 1
            continue
        if normalized in seen:
            issues["duplicate"] += 1
            continue
        seen.add(normalized)
        deduped.append((raw_url, label, normalized))

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label", "clean_url"])
        writer.writerows(deduped)

    label_counts = Counter([label for _, label, _ in deduped])

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write("Dataset cleanup report\n")
        f.write("======================\n")
        f.write(f"Input rows: {total}\n")
        f.write(f"Output rows: {len(deduped)}\n")
        f.write(f"Dropped rows: {dropped}\n")
        f.write(f"Invalid labels: {bad_label}\n")
        f.write("\nIssue counts:\n")
        for key, value in issues.most_common():
            f.write(f"- {key}: {value}\n")
        f.write("\nLabel distribution:\n")
        for key, value in label_counts.most_common():
            f.write(f"- {key}: {value}\n")


if __name__ == "__main__":
    main()
