from __future__ import annotations

import sqlite3
from pathlib import Path

import pandas as pd


BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "data" / "scan_history.sqlite3"
OUTPUT_PATH = BASE_DIR / "data" / "feedback_training_rows.csv"


def export_feedback_rows() -> None:
    if not DB_PATH.exists():
        raise FileNotFoundError(f"Scan history database not found: {DB_PATH}")

    with sqlite3.connect(DB_PATH) as conn:
        rows = pd.read_sql_query(
            """
            SELECT subject, body, user_verdict AS label
            FROM scan_results
            WHERE input_type IN ('email', 'combined')
              AND user_verdict IN ('SAFE', 'SUSPICIOUS', 'PHISHING')
              AND (subject != '' OR body != '')
            """,
            conn,
        )

    if rows.empty:
        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        rows.to_csv(OUTPUT_PATH, index=False)
        print(f"No feedback rows found. Wrote empty file to: {OUTPUT_PATH}")
        return

    rows["label"] = rows["label"].replace({"SUSPICIOUS": "SPAM"})
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    rows.to_csv(OUTPUT_PATH, index=False)
    print(f"Exported {len(rows)} feedback rows to: {OUTPUT_PATH}")


if __name__ == "__main__":
    export_feedback_rows()
