import csv
import os
import sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

CSV_FILE = os.path.join(os.path.dirname(__file__), "..", "ThreatIntelFeeds.csv")
DELIMITER = ";"
URL_COLUMN = "Url"
STATUS_COLUMN = "FeedStatus"
TIMEOUT = 10
MAX_WORKERS = 20


def check_url(url: str) -> str:
    """Return 'Active' if the URL responds with a non-error status, else 'Offline'."""
    try:
        response = requests.head(url, timeout=TIMEOUT, allow_redirects=True)
        # Some servers reject HEAD; fall back to GET
        if response.status_code in (405, 400, 403):
            response = requests.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
        if response.status_code < 400:
            return "Active"
        return "Offline"
    except requests.RequestException:
        return "Offline"


def main():
    if not os.path.exists(CSV_FILE):
        print(f"[ERROR] CSV file '{CSV_FILE}' not found.")
        sys.exit(1)

    # Read existing CSV
    with open(CSV_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter=DELIMITER)
        fieldnames = reader.fieldnames or []
        rows = list(reader)

    if URL_COLUMN not in fieldnames:
        print(f"[ERROR] Column '{URL_COLUMN}' not found in CSV. Available columns: {fieldnames}")
        sys.exit(1)

    # Add FeedStatus column if missing
    if STATUS_COLUMN not in fieldnames:
        print(f"[INFO] '{STATUS_COLUMN}' column not found. Adding it.")
        fieldnames = list(fieldnames) + [STATUS_COLUMN]

    # Collect URLs with their row indices
    url_index_pairs = [
        (i, row[URL_COLUMN].strip())
        for i, row in enumerate(rows)
        if row.get(URL_COLUMN, "").strip()
    ]

    total = len(url_index_pairs)
    print(f"[INFO] Checking {total} URLs using {MAX_WORKERS} workers...\n")

    results = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_index = {
            executor.submit(check_url, url): (i, url)
            for i, url in url_index_pairs
        }
        for done, future in enumerate(as_completed(future_to_index), start=1):
            idx, url = future_to_index[future]
            status = future.result()
            results[idx] = status
            indicator = "✅" if status == "Active" else "❌"
            print(f"[{done}/{total}] {indicator} {status:<8} {url}")

    # Write statuses back to rows
    for i, row in enumerate(rows):
        row[STATUS_COLUMN] = results.get(i, "")

    # Write updated CSV
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=DELIMITER)
        writer.writeheader()
        writer.writerows(rows)

    # Summary
    active = sum(1 for s in results.values() if s == "Active")
    offline = sum(1 for s in results.values() if s == "Offline")
    print(f"\n[DONE] Results written to '{CSV_FILE}'")
    print(f"       Active : {active}")
    print(f"       Offline: {offline}")


if __name__ == "__main__":
    main()