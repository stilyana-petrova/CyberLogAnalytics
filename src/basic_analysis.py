import csv
import time
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = PROJECT_DIR / "data" / "generated_logs.csv"


def analyze_logs():

    start_time = time.perf_counter()

    event_counts = Counter()
    severity_counts = Counter()
    failed_logins_by_ip = Counter()
    suspicious_events_by_ip = Counter()

    total_records = 0
    total_failed_logins = 0
    total_suspicious_events = 0

    if not INPUT_FILE.exists():
        print("Error: CSV file was not found.")
        print(f"Expected location: {INPUT_FILE}")
        return

    with open(INPUT_FILE, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            total_records += 1

            event_type = row["event_type"]
            severity = row["severity"]
            source_ip = row["source_ip"]
            status = row["status"]

            event_counts[event_type] += 1

            severity_counts[severity] += 1

            if event_type == "failed_login":
                total_failed_logins += 1
                failed_logins_by_ip[source_ip] += 1

            if status == "suspicious":
                total_suspicious_events += 1
                suspicious_events_by_ip[source_ip] += 1

    elapsed_time = time.perf_counter() - start_time

    print("\n========== CYBERLOG ANALYTICS ==========")

    print(f"\nTotal records: {total_records:,}")
    print(f"Failed logins: {total_failed_logins:,}")
    print(f"Suspicious events: {total_suspicious_events:,}")

    print("\n--- Events by type ---")
    for event_type, count in event_counts.most_common():
        print(f"{event_type}: {count:,}")

    print("\n--- Events by severity ---")
    for severity, count in severity_counts.most_common():
        print(f"{severity}: {count:,}")

    print("\n--- Top 10 IPs by failed logins ---")
    if failed_logins_by_ip:
        for ip, count in failed_logins_by_ip.most_common(10):
            print(f"{ip}: {count:,} failed logins")
    else:
        print("No failed logins found.")

    print("\n--- Top 10 IPs by suspicious events ---")
    if suspicious_events_by_ip:
        for ip, count in suspicious_events_by_ip.most_common(10):
            print(f"{ip}: {count:,} suspicious events")
    else:
        print("No suspicious events found.")

    print(f"\nAnalysis time: {elapsed_time:.4f} seconds")
    print("========================================")


if __name__ == "__main__":
    analyze_logs()
