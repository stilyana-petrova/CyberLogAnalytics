import csv
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt

PROJECT_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = PROJECT_DIR / "data" / "generated_logs.csv"
OUTPUT_DIR = PROJECT_DIR / "output"


def create_visualizations():
    if not INPUT_FILE.exists():
        print("CSV file was not found:", INPUT_FILE)
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    event_counts = Counter()
    severity_counts = Counter()
    status_counts = Counter()
    failed_logins_by_ip = Counter()

    with open(INPUT_FILE, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            event_counts[row["event_type"]] += 1
            severity_counts[row["severity"]] += 1
            status_counts[row["status"]] += 1

            if row["event_type"] == "failed_login":
                failed_logins_by_ip[row["source_ip"]] += 1

    # 1. Events by type
    plt.figure(figsize=(10, 6))
    events = event_counts.most_common()
    plt.bar(
        [item[0] for item in events],
        [item[1] for item in events]
    )
    plt.title("Security Events by Type")
    plt.xlabel("Event Type")
    plt.ylabel("Number of Events")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "events_by_type.png")
    plt.close()

    # 2. Events by severity
    plt.figure(figsize=(8, 5))
    severities = severity_counts.most_common()
    plt.bar(
        [item[0] for item in severities],
        [item[1] for item in severities]
    )
    plt.title("Security Events by Severity")
    plt.xlabel("Severity")
    plt.ylabel("Number of Events")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "events_by_severity.png")
    plt.close()

    # 3. Events by status
    plt.figure(figsize=(8, 5))
    statuses = status_counts.most_common()
    plt.pie(
        [item[1] for item in statuses],
        labels=[item[0] for item in statuses],
        autopct="%1.1f%%",
        startangle=90
    )
    plt.title("Distribution of Event Statuses")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "events_by_status.png")
    plt.close()

    # 4. Top 10 IPs by failed logins
    plt.figure(figsize=(10, 6))
    top_ips = failed_logins_by_ip.most_common(10)
    if top_ips:
        plt.barh(
            [item[0] for item in reversed(top_ips)],
            [item[1] for item in reversed(top_ips)]
        )
        plt.title("Top 10 Source IPs by Failed Logins")
        plt.xlabel("Number of Failed Logins")
        plt.ylabel("Source IP")
    else:
        plt.title("No Failed Logins Found")
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / "top_failed_login_ips.png")
    plt.close()

    print("Visualization completed!")
    print("Created 4 charts in:", OUTPUT_DIR)


if __name__ == "__main__":
    create_visualizations()
