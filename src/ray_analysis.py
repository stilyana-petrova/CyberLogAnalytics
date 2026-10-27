
import csv
import time
from collections import Counter
from pathlib import Path

import ray

PROJECT_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = PROJECT_DIR / "data" / "generated_logs.csv"
OUTPUT_DIR = PROJECT_DIR / "output"

CHUNK_SIZE = 25_000


@ray.remote
def analyze_chunk(records):
    event_counts = Counter()
    severity_counts = Counter()
    failed_logins_by_ip = Counter()

    for event_type, severity, source_ip in records:
        event_counts[event_type] += 1
        severity_counts[severity] += 1

        if event_type == "failed_login":
            failed_logins_by_ip[source_ip] += 1

    return {
        "record_count": len(records),
        "events": dict(event_counts),
        "severities": dict(severity_counts),
        "failed_ips": dict(failed_logins_by_ip),
    }


def analyze_with_ray():
    if not INPUT_FILE.exists():
        print(f"CSV file was not found: {INPUT_FILE}")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    ray.init(
        num_cpus=4,
        include_dashboard=False,
        ignore_reinit_error=True,
    )

    try:
        start_time = time.perf_counter()
        tasks = []
        chunk = []

        with open(INPUT_FILE, "r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)

            for row in reader:
                chunk.append((
                    row["event_type"],
                    row["severity"],
                    row["source_ip"],
                ))

                if len(chunk) >= CHUNK_SIZE:
                    tasks.append(analyze_chunk.remote(chunk))
                    chunk = []

            if chunk:
                tasks.append(analyze_chunk.remote(chunk))

        results = ray.get(tasks)

        total_records = 0
        event_counts = Counter()
        severity_counts = Counter()
        failed_logins_by_ip = Counter()

        for result in results:
            total_records += result["record_count"]
            event_counts.update(result["events"])
            severity_counts.update(result["severities"])
            failed_logins_by_ip.update(result["failed_ips"])

        elapsed_time = time.perf_counter() - start_time

        print("\n========== RAY ANALYSIS ==========")
        print(f"Total records: {total_records:,}")
        print(f"Number of Ray tasks: {len(tasks)}")

        print("\n--- Events by type ---")
        for name, count in event_counts.most_common():
            print(f"{name}: {count:,}")

        print("\n--- Events by severity ---")
        for name, count in severity_counts.most_common():
            print(f"{name}: {count:,}")

        print("\n--- Top 10 IPs by failed logins ---")
        for ip, count in failed_logins_by_ip.most_common(10):
            print(f"{ip}: {count:,} failed logins")

        print(f"\nRay execution time: {elapsed_time:.4f} seconds")
        print("==================================")

        report_file = OUTPUT_DIR / "ray_results.txt"

        with open(report_file, "w", encoding="utf-8") as file:
            file.write("CYBERLOG ANALYTICS - RAY RESULTS\n")
            file.write(f"Total records: {total_records:,}\n")
            file.write(f"Ray tasks: {len(tasks)}\n")
            file.write(f"Execution time: {elapsed_time:.4f} seconds\n\n")

            file.write("Events by type:\n")
            for name, count in event_counts.most_common():
                file.write(f"{name}: {count:,}\n")

            file.write("\nEvents by severity:\n")
            for name, count in severity_counts.most_common():
                file.write(f"{name}: {count:,}\n")

            file.write("\nTop 10 IPs by failed logins:\n")
            for ip, count in failed_logins_by_ip.most_common(10):
                file.write(f"{ip}: {count:,} failed logins\n")

        print(f"\nResults saved to: {report_file}")

    finally:
        ray.shutdown()


if __name__ == "__main__":
    analyze_with_ray()
