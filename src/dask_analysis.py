import time
from pathlib import Path

import dask.dataframe as dd

PROJECT_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = PROJECT_DIR / "data" / "generated_logs.csv"
OUTPUT_DIR = PROJECT_DIR / "output"


def analyze_with_dask():
    if not INPUT_FILE.exists():
        print(f"CSV file was not found: {INPUT_FILE}")
        return

    start_time = time.perf_counter()

    df = dd.read_csv(
        str(INPUT_FILE),
        blocksize="16MB"
    )

    events_by_type = df.groupby("event_type").size().compute()

    events_by_severity = df.groupby("severity").size().compute()

    failed_logins = df[df["event_type"] == "failed_login"]
    failed_logins_by_ip = (
        failed_logins.groupby("source_ip")
        .size()
        .compute()
        .sort_values(ascending=False)
        .head(10)
    )

    total_records = len(df)

    elapsed_time = time.perf_counter() - start_time

    print("\n========== DASK ANALYSIS ==========")
    print(f"Total records: {total_records:,}")

    print("\n--- Events by type ---")
    print(events_by_type.sort_values(ascending=False).to_string())

    print("\n--- Events by severity ---")
    print(events_by_severity.sort_values(ascending=False).to_string())

    print("\n--- Top 10 IPs by failed logins ---")
    print(failed_logins_by_ip.to_string())

    print(f"\nDask execution time: {elapsed_time:.4f} seconds")
    print("===================================")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    report_file = OUTPUT_DIR / "dask_results.txt"

    with open(report_file, "w", encoding="utf-8") as file:
        file.write("CYBERLOG ANALYTICS - DASK RESULTS\n")
        file.write(f"Total records: {total_records:,}\n")
        file.write(f"Execution time: {elapsed_time:.4f} seconds\n\n")

        file.write("Events by type:\n")
        file.write(events_by_type.sort_values(ascending=False).to_string())
        file.write("\n\nEvents by severity:\n")
        file.write(events_by_severity.sort_values(ascending=False).to_string())
        file.write("\n\nTop 10 IPs by failed logins:\n")
        file.write(failed_logins_by_ip.to_string())
        file.write("\n")

    print(f"\nResults saved to: {report_file}")


if __name__ == "__main__":
    analyze_with_dask()
