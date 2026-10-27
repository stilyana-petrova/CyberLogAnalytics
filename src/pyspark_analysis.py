
import time
from pathlib import Path

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

PROJECT_DIR = Path(__file__).resolve().parent.parent
INPUT_FILE = PROJECT_DIR / "data" / "generated_logs.csv"
OUTPUT_DIR = PROJECT_DIR / "output"


def analyze_with_pyspark():
    if not INPUT_FILE.exists():
        print(f"CSV file was not found: {INPUT_FILE}")
        return

    spark = (
        SparkSession.builder
        .appName("CyberLogAnalytics")
        .master("local[*]")
        .config("spark.ui.enabled", "false")
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("ERROR")

    try:
        start_time = time.perf_counter()

        df = (
            spark.read
            .option("header", True)
            .option("inferSchema", True)
            .csv(str(INPUT_FILE))
            .cache()
        )

        total_records = df.count()

        events_by_type = (
            df.groupBy("event_type")
            .count()
            .orderBy(F.desc("count"))
        )

        events_by_severity = (
            df.groupBy("severity")
            .count()
            .orderBy(F.desc("count"))
        )

        failed_logins_by_ip = (
            df.filter(F.col("event_type") == "failed_login")
            .groupBy("source_ip")
            .count()
            .orderBy(F.desc("count"))
            .limit(10)
        )

        event_rows = events_by_type.collect()
        severity_rows = events_by_severity.collect()
        ip_rows = failed_logins_by_ip.collect()

        elapsed_time = time.perf_counter() - start_time

        print("\n========== PYSPARK ANALYSIS ==========")
        print(f"Total records: {total_records:,}")

        print("\n--- Events by type ---")
        for row in event_rows:
            print(f"{row['event_type']}: {row['count']:,}")

        print("\n--- Events by severity ---")
        for row in severity_rows:
            print(f"{row['severity']}: {row['count']:,}")

        print("\n--- Top 10 IPs by failed logins ---")
        for row in ip_rows:
            print(f"{row['source_ip']}: {row['count']:,} failed logins")

        print(f"\nPySpark execution time: {elapsed_time:.4f} seconds")
        print("======================================")

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        report_file = OUTPUT_DIR / "pyspark_results.txt"

        with open(report_file, "w", encoding="utf-8") as file:
            file.write("CYBERLOG ANALYTICS - PYSPARK RESULTS\n")
            file.write(f"Total records: {total_records:,}\n")
            file.write(f"Execution time: {elapsed_time:.4f} seconds\n\n")

            file.write("Events by type:\n")
            for row in event_rows:
                file.write(f"{row['event_type']}: {row['count']:,}\n")

            file.write("\nEvents by severity:\n")
            for row in severity_rows:
                file.write(f"{row['severity']}: {row['count']:,}\n")

            file.write("\nTop 10 IPs by failed logins:\n")
            for row in ip_rows:
                file.write(
                    f"{row['source_ip']}: {row['count']:,} failed logins\n"
                )

        print(f"\nResults saved to: {report_file}")

        df.unpersist()

    finally:
        spark.stop()


if __name__ == "__main__":
    analyze_with_pyspark()
