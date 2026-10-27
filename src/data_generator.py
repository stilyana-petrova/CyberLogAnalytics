import csv
import random
import time
from datetime import datetime, timedelta
from pathlib import Path

from faker import Faker


PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_DIR / "data"
OUTPUT_FILE = DATA_DIR / "generated_logs.csv"

fake = Faker()
random.seed(42)
Faker.seed(42)


EVENT_TYPES = [
    "successful_login",
    "failed_login",
    "port_scan",
    "suspicious_connection",
    "file_access",
    "privilege_change",
]

EVENT_WEIGHTS = [50, 20, 8, 7, 10, 5]

SERVICES = ["SSH", "HTTP", "HTTPS", "FTP"]
SEVERITIES = ["low", "medium", "high"]

SOURCE_IPS = [fake.ipv4_private() for _ in range(1000)]
DESTINATION_IPS = [fake.ipv4_private() for _ in range(100)]
USERNAMES = [fake.user_name() for _ in range(500)]

SUSPICIOUS_IPS = SOURCE_IPS[:5]


def generate_log(event_id):

    event_type = random.choices(
        EVENT_TYPES,
        weights=EVENT_WEIGHTS,
        k=1,
    )[0]


    if event_type in [
        "failed_login",
        "port_scan",
        "suspicious_connection",
    ]:
        if random.random() < 0.65:
            source_ip = random.choice(SUSPICIOUS_IPS)
        else:
            source_ip = random.choice(SOURCE_IPS)
    else:
        source_ip = random.choice(SOURCE_IPS)

    if event_type == "failed_login":
        status = "failure"
        severity = random.choices(
            ["medium", "high"],
            weights=[30, 70],
            k=1,
        )[0]

    elif event_type in ["port_scan", "suspicious_connection"]:
        status = "suspicious"
        severity = "high"

    elif event_type == "privilege_change":
        status = "success"
        severity = "medium"

    else:
        status = "success"
        severity = random.choices(
            SEVERITIES,
            weights=[70, 25, 5],
            k=1,
        )[0]

    timestamp = datetime.now() - timedelta(
        seconds=random.randint(0, 30 * 24 * 60 * 60)
    )

    return {
        "event_id": event_id,
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": source_ip,
        "destination_ip": random.choice(DESTINATION_IPS),
        "event_type": event_type,
        "username": random.choice(USERNAMES),
        "service": random.choice(SERVICES),
        "status": status,
        "severity": severity,
        "bytes_transferred": random.randint(100, 10000),
    }


def generate_logs(count=1000, batch_size=10000):

    if count < 1:
        raise ValueError("Броят записи трябва да е поне 1.")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "event_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "event_type",
        "username",
        "service",
        "status",
        "severity",
        "bytes_transferred",
    ]

    start_time = time.perf_counter()

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for start_id in range(1, count + 1, batch_size):
            end_id = min(start_id + batch_size, count + 1)

            for event_id in range(start_id, end_id):
                writer.writerow(generate_log(event_id))

            processed = end_id - 1
            print(f"Generated {processed:,} / {count:,} records")

    elapsed = time.perf_counter() - start_time

    print("\nGeneration completed!")
    print(f"Records generated: {count:,}")
    print(f"Execution time: {elapsed:.2f} seconds")
    print(f"Output file: {OUTPUT_FILE}")
    print(f"File size: {OUTPUT_FILE.stat().st_size / (1024 * 1024):.2f} MB")


if __name__ == "__main__":
    generate_logs(500_000)
