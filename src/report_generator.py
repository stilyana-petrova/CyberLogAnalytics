import csv
import html
import re
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_DIR / "data" / "generated_logs.csv"
OUTPUT_DIR = PROJECT_DIR / "output"
REPORT_FILE = OUTPUT_DIR / "cyberlog_report.html"

CHARTS = [
    ("events_by_type.png", "Security Events by Type"),
    ("events_by_severity.png", "Security Events by Severity"),
    ("events_by_status.png", "Distribution of Event Statuses"),
    ("top_failed_login_ips.png", "Top Source IPs by Failed Logins"),
]


def read_performance_time(filename):
    file_path = OUTPUT_DIR / filename

    if not file_path.exists():
        return None

    content = file_path.read_text(encoding="utf-8")

    match = re.search(
        r"Execution time:\s*([\d.]+)\s*seconds",
        content,
        re.IGNORECASE,
    )

    if not match:
        match = re.search(
            r"(?:Dask|PySpark|Ray) execution time:\s*([\d.]+)\s*seconds",
            content,
            re.IGNORECASE,
        )

    return float(match.group(1)) if match else None


def analyze_csv():
    event_counts = Counter()
    severity_counts = Counter()
    status_counts = Counter()
    failed_logins_by_ip = Counter()

    total_records = 0
    total_bytes = 0
    start_time = time.perf_counter()

    with open(DATA_FILE, "r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            total_records += 1
            event_counts[row["event_type"]] += 1
            severity_counts[row["severity"]] += 1
            status_counts[row["status"]] += 1
            total_bytes += int(row["bytes_transferred"])

            if row["event_type"] == "failed_login":
                failed_logins_by_ip[row["source_ip"]] += 1

    elapsed = time.perf_counter() - start_time

    return {
        "records": total_records,
        "events": event_counts,
        "severities": severity_counts,
        "statuses": status_counts,
        "failed_ips": failed_logins_by_ip,
        "total_bytes": total_bytes,
        "python_time": elapsed,
    }


def make_table(counter, first_header, second_header):
    rows = "".join(
        f"<tr><td>{html.escape(str(name))}</td>"
        f"<td>{count:,}</td></tr>"
        for name, count in counter.most_common()
    )

    return (
        "<table><thead><tr>"
        f"<th>{html.escape(first_header)}</th>"
        f"<th>{html.escape(second_header)}</th>"
        f"</tr></thead><tbody>{rows}</tbody></table>"
    )


def generate_report():
    if not DATA_FILE.exists():
        print(f"Data file not found: {DATA_FILE}")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Analyzing data and preparing the report...")
    data = analyze_csv()

    if data["records"] == 0:
        print("The CSV file contains no records.")
        return

    timings = {
        "Python (baseline)": data["python_time"],
        "Dask": read_performance_time("dask_results.txt"),
        "PySpark": read_performance_time("pyspark_results.txt"),
        "Ray": read_performance_time("ray_results.txt"),
    }

    event_counts = data["events"]
    severity_counts = data["severities"]
    statuses = data["statuses"]
    failed_ips = data["failed_ips"]

    top_event = event_counts.most_common(1)[0]
    high_count = severity_counts.get("high", 0)
    high_percent = high_count / data["records"] * 100
    failed_count = event_counts.get("failed_login", 0)
    suspicious_count = statuses.get("suspicious", 0)
    top_ip = failed_ips.most_common(1)

    conclusions = [
        (
            f"The most common event type is '{top_event[0]}', "
            f"with {top_event[1]:,} records."
        ),
        (
            f"{high_count:,} events ({high_percent:.2f}%) "
            "are classified as high severity."
        ),
        (
            f"The dataset contains {failed_count:,} failed-login events "
            f"and {suspicious_count:,} events with suspicious status."
        ),
    ]

    if top_ip:
        conclusions.append(
            f"The source IP with the most failed logins is "
            f"{top_ip[0][0]}, with {top_ip[0][1]:,} attempts."
        )

    conclusions.append(
        "These are synthetic training data. A high event count is an "
        "indicator for further investigation, not proof of an attack."
    )

    conclusion_html = "".join(
        f"<li>{html.escape(item)}</li>" for item in conclusions
    )

    timing_rows = ""
    for technology, seconds in timings.items():
        value = f"{seconds:.4f} seconds" if seconds is not None else "Not available"
        timing_rows += (
            f"<tr><td>{html.escape(technology)}</td>"
            f"<td>{html.escape(value)}</td></tr>"
        )

    chart_html = ""
    for filename, title in CHARTS:
        chart_path = OUTPUT_DIR / filename

        if chart_path.exists():
            chart_html += (
                '<div class="chart">'
                f"<h3>{html.escape(title)}</h3>"
                f'<img src="{html.escape(filename)}" '
                f'alt="{html.escape(title)}">'
                "</div>"
            )
        else:
            chart_html += (
                f"<p>Chart not found: {html.escape(filename)}</p>"
            )

    generated_at = datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %Z"
    )

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberLog Analytics Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    max-width: 1100px;
    margin: 35px auto;
    padding: 0 20px;
    color: #24332c;
    background: #f5f4ed;
    line-height: 1.6;
}}
h1, h2 {{ color: #315c48; }}
.card {{
    background: white;
    padding: 20px;
    margin: 18px 0;
    border-radius: 10px;
}}
.metrics {{
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
}}
.metric {{
    background: #e4eadf;
    padding: 16px;
    border-radius: 8px;
    flex: 1;
    min-width: 170px;
}}
.metric strong {{ display: block; font-size: 1.5em; }}
table {{
    border-collapse: collapse;
    width: 100%;
    background: white;
}}
th, td {{
    border: 1px solid #d5ddd4;
    padding: 10px;
    text-align: left;
}}
th {{ background: #dfe8dd; }}
.chart {{ margin: 25px 0; }}
.chart img {{ width: 100%; max-width: 850px; height: auto; }}
footer {{ color: #59685f; margin: 30px 0; }}
</style>
</head>
<body>
<h1>CyberLog Analytics</h1>
<p>Automated Security Log Analysis Report</p>
<p>Generated: {html.escape(generated_at)}</p>

<section class="card">
<h2>Dataset Overview</h2>
<div class="metrics">
<div class="metric">
Records processed
<strong>{data["records"]:,}</strong>
</div>
<div class="metric">
Failed logins
<strong>{failed_count:,}</strong>
</div>
<div class="metric">
Suspicious events
<strong>{suspicious_count:,}</strong>
</div>
<div class="metric">
Total data transferred
<strong>{data["total_bytes"]:,} bytes</strong>
</div>
</div>
</section>

<section class="card">
<h2>Events by Type</h2>
{make_table(event_counts, "Event Type", "Count")}
</section>

<section class="card">
<h2>Events by Severity</h2>
{make_table(severity_counts, "Severity", "Count")}
</section>

<section class="card">
<h2>Events by Status</h2>
{make_table(statuses, "Status", "Count")}
</section>

<section class="card">
<h2>Top 10 IPs by Failed Logins</h2>
{make_table(Counter(dict(failed_ips.most_common(10))), "Source IP", "Failed Logins")}
</section>

<section class="card">
<h2>Visualizations</h2>
{chart_html}
</section>

<section class="card">
<h2>Execution Time Comparison</h2>
<p>Times are measured separately by each analysis module. The Python
baseline is measured during report generation. Results depend on the
machine, environment, and implementation.</p>
<table>
<thead><tr><th>Technology</th><th>Execution Time</th></tr></thead>
<tbody>{timing_rows}</tbody>
</table>
</section>

<section class="card">
<h2>Analysis Conclusions</h2>
<ul>{conclusion_html}</ul>
</section>

<footer>
CyberLog Analytics is an educational project using synthetic log data.
Its results do not establish that real systems have been attacked.
</footer>
</body>
</html>
"""

    REPORT_FILE.write_text(report_html, encoding="utf-8")

    print("\nReport generated successfully!")
    print(f"Records processed: {data['records']:,}")
    print(f"HTML report: {REPORT_FILE}")


if __name__ == "__main__":
    generate_report()
