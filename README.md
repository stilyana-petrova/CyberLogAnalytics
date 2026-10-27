# CyberLog Analytics

## Overview

CyberLog Analytics is a Python application for analyzing synthetic cybersecurity logs. It generates a large dataset, identifies event patterns, creates visualizations, and produces an automated HTML report.

## Descriptive Analysis
The decided type of analysis for this project is Descriptive analysis.

## Features

- Generates 500,000 synthetic security log records using Faker.
- Performs statistical analysis using Python.
- Processes data with Dask and PySpark.
- Executes parallel analysis tasks with Ray.
- Creates four visualizations using Matplotlib.
- Generates an HTML report with statistics, execution times, and conclusions.
- Saves intermediate results and charts in the `output/` directory.

## Dataset

The generated CSV file contains the following fields:

- `event_id`
- `timestamp`
- `source_ip`
- `destination_ip`
- `event_type`
- `username`
- `service`
- `status`
- `severity`
- `bytes_transferred`

The dataset is synthetic and intended for educational purposes. It does not contain real security logs.

## Technologies

- Python
- Faker
- Matplotlib
- Dask
- Apache Spark / PySpark
- Ray

## Installation

1. Install a compatible Python version and Java runtime required by PySpark.
2. Create and activate a virtual environment.
3. Install the dependencies:

```bash
python -m pip install -r requirements.txt
```

## Running the application

Run the scripts from the project in the following order:

1. `src/data_generator.py` — generates the dataset.
2. `src/basic_analysis.py` — performs the baseline analysis.
3. `src/visualization.py` — creates the charts.
4. `src/dask_analysis.py` — analyzes the dataset with Dask.
5. `src/pyspark_analysis.py` — analyzes the dataset with PySpark.
6. `src/ray_analysis.py` — performs parallel analysis with Ray.
7. `src/report_generator.py` — generates the HTML report.

The generated dataset is saved to `data/generated_logs.csv`. Charts, analysis results, and the final HTML report are saved to `output/`.

## Output

The project generates:

- `events_by_type.png`
- `events_by_severity.png`
- `events_by_status.png`
- `top_failed_login_ips.png`
- `dask_results.txt`
- `pyspark_results.txt`
- `ray_results.txt`
- `cyberlog_report.html`

## Performance measurements

Each analysis module measures its execution time. The HTML report includes these measurements for comparison. Actual performance depends on the hardware, environment, and implementation.

## Disclaimer

This project is an educational demonstration using synthetic data. Suspicious-event counts are analytical indicators, not proof of malicious activity.
