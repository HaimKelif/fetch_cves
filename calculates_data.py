import json
import os
import typer
import logging
from collections import defaultdict
import collections

app = typer.Typer()

logging.basicConfig(level=logging.INFO)


def load_cve_data(cve_data_directory: str) -> list[dict]:
    """
    Load CVE data from JSON files in the specified directory.

    @params: cve_data_directory: str
    @output: list[dict]
    """
    cve_data = []
    for filename in os.listdir(cve_data_directory):
        if filename.endswith(".json"):
            try:
                with open(os.path.join(cve_data_directory, filename), "r") as f:
                    data = json.load(f)
                    cve_data.extend(data)
            except (IOError, json.JSONDecodeError) as e:
                logging.error(f"Error loading data from {filename}: {str(e)}")
    return cve_data


def calculate_metrics(cve_data: list[dict]) -> dict:
    """
    Calculate metrics based on CVE data.

    @params: cve_data: list[dict]
    @output: dict
    """
    severity_counts = defaultdict(int)
    packages_names = [str]
    total_cvss_score = 0

    for cve_entry in cve_data:
        cvssMetricV31 = (
            cve_entry.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])
        )
        for m in cvssMetricV31:
            severity = m.get("cvssData", {}).get("baseSeverity")
            if severity:
                severity_counts[severity] += 1
            base_score = m.get("cvssData", {}).get("baseScore")
            if base_score:
                total_cvss_score += base_score
        weaknesses = cve_entry.get("cve", {}).get("weaknesses", [{}])
        for m in weaknesses:
            packages_names.append(m.get("source"))

    num_vulnerabilities = sum(severity_counts.values())
    average_cvss_score = (
        total_cvss_score / num_vulnerabilities if num_vulnerabilities > 0 else 0.0
    )

    return {
        "severity_counts": dict(severity_counts),
        "average_cvss_score": average_cvss_score,
        "packages_names": collections.Counter(packages_names).most_common(5),
    }


@app.command()
def analyze_cve_data(cve_data_directory: str = "output"):
    """
    Analyze and print various metrics based on CVE data in JSON files.

    @params: cve_data_directory: str
    @output: None
    """
    cve_data = load_cve_data(cve_data_directory)
    metrics = calculate_metrics(cve_data)

    typer.echo("Metrics:")
    typer.echo(f"Severity Counts: {metrics['severity_counts']}")
    typer.echo(f"Average CVSS3.0 Score: {metrics['average_cvss_score']:.2f}")
    typer.echo(f"5 most  vulnerable packages: {metrics['packages_names']}")


if __name__ == "__main__":
    app()
