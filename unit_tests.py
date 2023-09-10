import os
import json
import pytest
import fetch_cves
import calculates_data as calc
from datetime import datetime


def cleanup_test_files():
    if os.path.exists("test_fetch"):
        for filename in os.listdir("test_fetch"):
            file_path = os.path.join("test_fetch", filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
        os.rmdir("test_fetch")


def test_load_cve_data_valid():
    """Test loading valid CVE data."""
    cve_data = calc.load_cve_data("output-test")

    assert len(cve_data) == 14954
    assert cve_data[0]["cve"]["id"] == "CVE-2022-37941"
    assert cve_data[1]["cve"]["id"] == "CVE-2022-37942"


def test_calculate_metrics():
    """Test calculating metrics from CVE data."""
    cve_data = calc.load_cve_data("output-test")
    metrics = calc.calculate_metrics(cve_data)

    assert metrics["severity_counts"] == {
        "HIGH": 7280,
        "MEDIUM": 9352,
        "CRITICAL": 2608,
        "LOW": 483,
        "NONE": 4,
    }
    assert metrics["average_cvss_score"] == 6.924940436965183


def test_fetch_cves_and_save():
    """Test fetching CVEs and saving them."""
    if not os.path.exists("test_fetch"):
        os.makedirs("test_fetch")
    fetch_cves.fetch_cves_and_save(
        datetime(2023, 9, 9), datetime(2023, 9, 9), 0, "test_fetch"
    )

    file_path = os.path.join(
        "test_fetch", f"cves-{datetime(2023, 9, 9).date()}-{0}.json"
    )
    assert os.path.exists(file_path)

    with open(file_path, "r") as f:
        data = json.load(f)
        assert data["startIndex"] == 0
        assert data["totalResults"] == 0

    fetch_cves.fetch_cves_and_save(
        datetime(2023, 9, 8), datetime(2023, 9, 9), 0, "test_fetch"
    )

    file_path = os.path.join(
        "test_fetch", f"cves-{datetime(2023, 9, 9).date()}-{0}.json"
    )
    assert os.path.exists(file_path)

    with open(file_path, "r") as f:
        data = json.load(f)
        assert data["startIndex"] == 0
        assert data["totalResults"] == 54
    cleanup_test_files()


def test_get_total_results():
    """Test fetching the total results for a date range."""
    total_results = fetch_cves.get_total_results(
        datetime(2023, 9, 8), datetime(2023, 9, 9)
    )

    assert total_results == 54
