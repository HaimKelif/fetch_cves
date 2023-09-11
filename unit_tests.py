import os
import json
import fetch_cves
import nvd_api_caller
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

    assert len(cve_data) == 694
    assert cve_data[0]["cve"]["id"] == "CVE-2022-46527"
    assert cve_data[1]["cve"]["id"] == "CVE-2022-4343"


def test_calculate_metrics():
    """Test calculating metrics from CVE data."""
    cve_data = calc.load_cve_data("output-test")
    metrics = calc.calculate_metrics(cve_data)

    assert metrics["severity_counts"] == {
        "HIGH": 261,
        "MEDIUM": 392,
        "LOW": 35,
        "CRITICAL": 72,
    }
    assert metrics["average_cvss_score"] == 6.589210526315824
    assert metrics["packages_names"] == [
        ("nvd@nist.gov", 295),
        (None, 113),
        ("audit@patchstack.com", 50),
        ("security-advisories@github.com", 45),
        ("cna@vuldb.com", 38),
    ]


def test_fetch_cves_and_save():
    """Test fetching CVEs and saving them."""
    cleanup_test_files()
    if not os.path.exists("test_fetch"):
        os.makedirs("test_fetch")
    fetch_cves.fetch_cves_and_save(
        datetime(2023, 9, 9), datetime(2023, 9, 9), 0, "test_fetch"
    )

    file_path = os.path.join(
        "test_fetch", f"cves-{datetime(2023, 9, 9).date()}-{0}.json"
    )
    assert not os.path.exists(file_path)

    fetch_cves.fetch_cves_and_save(
        datetime(2023, 9, 8), datetime(2023, 9, 9), 0, "test_fetch"
    )

    file_path = os.path.join(
        "test_fetch", f"cves-{datetime(2023, 9, 9).date()}-{0}.json"
    )
    assert os.path.exists(file_path)

    with open(file_path, "r") as f:
        data = json.load(f)
        assert data[0]["cve"]["id"] == "CVE-2021-33834"
        assert data[0]["cve"]["id"] == "CVE-2021-33834"
    cleanup_test_files()


def test_get_total_results():
    """Test fetching the total results for a date range."""
    total_results = nvd_api_caller.get_total_results(
        datetime(2023, 9, 8), datetime(2023, 9, 9)
    )

    assert total_results == 54


def test_date_chunks_by_api_size():
    assert fetch_cves.date_chunks_by_api_size(
        datetime(2023, 9, 8), datetime(2023, 9, 9)
    ) == [((datetime(2023, 9, 8), datetime(2023, 9, 9)))]
    assert fetch_cves.date_chunks_by_api_size(
        datetime(2022, 9, 9), datetime(2023, 9, 8)
    ) == [
        (datetime(2022, 9, 9, 0, 0), datetime(2023, 1, 7, 0, 0)),
        (datetime(2023, 1, 7, 0, 0), datetime(2023, 5, 7, 0, 0)),
        (datetime(2023, 5, 7, 0, 0), datetime(2023, 9, 4, 0, 0)),
        (datetime(2023, 9, 4, 0, 0), datetime(2023, 9, 8, 0, 0)),
    ]
