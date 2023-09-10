import typer
import json
import requests
from datetime import datetime, timedelta
from typing import Optional
import threading
import os
import logging


app = typer.Typer()

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 50
MAX_DAYS = 120

logging.basicConfig(level=logging.INFO)


def fetch_cves_and_save(
    start_date: datetime,
    end_date: datetime,
    start_index: int,
    output_directory: str,
):
    """
    Fetch CVEs for the given date range and save them to a file.

    @params:    start_date: datetime, end_date: datetime,
                start_index: int, output_directory: str
    @output: None
    """
    params = {
        "pubStartDate": start_date.isoformat(),
        "pubEndDate": end_date.isoformat(),
        "startIndex": start_index,
        "resultsPerPage": RESULTS_PER_PAGE,
    }

    try:
        response = requests.get(BASE_URL, params=params)
        response.raise_for_status()
        data = response.json()
        with open(
            f"{output_directory}/cves-{end_date.date()}-{start_index}.json", "w"
        ) as f:
            json.dump(data, f)
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data: {e}")
    except Exception as e:
        logging.error(f"Error: {e}")


def get_total_results(
    start_date: datetime,
    end_date: datetime,
) -> str:
    """
    Fetch the total number of results for the given date range.

    @params: start_date: datetime, end_date: datetime,
    @output: str
    """
    params = {
        "pubStartDate": start_date.isoformat(),
        "pubEndDate": end_date.isoformat(),
        "startIndex": 0,
        "resultsPerPage": 1,
    }
    try:
        response = requests.get(BASE_URL, params=params)
        response.raise_for_status()
        data = response.json()
        return data["totalResults"]
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data: {e}")
    except Exception as e:
        logging.error(f"Error: {e}")
    return 0


def download_cves_threaded(
    total_results: int, date_start: datetime, date_end: datetime, output_directory: str
):
    """
    Download CVE data from the NVD in a multithreaded manner and save it.

    @params: total_results: int, date_start: datetime, date_end: datetime, output_directory: str
    @output: None
    """
    threads = []
    for index in range(0, total_results, RESULTS_PER_PAGE):
        threads.append(
            threading.Thread(
                target=fetch_cves_and_save,
                args=(date_start, date_end, index, output_directory),
            )
        )
        threads[-1].start()

    for t in threads:
        t.join()


@app.command()
def fetch_cves(days_back: int = MAX_DAYS, output_directory: str = "cve_data"):
    """
    Fetch CVEs for the specified number of days back and save them in the output directory.

    @params: days_back: int, output_directory: str (Typer)
    @output: None
    """
    today = datetime.now()
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    for days in range(days_back, 0, -MAX_DAYS):
        if days > MAX_DAYS:
            date_start = today - timedelta(days=MAX_DAYS)
        else:
            date_start = today - timedelta(days=days)

        total_results = get_total_results(date_start, today)

        if total_results > 0:
            logging.info(f"Downloading CVEs for {date_start.date()} to {today.date()}")
            download_cves_threaded(total_results, date_start, today, output_directory)

        today = date_start


if __name__ == "__main__":
    app()
