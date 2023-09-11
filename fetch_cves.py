import typer
import json
import requests
from datetime import datetime, timedelta
import os
import logging
import concurrent.futures
import nvd_api
import time


app = typer.Typer()

RESULTS_PER_PAGE = 2000  # pagination max by NVD API
RESULTS_PER_FILE = 50
MAX_DAYS_RANGE_API = 120
MAX_REQUESTS_PER_30_SECONDS = 5  # 5 with no API key; 50 with an API key
SECONDS = 32

logging.basicConfig(level=logging.INFO)


def date_chunks_by_api_size(
    start_date: datetime, end_date: datetime
) -> list[tuple((datetime, datetime))]:
    """
    Returns a list of chuncks of the given dates range.

    @params:    start_date: datetime, end_date: datetime
    @output: list[tuple((datetime, datetime))]
    """
    date_range = []
    current_date = start_date
    while current_date <= end_date:
        chunk_end_date = min(
            current_date + timedelta(days=MAX_DAYS_RANGE_API), end_date
        )
        date_range.append((current_date, chunk_end_date))
        current_date += timedelta(days=MAX_DAYS_RANGE_API)
    return date_range


def chunk_list(input_list: list) -> list[list]:
    """
    Returns a list of chuncks of the givven list.

    @params:    input_list: list
    @output: list[list]
    """
    for i in range(0, len(input_list), RESULTS_PER_FILE):
        yield input_list[i : i + RESULTS_PER_FILE]


def save_cves(cves: list, output_directory: str, end_date: datetime, start_index: int):
    """
    save CVEs for the given date range to a file.

    @params:    cves: list, output_directory: str,
                end_date: datetime, start_index: int
    @output: None
    """
    sublists_cves = list(chunk_list(cves))
    for sublist in sublists_cves:
        try:
            with open(
                f"{output_directory}/cves-{end_date.date()}-{start_index}.json", "w"
            ) as f:
                json.dump(sublist, f)
            start_index += RESULTS_PER_FILE
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching data: {e}")
        except Exception as e:
            logging.error(f"Error: {e}")


def fetch_cves_and_save(
    start_date: datetime,
    end_date: datetime,
    start_index: int,
    output_directory: str,
):
    """
    Fetch CVEs for the given date range.

    @params:    start_date: datetime, end_date: datetime,
                start_index: int, output_directory: str
    @output: None
    """
    save_cves(
        nvd_api.get_cves(start_date, end_date, start_index),
        output_directory,
        end_date,
        start_index,
    )


def download_cves_threaded(
    date_chunks: list[tuple((datetime, datetime))], output_directory: str
):
    """
    Download CVE data from the NVD in a multithreaded manner and save it.
    The function sleeps for 32/5 seconds (if there is a key to API 32/50) between requests as required by the API.

    @params: total_results: int, date_start: datetime, date_end: datetime, output_directory: str
    @output: None
    """
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_REQUESTS_PER_30_SECONDS
    ) as executor:
        for date_chunk in date_chunks:
            time.sleep(SECONDS / MAX_REQUESTS_PER_30_SECONDS)
            total_results_in_this_chunck = nvd_api.get_total_results(date_chunk[0], date_chunk[1])
            if total_results_in_this_chunck > 0:
                for index in range(0, total_results_in_this_chunck, RESULTS_PER_PAGE):
                    time.sleep(SECONDS / MAX_REQUESTS_PER_30_SECONDS)
                    executor.submit(
                        fetch_cves_and_save,
                        date_chunk[0],
                        date_chunk[1],
                        index,
                        output_directory,
                    )


@app.command()
def fetch_cves(days_back: int = MAX_DAYS_RANGE_API, output_directory: str = "cve_data"):
    """
    Fetch CVEs for the specified number of days back and save them in the output directory.

    @params: days_back: int, output_directory: str (Typer)
    @output: None
    """
    current_day = datetime.now()

    os.makedirs(output_directory, exist_ok=True)

    day_chunks = date_chunks_by_api_size(
        current_day - timedelta(days=days_back), current_day
    )

    logging.info(
        f"Downloading CVEs for {(current_day - timedelta(days=days_back)).date()} to {current_day.date()}"
    )

    download_cves_threaded(day_chunks, output_directory)


if __name__ == "__main__":
    app()
