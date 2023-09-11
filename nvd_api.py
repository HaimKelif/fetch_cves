import requests
from datetime import datetime
import logging
import time


BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000  # pagination max by NVD API
MAX_REQUESTS_PER_SECONDS = 5  # 5 with no API key; 50 with an API key
SECONDS = 32


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
    }
    try:
        response = requests.get(BASE_URL, params=params)
        response.raise_for_status()
        data = response.json()
        return data["totalResults"]
    except requests.exceptions.RequestException as e:
        if response.status_code == 403:
            logging.error(f"Sleep after error: {e}")
            time.sleep(SECONDS)
            return get_total_results(start_date, end_date)
        logging.error(f"Error fetching data: {e}")
    except Exception as e:
        logging.error(f"Error: {e}")
    return 0


def get_cves(
    start_date: datetime,
    end_date: datetime,
    start_index: int,
) -> list:
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
    }

    try:
        response = requests.get(BASE_URL, params=params)
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except requests.exceptions.RequestException as e:
        if response.status_code == 403:
            logging.error(f"Sleep after error: {e}")
            time.sleep(SECONDS)
            return get_cves(start_date, end_date, start_index)
        logging.error(f"Error fetching data: {e}")
    except Exception as e:
        logging.error(f"Error: {e}")
