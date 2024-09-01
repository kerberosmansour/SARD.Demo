import requests
import time
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import logging
from typing import Dict, Any

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_nvd_data(cve_id: str) -> Dict[str, Any]:
    """Fetches available CVSS scores and severities from NVD API.

    Args:
        cve_id: The CVE ID to query.

    Returns:
        A dictionary with CVSS version, score, and severity.
    """
    url = f"{API_URL}?cveId={cve_id}"
    retries = 3  # Number of retries in case of rate limit errors
    backoff_time = 30  # Initial backoff time in seconds for 403 errors

    for attempt in range(retries):
        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()

            if "vulnerabilities" not in data or not data["vulnerabilities"]:
                raise Exception(f"No vulnerabilities data found for {cve_id}")

            vulnerability_data = data["vulnerabilities"][0]["cve"]["metrics"]

            # Initialize return values
            latest_cvss = None
            base_severity = None

            # Check for available CVSS metrics and choose the highest version available
            if "cvssMetricV31" in vulnerability_data:
                latest_cvss = vulnerability_data["cvssMetricV31"][0]["cvssData"]
                base_severity = vulnerability_data["cvssMetricV31"][0]["cvssData"].get("baseSeverity")
            elif "cvssMetricV30" in vulnerability_data:
                latest_cvss = vulnerability_data["cvssMetricV30"][0]["cvssData"]
                base_severity = vulnerability_data["cvssMetricV30"][0]["cvssData"].get("baseSeverity")
            elif "cvssMetricV2" in vulnerability_data:
                latest_cvss = vulnerability_data["cvssMetricV2"][0]["cvssData"]
                base_severity = vulnerability_data["cvssMetricV2"][0].get("baseSeverity")
            else:
                raise Exception(f"No CVSS data available for {cve_id}")

            # Extract the base score
            base_score = latest_cvss["baseScore"]

            return {
                "cvss_version": latest_cvss["version"],
                "base_score": base_score,
                "base_severity": base_severity
            }

        except requests.exceptions.HTTPError as e:
            if response.status_code == 403:
                logging.error(f"Rate limit exceeded for CVE {cve_id}. Waiting {backoff_time} seconds before retrying...")
                time.sleep(backoff_time)
                backoff_time *= 2  # Exponential backoff
            else:
                logging.error(f"Failed to fetch data for CVE {cve_id}: {e}")
                return {
                    "cvss_version": None,
                    "base_score": None,
                    "base_severity": None
                }
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to fetch data for CVE {cve_id}: {e}")
            return {
                "cvss_version": None,
                "base_score": None,
                "base_severity": None
            }
        except Exception as e:
            logging.error(f"Failed to process data for CVE {cve_id}: {e}")
            return {
                "cvss_version": None,
                "base_score": None,
                "base_severity": None
            }

    logging.error(f"Exceeded maximum retries for CVE {cve_id}.")
    return {
        "cvss_version": None,
        "base_score": None,
        "base_severity": None
    }

def enrich_parquet_with_nvd_data(parquet_file: str, output_file: str) -> None:
    """Enriches Parquet file with CVSS version, score, and severity from NVD.

    Args:
        parquet_file: Path to the input Parquet file.
        output_file: Path to the output Parquet file with enriched data.
    """
    # Load the existing Parquet file
    df = pd.read_parquet(parquet_file, engine='pyarrow')

    # Initialize lists to store new columns
    cvss_versions = []
    base_scores = []
    base_severities = []

    # Iterate through each row to enrich data
    for index, row in df.iterrows():
        cve_id = row.get("cve")
        if cve_id:
            logging.info(f"Processing CVE {cve_id} (index {index})")
            nvd_data = get_nvd_data(cve_id)
            cvss_versions.append(nvd_data["cvss_version"])
            base_scores.append(nvd_data["base_score"])
            base_severities.append(nvd_data["base_severity"])

            # Print out the results
            print(f"CVE: {cve_id}")
            print(f"CVSS Version: {nvd_data['cvss_version']}")
            print(f"CVSS Score: {nvd_data['base_score']}")
            print(f"CVSS Severity: {nvd_data['base_severity']}")
            print("-" * 40)

            # Sleep for 6 seconds to avoid rate limiting
            time.sleep(6)
        else:
            logging.warning(f"No CVE ID found for index {index}")
            cvss_versions.append(None)
            base_scores.append(None)
            base_severities.append(None)

    # Add the new columns to the DataFrame
    df["cvss_version"] = cvss_versions
    df["base_score"] = base_scores
    df["base_severity"] = base_severities

    # Save the enriched DataFrame back to a Parquet file
    table = pa.Table.from_pandas(df)
    pq.write_table(table, output_file)

    logging.info(f"Enriched data saved to {output_file}")

# Example usage
enrich_parquet_with_nvd_data("output.parquet", "enriched_output.parquet")
