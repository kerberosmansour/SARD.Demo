import requests
import time
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import logging
from typing import Dict, Any, Optional

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class NVDDataFetcher:
    """A class to fetch CVSS data from the NVD API and enrich Parquet files with this data."""

    API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self):
        """Initialize the NVDDataFetcher."""
        self.retries = 3
        self.backoff_time = 30

    def fetch_cve_info(self, cve_id: str) -> Dict[str, Optional[Any]]:
        """Fetch available CVSS scores and severities from NVD API.

        Args:
            cve_id: The CVE ID to query.

        Returns:
            A dictionary with CVSS version, score, and severity.
        """
        url = f"{self.API_URL}?cveId={cve_id}"
        backoff_time = self.backoff_time  # Start with the initial backoff time

        for attempt in range(self.retries):
            try:
                response = requests.get(url)
                response.raise_for_status()
                data = response.json()

                logging.info(f"Response from NVD API: {data}")

                if "vulnerabilities" not in data or not data["vulnerabilities"]:
                    logging.warning(f"No vulnerabilities data found for {cve_id}")
                    return self._default_cve_response()

                vulnerability_data = data["vulnerabilities"][0]["cve"]["metrics"]

                latest_cvss, base_severity = self._extract_latest_cvss(vulnerability_data)

                if not latest_cvss:
                    logging.warning(f"No CVSS data available for {cve_id}")
                    return self._default_cve_response()

                base_score = latest_cvss["baseScore"]

                return {
                    "cvss_version": latest_cvss["version"],
                    "base_score": base_score,
                    "base_severity": base_severity
                }

            except requests.exceptions.HTTPError as e:
                if response.status_code == 403:
                    logging.error(
                        f"Rate limit exceeded for CVE {cve_id}. Waiting {backoff_time} seconds before retrying..."
                    )
                    time.sleep(backoff_time)
                    backoff_time *= 2  # Exponential backoff
                else:
                    logging.error(f"Failed to fetch data for CVE {cve_id}: {e}")
                    return self._default_cve_response()
            except requests.exceptions.RequestException as e:
                logging.error(f"Failed to fetch data for CVE {cve_id}: {e}")
                return self._default_cve_response()
            except Exception as e:
                logging.error(f"Failed to process data for CVE {cve_id}: {e}")
                return self._default_cve_response()

        logging.error(f"Exceeded maximum retries for CVE {cve_id}.")
        return self._default_cve_response()

    def enrich_parquet(self, parquet_file: str, output_file: str) -> None:
        """Enriches Parquet file with CVSS version, score, and severity from NVD.

        Args:
            parquet_file: Path to the input Parquet file.
            output_file: Path to the output Parquet file with enriched data.
        """
        df = pd.read_parquet(parquet_file, engine='pyarrow')

        cvss_versions = []
        base_scores = []
        base_severities = []

        for index, row in df.iterrows():
            cve_id = row.get("cve")
            if cve_id:
                logging.info(f"Processing CVE {cve_id} (index {index})")
                nvd_data = self.fetch_cve_info(cve_id)
                cvss_versions.append(nvd_data["cvss_version"])
                base_scores.append(nvd_data["base_score"])
                base_severities.append(nvd_data["base_severity"])

                # Print out the results
                print(f"CVE: {cve_id}")
                print(f"CVSS Version: {nvd_data['cvss_version']}")
                print(f"CVSS Score: {nvd_data['base_score']}")
                print(f"CVSS Severity: {nvd_data['base_severity']}")
                print("-" * 40)

                # Sleep to avoid rate limiting
                time.sleep(6)
            else:
                logging.warning(f"No CVE ID found for index {index}")
                cvss_versions.append(None)
                base_scores.append(None)
                base_severities.append(None)

        df["cvss_version"] = cvss_versions
        df["base_score"] = base_scores
        df["base_severity"] = base_severities

        table = pa.Table.from_pandas(df)
        pq.write_table(table, output_file)

        logging.info(f"Enriched data saved to {output_file}")

    def _extract_latest_cvss(self, vulnerability_data: Dict[str, Any]) -> tuple:
        """Extracts the latest CVSS metrics and base severity from the vulnerability data."""
        if "cvssMetricV31" in vulnerability_data:
            cvss_data = vulnerability_data["cvssMetricV31"][0]["cvssData"]
            severity = cvss_data.get("baseSeverity")
        elif "cvssMetricV30" in vulnerability_data:
            cvss_data = vulnerability_data["cvssMetricV30"][0]["cvssData"]
            severity = cvss_data.get("baseSeverity")
        elif "cvssMetricV2" in vulnerability_data:
            cvss_data = vulnerability_data["cvssMetricV2"][0]["cvssData"]
            severity = vulnerability_data["cvssMetricV2"][0].get("baseSeverity")
        else:
            return None, None

        return cvss_data, severity

    def _default_cve_response(self) -> Dict[str, Optional[Any]]:
        """Returns a default response dictionary for failed CVE lookups."""
        return {
            "cvss_version": None,
            "base_score": None,
            "base_severity": None
        }
