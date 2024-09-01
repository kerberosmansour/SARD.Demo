import json
import os
from typing import List, Dict, Any

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq


def extract_sarif_data(sarif_file: str) -> List[Dict[str, Any]]:
    """Extracts relevant data from a SARIF file.

    Args:
        sarif_file: Path to the SARIF file.

    Returns:
        A list of dictionaries containing extracted data.
    """
    with open(sarif_file, 'r') as file:
        sarif_data = json.load(file)

    extracted_data = []
    runs = sarif_data.get('runs', [])
    for run in runs:
        # Extracting properties
        properties = run.get('properties', {})
        author = properties.get('author', None)
        language = properties.get('language', None)
        application = properties.get('application', None)
        cves = properties.get('cves', [None])[0]  # Taking the first CVE if it exists

        results = run.get('results', [])
        for result in results:
            rule_id = result.get('ruleId')
            message = result.get('message', {}).get('text')
            locations = result.get('locations', [])
            cwe = rule_id  # CWE ID

            for location in locations:
                artifact_location = location.get('physicalLocation', {}).get(
                    'artifactLocation', {}).get('uri')
                region = location.get('physicalLocation', {}).get('region', {})
                start_line = region.get('startLine')
                end_line = region.get('endLine')
                start_column = region.get('startColumn')
                end_column = region.get('endColumn')

                extracted_data.append({
                    'rule_id': rule_id,
                    'message': message,
                    'cwe': cwe,
                    'cve': cves,
                    'artifact_location': artifact_location,
                    'start_line': start_line,
                    'end_line': end_line,
                    'start_column': start_column,
                    'end_column': end_column,
                    'author': author,
                    'language': language,
                    'application': application,
                    'sarif_file': sarif_data  # Storing the entire JSON content
                })
    return extracted_data


def process_directory(directory: str) -> List[Dict[str, Any]]:
    """Processes a directory, extracting SARIF data from all SARIF files.

    Args:
        directory: The base directory to process.

    Returns:
        A list of dictionaries containing the extracted data from all SARIF files.
    """
    all_data = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.sarif'):
                file_path = os.path.join(root, file)
                data = extract_sarif_data(file_path)
                all_data.extend(data)

    return all_data


def save_to_parquet(data: List[Dict[str, Any]], output_file: str) -> None:
    """Saves extracted data to a Parquet file.

    Args:
        data: The extracted data to save.
        output_file: The path of the output Parquet file.
    """
    df = pd.DataFrame(data)
    table = pa.Table.from_pandas(df)
    pq.write_table(table, output_file)


def main() -> None:
    """Main function to process the SARIF files and save the results."""
    base_directory = "sard_dataset/2015-03-31-wordpress-v2-0"  # Replace with the actual base directory
    output_file = "output.parquet"

    data = process_directory(base_directory)
    save_to_parquet(data, output_file)

    print(f"Data saved to {output_file}")


if __name__ == "__main__":
    main()