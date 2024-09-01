import json
import os
import logging
from typing import List, Dict, Any

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

logging.basicConfig(level=logging.INFO)


def extract_sarif_data(sarif_file: str) -> List[Dict[str, Any]]:
    """Extracts relevant data from a SARIF file.

    Args:
        sarif_file: Path to the SARIF file.

    Returns:
        A list of dictionaries containing extracted data.
    """
    try:
        with open(sarif_file, 'r') as file:
            sarif_data = json.load(file)
    except FileNotFoundError:
        logging.error(f"File not found: {sarif_file}")
        return []
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from file: {sarif_file}")
        return []

    extracted_data = []
    runs = sarif_data.get('runs', [])
    for run in runs:
        properties = run.get('properties', {})
        author = properties.get('author')
        language = properties.get('language')
        application = properties.get('application')
        cve = properties.get('cves', [None])[0]

        results = run.get('results', [])
        for result in results:
            rule_id = result.get('ruleId')
            message = result.get('message', {}).get('text')
            locations = result.get('locations', [])

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
                    'cwe': rule_id,
                    'cve': cve,
                    'artifact_location': artifact_location,
                    'start_line': start_line,
                    'end_line': end_line,
                    'start_column': start_column,
                    'end_column': end_column,
                    'author': author,
                    'language': language,
                    'application': application,
                    'sarif_file': sarif_file
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
                logging.info(f"Processing file: {file_path}")
                data = extract_sarif_data(file_path)
                all_data.extend(data)

    return all_data


def save_to_parquet(data: List[Dict[str, Any]], output_file: str) -> None:
    """Saves extracted data to a Parquet file.

    Args:
        data: The extracted data to save.
        output_file: The path of the output Parquet file.
    """
    if not data:
        logging.warning("No data to save.")
        return

    df = pd.DataFrame(data)
    table = pa.Table.from_pandas(df)
    pq.write_table(table, output_file)
    logging.info(f"Data saved to {output_file}")


def process_sarif_directory(base_directory: str, output_file: str) -> None:
    """Processes the SARIF files in a directory and saves the results.

    Args:
        base_directory: The directory containing SARIF files.
        output_file: The path where the output Parquet file will be saved.
    """
    data = process_directory(base_directory)
    save_to_parquet(data, output_file)
