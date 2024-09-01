
# SARD.Demo

## Overview

SARD.Demo is a project designed to extract and process datasets from the NIST Software Assurance Reference Dataset (SARD). Although this project is not directly affiliated with NIST or the SARD initiative, it utilizes the publicly available SARD datasets to create a data frame that helps make sense of the data and enriches it with additional content from the National Vulnerability Database (NVD).

This toolset assists researchers and developers in analyzing software assurance data more effectively by providing scripts that extract relevant information from SARIF files and integrate vulnerability data from the NVD.

## Project Structure

- **SardDataGen.py**: This script processes directories containing SARIF files, extracting relevant security-related information from each SARIF file. The extracted data is compiled into a Pandas DataFrame, which is then saved as a Parquet file for further analysis.

  - **Functions:**
    - `extract_sarif_data(sarif_file: str)`: Extracts data from a SARIF file, such as CVE IDs, CWE IDs, vulnerability locations, and other metadata.
    - `process_directory(directory: str)`: Walks through a directory, processes each SARIF file, and compiles the extracted data.
    - `save_to_parquet(data: List[Dict[str, Any]], output_file: str)`: Saves the compiled data into a Parquet file for efficient storage and retrieval.
    - `main()`: The main function that orchestrates the directory processing and saving of data.

  - **Usage:** The script processes a specified directory of SARIF files and saves the extracted data into a Parquet file named `output.parquet`.

- **UpdateCVE_Data.py**: This script takes a Parquet file containing CVE IDs and enriches it with additional data from the National Vulnerability Database (NVD), such as CVSS version, score, and severity. The enriched data is then saved to another Parquet file.

  - **Functions:**
    - `get_nvd_data(cve_id)`: Fetches CVSS scores and severity data from the NVD API for a given CVE ID.
    - `enrich_parquet_with_nvd_data(parquet_file, output_file)`: Reads the input Parquet file, enriches it with data from the NVD, and saves the enriched data to a new Parquet file.
  
  - **Usage:** The script reads a Parquet file (e.g., `output.parquet`), enriches it with NVD data, and saves it as another Parquet file (e.g., `enriched_output.parquet`).

## Prerequisites

- Python 3.x
- Required Python packages:
  - `requests` (for making API requests)
  - `pandas` (for data manipulation)
  - `pyarrow` (for working with Parquet files)
  - `json` (for handling JSON data)
  - `os` (for file system operations)
  - `logging` (for logging operations)

You can install the required Python packages using pip:
```sh
pip install requests pandas pyarrow
```

## Usage

1. **Extract Data from SARIF Files:**
   - Run `SardDataGen.py` to process a directory of SARIF files. The extracted data will be saved to a Parquet file (e.g., `output.parquet`).

   ```sh
   python SardDataGen.py
   ```

2. **Enrich CVE Data:**
   - Run `UpdateCVE_Data.py` to enrich a Parquet file containing CVE IDs with CVSS data from the NVD. The script will save the enriched data to a new Parquet file.

   ```sh
   python UpdateCVE_Data.py
   ```

## Contribution

Contributions to this project are welcome. If you have ideas for improving the data extraction and enrichment processes or if you wish to expand the functionality of the scripts, feel free to contribute.

## License

This project is licensed under the terms specified by the author. It is not affiliated with or endorsed by the National Institute of Standards and Technology (NIST). 

## Contact

For questions or suggestions regarding this project, please reach out to the project maintainer.
