import argparse
import sys
from .nvd_data_fetcher import NVDDataFetcher

def main():
    parser = argparse.ArgumentParser(
        description="A tool to fetch CVE data from NVD API and enrich Parquet files."
    )

    subparsers = parser.add_subparsers(dest="command")

    # Sub-command to fetch CVE information
    fetch_parser = subparsers.add_parser("fetch", help="Fetch CVE information.")
    fetch_parser.add_argument("cve_id", type=str, help="The CVE ID to fetch data for.")

    # Sub-command to enrich a Parquet file
    enrich_parser = subparsers.add_parser("enrich", help="Enrich a Parquet file with CVE data.")
    enrich_parser.add_argument("input_parquet", type=str, help="Path to the input Parquet file.")
    enrich_parser.add_argument("output_parquet", type=str, help="Path to save the enriched Parquet file.")

    args = parser.parse_args()

    fetcher = NVDDataFetcher()

    if args.command == "fetch":
        cve_data = fetcher.fetch_cve_info(args.cve_id)
        print(f"CVE: {args.cve_id}")
        if cve_data['cvss_version'] and cve_data['base_score'] and cve_data['base_severity']:
            print(f"CVSS Version: {cve_data['cvss_version']}")
            print(f"CVSS Score: {cve_data['base_score']}")
            print(f"CVSS Severity: {cve_data['base_severity']}")
        else:
            print("No CVSS data available for the given CVE ID.")

    elif args.command == "enrich":
        fetcher.enrich_parquet(args.input_parquet, args.output_parquet)
        print(f"Enriched data saved to {args.output_parquet}")

    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
