import argparse
from .processor import process_sarif_directory

def main() -> None:
    parser = argparse.ArgumentParser(description="Process SARIF files and save to Parquet.")
    parser.add_argument("base_directory", help="The directory containing SARIF files.")
    parser.add_argument("output_file", help="The output Parquet file.")

    args = parser.parse_args()
    process_sarif_directory(args.base_directory, args.output_file)


if __name__ == "__main__":
    main()