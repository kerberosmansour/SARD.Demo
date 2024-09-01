import pandas as pd

# Read the first 5 rows from the Parquet file
df = pd.read_parquet('output.parquet', engine='pyarrow')
print(df.head())