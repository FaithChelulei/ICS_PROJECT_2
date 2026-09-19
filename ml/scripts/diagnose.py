import pandas as pd
from pathlib import Path

DATA = str(Path(__file__).resolve().parent.parent / "data")

device = pd.read_csv(f"{DATA}\\device.csv")
print("device.csv activity unique values:", device["activity"].unique())

insiders = pd.read_csv(f"{DATA}\\insiders.csv", dtype=str)
print("\ninsiders.csv dataset unique values:", sorted(insiders["dataset"].unique()))
print("rows where dataset == '4.2':", (insiders["dataset"] == "4.2").sum())
print("total rows in insiders.csv:", len(insiders))
print(insiders["dataset"].value_counts())
