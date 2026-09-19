import pandas as pd
from pathlib import Path
DATA = Path(__file__).resolve().parent.parent / "data" / "processed" / "sessions_features.csv"
df = pd.read_csv(DATA)
row = df[df["session_id"] == 380109]
cols = ["session_id","user","pc","session_start","filecount_doc","filecount_pdf",
        "filecount_txt","filecount_jpg","filecount_zip","filecount_exe",
        "device_connect_count","label"]
print(row[cols].to_string(index=False), flush=True)
