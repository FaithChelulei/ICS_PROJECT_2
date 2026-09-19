import pandas as pd
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data" / "processed" / "sessions_features.csv"
df = pd.read_csv(DATA)

print(f"Total sessions: {len(df)}", flush=True)
print(f"Malicious sessions (label=1): {df['label'].sum()}", flush=True)

print("\n=== device_connect_count ===", flush=True)
print(df["device_connect_count"].describe(), flush=True)
nonzero = (df["device_connect_count"] > 0).mean()
print(f"% of sessions with device_connect_count > 0: {nonzero*100:.2f}%", flush=True)
print("Mean device_connect_count by label:", flush=True)
print(df.groupby("label")["device_connect_count"].mean(), flush=True)

print("\n=== file type counts: % of sessions with each > 0 ===", flush=True)
for col in ["filecount_doc", "filecount_pdf", "filecount_txt", "filecount_jpg", "filecount_zip", "filecount_exe"]:
    pct = (df[col] > 0).mean() * 100
    mean_normal = df.loc[df["label"] == 0, col].mean()
    mean_mal = df.loc[df["label"] == 1, col].mean()
    print(f"{col:16s}  nonzero={pct:6.2f}%   mean(normal)={mean_normal:.3f}   mean(malicious)={mean_mal:.3f}", flush=True)

print("\nDone.", flush=True)
