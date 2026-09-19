import pandas as pd
import numpy as np
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data" / "processed" / "sessions_features.csv"
df = pd.read_csv(DATA)
df["session_duration_minutes"] = df["session_duration_minutes"].clip(lower=0)

FEATURES = [
    "session_duration_minutes", "hour_of_day", "day_of_week", "is_weekend", "is_after_hours",
    "is_own_pc", "unique_pcs_used_that_day", "files_accessed_per_session",
    "filecount_doc", "filecount_exe", "filecount_jpg", "filecount_pdf", "filecount_txt", "filecount_zip",
    "device_connect_count", "events_prev_hour", "events_prev_day",
]

y = df["label"].values
rows = []
for f in FEATURES:
    x = df[f].values.astype(float)
    if x.std() == 0:
        corr = 0.0
    else:
        corr = np.corrcoef(x, y)[0, 1]
    rows.append((f, corr))

rows.sort(key=lambda r: -abs(r[1]))
print(f"{'feature':28s} {'corr with label':>16s}", flush=True)
for f, c in rows:
    print(f"{f:28s} {c:16.4f}", flush=True)
