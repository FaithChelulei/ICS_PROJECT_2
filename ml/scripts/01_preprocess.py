import pandas as pd
import numpy as np
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
OUT = DATA / "processed"
OUT.mkdir(exist_ok=True, parents=True)

DT_FMT = "%m/%d/%Y %H:%M:%S"

print("=== Loading LDAP ===", flush=True)
ldap = pd.read_csv(DATA / "ldap.csv", dtype={"user_id": str})

def map_role(row):
    if row["role"] == "ITAdmin":
        return 2  # System Administrator
    if row["department"] == "6 - Security":
        return 1  # Security Auditor
    return 0  # Caregiver

ldap["mapped_role"] = ldap.apply(map_role, axis=1)
print(ldap["mapped_role"].value_counts().rename({0: "Caregiver", 1: "SecurityAuditor", 2: "SysAdmin"}), flush=True)
role_map = ldap.set_index("user_id")[["mapped_role", "department", "business_unit"]]

print("=== Loading logon.csv ===", flush=True)
logon = pd.read_csv(DATA / "logon.csv", dtype={"user": str, "pc": str})
logon["date"] = pd.to_datetime(logon["date"], format=DT_FMT)
logon = logon.sort_values(["user", "pc", "date"]).reset_index(drop=True)
print(f"logon rows: {len(logon)}", flush=True)

print("=== Building sessions (Logon->Logoff pairing) ===", flush=True)
logon["next_activity"] = logon.groupby(["user", "pc"])["activity"].shift(-1)
logon["next_date"] = logon.groupby(["user", "pc"])["date"].shift(-1)

sessions = logon[logon["activity"] == "Logon"].copy()
sessions["session_end"] = np.where(sessions["next_activity"] == "Logoff", sessions["next_date"], sessions["date"])
sessions["session_end"] = pd.to_datetime(sessions["session_end"])
sessions["session_duration_minutes"] = (sessions["session_end"] - sessions["date"]).dt.total_seconds() / 60.0
sessions = sessions.rename(columns={"date": "session_start"})
sessions = sessions[["user", "pc", "session_start", "session_end", "session_duration_minutes"]].reset_index(drop=True)
sessions["session_id"] = np.arange(len(sessions))
print(f"sessions built: {len(sessions)}", flush=True)

print("=== Time features ===", flush=True)
sessions["hour_of_day"] = sessions["session_start"].dt.hour
sessions["day_of_week"] = sessions["session_start"].dt.dayofweek
sessions["is_weekend"] = (sessions["day_of_week"] >= 5).astype(int)
sessions["is_after_hours"] = ((sessions["hour_of_day"] < 6) | (sessions["hour_of_day"] >= 20)).astype(int)

print("=== Own-PC feature ===", flush=True)
user_main_pc = logon.groupby("user")["pc"].agg(lambda x: x.value_counts().idxmax())
sessions["is_own_pc"] = (sessions["pc"] == sessions["user"].map(user_main_pc)).astype(int)

print("=== unique_pcs_used_that_day ===", flush=True)
logon["cal_date"] = logon["date"].dt.date
daily_pc = logon.groupby(["user", "cal_date"])["pc"].nunique().rename("unique_pcs_used_that_day")
sessions["cal_date"] = sessions["session_start"].dt.date
sessions = sessions.merge(daily_pc, left_on=["user", "cal_date"], right_index=True, how="left")
sessions["unique_pcs_used_that_day"] = sessions["unique_pcs_used_that_day"].fillna(1).astype(int)

print("=== Loading file.csv ===", flush=True)
files = pd.read_csv(DATA / "file.csv", usecols=["date", "user", "pc", "filename"], dtype={"user": str, "pc": str})
files["date"] = pd.to_datetime(files["date"], format=DT_FMT)
files["ext"] = files["filename"].str.extract(r"\.([A-Za-z0-9]+)$")[0].str.lower()
files["ext"] = files["ext"].where(files["ext"].isin(["doc", "pdf", "txt", "jpg", "zip", "exe"]), "other")
print(f"file rows: {len(files)}", flush=True)

print("=== Loading device.csv ===", flush=True)
device_raw = pd.read_csv(DATA / "device.csv", dtype={"user": str, "pc": str})
device_raw["date"] = pd.to_datetime(device_raw["date"], format=DT_FMT)
device_connect = device_raw[device_raw["activity"] == "Connect"].copy()
print(f"device rows: {len(device_raw)} (connect: {len(device_connect)})", flush=True)


def assign_to_sessions(events, sessions):
    events = events.sort_values("date")
    sess_sorted = sessions[["user", "session_id", "session_start", "session_end"]].sort_values("session_start")
    merged = pd.merge_asof(events, sess_sorted, left_on="date", right_on="session_start", by="user", direction="backward")
    cap_end = merged["session_start"] + pd.Timedelta(days=1)
    valid_end = merged["session_end"].where(merged["session_end"] <= cap_end, cap_end)
    ok = (merged["date"] >= merged["session_start"]) & (merged["date"] <= valid_end)
    return merged[ok]


print("=== Assigning file events to sessions ===", flush=True)
files_assigned = assign_to_sessions(files, sessions)
file_counts = files_assigned.groupby("session_id").size().rename("files_accessed_per_session")
ext_counts = files_assigned.pivot_table(index="session_id", columns="ext", aggfunc="size", fill_value=0)
ext_counts = ext_counts.add_prefix("filecount_")

print("=== Assigning device connect events to sessions ===", flush=True)
device_assigned = assign_to_sessions(device_connect, sessions)
device_counts = device_assigned.groupby("session_id").size().rename("device_connect_count")

sessions = sessions.set_index("session_id")
sessions = sessions.join(file_counts).join(ext_counts).join(device_counts)
count_cols = ["files_accessed_per_session", "device_connect_count"] + list(ext_counts.columns)
for col in count_cols:
    sessions[col] = sessions[col].fillna(0).astype(int)
sessions = sessions.reset_index()

print("=== Rolling activity counts (prev hour / prev day), per user ===", flush=True)
all_events = pd.concat([
    logon[["user", "date"]],
    files[["user", "date"]],
    device_raw[["user", "date"]],
], ignore_index=True).sort_values(["user", "date"])

def rolling_counts(sessions, all_events):
    ev_by_user = {u: g["date"].values.astype("datetime64[ns]") for u, g in all_events.groupby("user")}
    sessions = sessions.reset_index(drop=True)
    hour_arr = np.zeros(len(sessions), dtype=int)
    day_arr = np.zeros(len(sessions), dtype=int)
    for u, grp in sessions.groupby("user"):
        times = ev_by_user.get(u)
        if times is None or len(times) == 0:
            continue
        starts = grp["session_start"].values.astype("datetime64[ns]")
        hi = np.searchsorted(times, starts, side="right")
        lo_h = np.searchsorted(times, starts - np.timedelta64(1, "h"), side="right")
        lo_d = np.searchsorted(times, starts - np.timedelta64(1, "D"), side="right")
        idx = grp.index.values
        hour_arr[idx] = hi - lo_h
        day_arr[idx] = hi - lo_d
    return hour_arr, day_arr

sessions["events_prev_hour"], sessions["events_prev_day"] = rolling_counts(sessions, all_events)

print("=== Joining role/department from LDAP ===", flush=True)
sessions = sessions.merge(role_map, left_on="user", right_index=True, how="left")
sessions["mapped_role"] = sessions["mapped_role"].fillna(0).astype(int)

print("=== Labeling against insiders.csv (evaluation only, NOT a model input) ===", flush=True)
insiders = pd.read_csv(DATA / "insiders.csv", dtype={"dataset": str, "user": str})
insiders["start"] = pd.to_datetime(insiders["start"], format=DT_FMT, errors="coerce")
insiders["end"] = pd.to_datetime(insiders["end"], format=DT_FMT, errors="coerce")
insiders = insiders[insiders["dataset"] == "4.2"]
print(f"insider ground-truth rows for r4.2: {len(insiders)}", flush=True)

sessions["label"] = 0
for _, row in insiders.iterrows():
    mask = (sessions["user"] == row["user"]) & (sessions["session_start"] >= row["start"]) & (sessions["session_start"] <= row["end"])
    sessions.loc[mask, "label"] = 1

print(f"\nTotal sessions: {len(sessions)}", flush=True)
print("Sessions by mapped_role:", flush=True)
print(sessions["mapped_role"].value_counts(), flush=True)
print("\nLabel counts:", flush=True)
print(sessions["label"].value_counts(), flush=True)
print("\nLabel counts by role:", flush=True)
print(sessions.groupby("mapped_role")["label"].value_counts(), flush=True)

out_path = OUT / "sessions_features.csv"
sessions.drop(columns=["cal_date"], errors="ignore").to_csv(out_path, index=False)
print(f"\nSaved: {out_path}", flush=True)
print("\nColumns:", list(sessions.columns), flush=True)
print("\nDone.", flush=True)
