"""
Test: what actually happens if device.csv is fully excluded (not even
contributing to events_prev_hour/events_prev_day)? Recomputes those two
columns from logon.csv + file.csv only, compares to the current versions
(which include device.csv), and checks AUC impact per role.
"""
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score

DATA_DIR = str(Path(__file__).resolve().parent.parent / "data")
DT_FMT = "%m/%d/%Y %H:%M:%S"

print("Loading raw logs...", flush=True)
logon = pd.read_csv(DATA_DIR + r"\logon.csv", dtype={"user": str, "pc": str})
logon["date"] = pd.to_datetime(logon["date"], format=DT_FMT)
files = pd.read_csv(DATA_DIR + r"\file.csv", usecols=["date", "user", "pc", "filename"], dtype={"user": str, "pc": str})
files["date"] = pd.to_datetime(files["date"], format=DT_FMT)

sessions = pd.read_csv(Path(DATA_DIR) / "processed" / "sessions_features.csv")
sessions["session_start"] = pd.to_datetime(sessions["session_start"])
sessions["session_duration_minutes"] = sessions["session_duration_minutes"].clip(lower=0)

all_events_no_device = pd.concat(
    [logon[["user", "date"]], files[["user", "date"]]], ignore_index=True
).sort_values(["user", "date"])

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

print("Recomputing events_prev_hour/day WITHOUT device.csv...", flush=True)
sessions["events_prev_hour_nodev"], sessions["events_prev_day_nodev"] = rolling_counts(sessions, all_events_no_device)

diff_hour = (sessions["events_prev_hour"] - sessions["events_prev_hour_nodev"]).abs()
diff_day = (sessions["events_prev_day"] - sessions["events_prev_day_nodev"]).abs()
print(f"\nevents_prev_hour changed in {(diff_hour>0).mean()*100:.2f}% of sessions, mean abs diff={diff_hour.mean():.4f}, max diff={diff_hour.max()}", flush=True)
print(f"events_prev_day  changed in {(diff_day>0).mean()*100:.2f}% of sessions, mean abs diff={diff_day.mean():.4f}, max diff={diff_day.max()}", flush=True)

FEATURES_WITH_DEVICE = ["files_accessed_per_session", "events_prev_day", "events_prev_hour",
                        "unique_pcs_used_that_day", "session_duration_minutes", "is_after_hours", "is_own_pc"]
FEATURES_NO_DEVICE = ["files_accessed_per_session", "events_prev_day_nodev", "events_prev_hour_nodev",
                      "unique_pcs_used_that_day", "session_duration_minutes", "is_after_hours", "is_own_pc"]
ROLE_NAMES = {0: "Caregiver", 1: "SecurityAuditor", 2: "SysAdmin"}

def eval_featureset(sub, features, seed=42):
    X_all = sub[features].fillna(0).values
    y_all = sub["label"].values
    normal_idx = np.where(y_all == 0)[0]
    mal_idx = np.where(y_all == 1)[0]
    rng = np.random.RandomState(seed)
    rng.shuffle(normal_idx)
    n_test_normal = max(1, int(0.2 * len(normal_idx)))
    test_idx = np.concatenate([normal_idx[:n_test_normal], mal_idx])
    train_idx = normal_idx[n_test_normal:]
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_all[train_idx])
    X_test = scaler.transform(X_all[test_idx])
    y_test = y_all[test_idx]
    iso = IsolationForest(n_estimators=200, contamination="auto", random_state=seed, n_jobs=-1)
    iso.fit(X_train)
    score = -iso.score_samples(X_test)
    return roc_auc_score(y_test, score)

print(f"\n{'Role':18s} {'AUC (with device)':>20s} {'AUC (no device)':>18s} {'Diff':>8s}", flush=True)
for role, name in ROLE_NAMES.items():
    sub = sessions[sessions["mapped_role"] == role].reset_index(drop=True)
    auc_with = eval_featureset(sub, FEATURES_WITH_DEVICE)
    auc_without = eval_featureset(sub, FEATURES_NO_DEVICE)
    print(f"{name:18s} {auc_with:20.4f} {auc_without:18.4f} {auc_without-auc_with:+8.4f}", flush=True)

print("\nDone.", flush=True)
