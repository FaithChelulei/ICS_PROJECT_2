"""
Quick empirical check: does dropping from 17 features to the proposed 7
lose meaningful detection power? Uses Isolation Forest AUC only (fast,
seconds not minutes) as an apples-to-apples proxy comparison for both
feature sets, same train/test split, same seed, per role.
"""
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score

DATA = Path(__file__).resolve().parent.parent / "data" / "processed" / "sessions_features.csv"
df = pd.read_csv(DATA)
df["session_duration_minutes"] = df["session_duration_minutes"].clip(lower=0)

FEATURES_FULL = [
    "session_duration_minutes", "hour_of_day", "day_of_week", "is_weekend", "is_after_hours",
    "is_own_pc", "unique_pcs_used_that_day", "files_accessed_per_session",
    "filecount_doc", "filecount_exe", "filecount_jpg", "filecount_pdf", "filecount_txt", "filecount_zip",
    "device_connect_count", "events_prev_hour", "events_prev_day",
]
FEATURES_REDUCED = [
    "files_accessed_per_session", "events_prev_day", "events_prev_hour",
    "unique_pcs_used_that_day", "session_duration_minutes", "is_after_hours", "is_own_pc",
]
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

print(f"{'Role':18s} {'AUC (17 feat)':>14s} {'AUC (7 feat)':>14s} {'Diff':>8s}", flush=True)
for role, name in ROLE_NAMES.items():
    sub = df[df["mapped_role"] == role].reset_index(drop=True)
    auc_full = eval_featureset(sub, FEATURES_FULL)
    auc_reduced = eval_featureset(sub, FEATURES_REDUCED)
    print(f"{name:18s} {auc_full:14.4f} {auc_reduced:14.4f} {auc_reduced-auc_full:+8.4f}", flush=True)

print("\nDone. (Isolation-Forest-only AUC, used as a fast proxy for the full hybrid model.)", flush=True)
