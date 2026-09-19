import json
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from tensorflow import keras
from sklearn.metrics import precision_score, recall_score

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data" / "processed" / "sessions_features.csv"
MODELS = BASE / "models"

FEATURES = ["files_accessed_per_session", "events_prev_day", "events_prev_hour",
            "unique_pcs_used_that_day", "session_duration_minutes", "is_after_hours", "is_own_pc"]
ROLE_NAMES = {0: "Caregiver", 1: "SecurityAuditor", 2: "SysAdmin"}
CHECKPOINTS = [0.05, 0.10, 0.20, 0.30, 0.50, 0.70, 0.90]

df = pd.read_csv(DATA)
df["session_duration_minutes"] = df["session_duration_minutes"].clip(lower=0)

for role, role_name in ROLE_NAMES.items():
    print(f"\n=== {role_name} ===", flush=True)
    sub = df[df["mapped_role"] == role].reset_index(drop=True)
    X_all = sub[FEATURES].fillna(0).values
    y_all = sub["label"].values
    normal_idx = np.where(y_all == 0)[0]
    mal_idx = np.where(y_all == 1)[0]
    rng = np.random.RandomState(42)
    rng.shuffle(normal_idx)
    n_test_normal = max(1, int(0.2 * len(normal_idx)))
    test_idx = np.concatenate([normal_idx[:n_test_normal], mal_idx])
    y_test = y_all[test_idx]

    scaler = joblib.load(MODELS / f"scaler_{role_name}.joblib")
    iso = joblib.load(MODELS / f"isoforest_{role_name}.joblib")
    ae = keras.models.load_model(MODELS / f"autoencoder_{role_name}.keras")
    meta = json.load(open(MODELS / f"meta_{role_name}.json"))

    X_test = scaler.transform(X_all[test_idx])
    iso_raw = -iso.score_samples(X_test)
    iso_score = np.clip((iso_raw - meta["iso_train_min"]) / max(meta["iso_train_max"] - meta["iso_train_min"], 1e-9), 0, 1)
    recon = ae.predict(X_test, verbose=0)
    ae_raw = np.mean((X_test - recon) ** 2, axis=1)
    ae_score = np.clip((ae_raw - meta["ae_train_min"]) / max(meta["ae_train_max"] - meta["ae_train_min"], 1e-9), 0, 1)
    risk = (iso_score + ae_score) / 2.0

    print(f"risk_score range in test set: min={risk.min():.3f} max={risk.max():.3f} 99th pct={np.percentile(risk,99):.3f}", flush=True)
    for thr in CHECKPOINTS:
        pred = (risk >= thr).astype(int)
        n_flagged = pred.sum()
        prec = precision_score(y_test, pred, zero_division=0)
        rec = recall_score(y_test, pred, zero_division=0)
        print(f"  threshold={thr:.2f}  n_flagged={n_flagged:6d}  precision={prec:.4f}  recall={rec:.4f}", flush=True)

print("\nDone.", flush=True)
