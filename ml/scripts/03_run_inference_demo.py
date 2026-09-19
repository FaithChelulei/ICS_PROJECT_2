"""
Demo: load the already-trained models (no retraining) and score real
sessions so you can SEE the anomaly detector working, per role.
Run after 01_preprocess.py / 02_train_models.py (already done).
"""
import json
import numpy as np
import pandas as pd
from pathlib import Path
import joblib
from tensorflow import keras

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data" / "processed" / "sessions_features.csv"
MODELS = BASE / "models"

FEATURES = [
    "files_accessed_per_session", "events_prev_day", "events_prev_hour",
    "unique_pcs_used_that_day", "session_duration_minutes", "is_after_hours", "is_own_pc",
]
ROLE_NAMES = {0: "Caregiver", 1: "SecurityAuditor", 2: "SysAdmin"}
N_SHOW = 10

print("Loading processed sessions...", flush=True)
df = pd.read_csv(DATA)
df["session_duration_minutes"] = df["session_duration_minutes"].clip(lower=0)

for role, role_name in ROLE_NAMES.items():
    print(f"\n{'='*70}\nROLE: {role_name}\n{'='*70}", flush=True)
    sub = df[df["mapped_role"] == role].reset_index(drop=True)

    scaler = joblib.load(MODELS / f"scaler_{role_name}.joblib")
    iso = joblib.load(MODELS / f"isoforest_{role_name}.joblib")
    ae = keras.models.load_model(MODELS / f"autoencoder_{role_name}.keras")
    meta = json.load(open(MODELS / f"meta_{role_name}.json"))
    threshold = meta["best_threshold"]

    X = sub[FEATURES].fillna(0).values
    Xs = scaler.transform(X)

    iso_raw = -iso.score_samples(Xs)
    iso_score = np.clip(
        (iso_raw - meta["iso_train_min"]) / max(meta["iso_train_max"] - meta["iso_train_min"], 1e-9), 0, 1
    )

    recon = ae.predict(Xs, verbose=0)
    ae_raw = np.mean((Xs - recon) ** 2, axis=1)
    ae_score = np.clip(
        (ae_raw - meta["ae_train_min"]) / max(meta["ae_train_max"] - meta["ae_train_min"], 1e-9), 0, 1
    )

    risk = (iso_score + ae_score) / 2.0
    sub["risk_score"] = risk
    sub["flagged"] = (risk >= threshold).astype(int)

    n_mal = int(sub["label"].sum())
    n_caught = int(sub.loc[sub["label"] == 1, "flagged"].sum())
    print(f"threshold used: {threshold:.2f}", flush=True)
    print(f"sessions scored: {len(sub)}  flagged as anomalous: {sub['flagged'].sum()} "
          f"({100*sub['flagged'].mean():.1f}%)", flush=True)
    print(f"real insider-threat sessions in this role: {n_mal}  caught by model: {n_caught}", flush=True)

    print(f"\nTop {N_SHOW} highest-risk sessions:", flush=True)
    top = sub.sort_values("risk_score", ascending=False).head(N_SHOW)
    cols = ["session_id", "user", "pc", "session_start", "risk_score", "flagged", "label"]
    print(top[cols].to_string(index=False), flush=True)

print("\nDone. label=1 means CERT ground truth marks this as a real insider-threat "
      "session (used only to check the model, never fed into training). "
      "flagged=1 means the model's risk_score crossed this role's threshold.", flush=True)
