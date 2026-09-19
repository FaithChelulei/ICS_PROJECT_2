import json
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from tensorflow import keras
from sklearn.metrics import roc_curve, precision_recall_curve, roc_auc_score
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data" / "processed" / "sessions_features.csv"
MODELS = BASE / "models"
CHARTS = MODELS / "charts"
CHARTS.mkdir(exist_ok=True, parents=True)

FEATURES = ["files_accessed_per_session", "events_prev_day", "events_prev_hour",
            "unique_pcs_used_that_day", "session_duration_minutes", "is_after_hours", "is_own_pc"]
ROLE_NAMES = {0: "Caregiver", 1: "SecurityAuditor", 2: "SysAdmin"}

df = pd.read_csv(DATA)
df["session_duration_minutes"] = df["session_duration_minutes"].clip(lower=0)
tier_results = {}

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

    fpr, tpr, roc_thr = roc_curve(y_test, risk)
    prec, rec, pr_thr = precision_recall_curve(y_test, risk)
    auc = roc_auc_score(y_test, risk)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
    axes[0].plot(fpr, tpr, label=f"AUC={auc:.3f}")
    axes[0].plot([0, 1], [0, 1], "--", color="gray")
    axes[0].set_xlabel("False Positive Rate"); axes[0].set_ylabel("True Positive Rate")
    axes[0].set_title(f"{role_name} - ROC Curve"); axes[0].legend()
    axes[1].plot(rec, prec)
    axes[1].set_xlabel("Recall"); axes[1].set_ylabel("Precision")
    axes[1].set_title(f"{role_name} - Precision-Recall Curve")
    plt.tight_layout()
    fig.savefig(CHARTS / f"{role_name}_roc_pr.png", dpi=150)
    plt.close(fig)

    medium_thr = meta["best_threshold"]
    candidates = [(t, p, r) for p, r, t in zip(prec[:-1], rec[:-1], pr_thr) if t >= medium_thr and r >= 0.15]
    if candidates:
        high_thr, high_p, high_r = max(candidates, key=lambda x: x[1])
    else:
        high_thr, high_p, high_r = medium_thr, None, None
    low_thr = medium_thr * 0.5

    tier_results[role_name] = {
        "low_threshold": float(low_thr), "medium_threshold": float(medium_thr), "high_threshold": float(high_thr),
        "high_tier_precision": None if high_p is None else float(high_p),
        "high_tier_recall": None if high_r is None else float(high_r),
        "auc": float(auc),
    }
    print(f"low={low_thr:.3f}  medium={medium_thr:.3f}  high={high_thr:.3f}  "
          f"(high-tier precision={high_p}, recall={high_r})", flush=True)

with open(MODELS / "risk_tiers.json", "w") as f:
    json.dump(tier_results, f, indent=2)
print("\nSaved risk_tiers.json and ROC/PR charts to ml\\models\\charts\\", flush=True)
print("Done.", flush=True)
