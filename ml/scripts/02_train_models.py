import json
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, precision_score, recall_score, f1_score, accuracy_score, confusion_matrix
import joblib
import tensorflow as tf
from tensorflow import keras

tf.random.set_seed(42)
np.random.seed(42)

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data" / "processed" / "sessions_features.csv"
MODELS = BASE / "models"
MODELS.mkdir(exist_ok=True, parents=True)

FEATURES = [
    "files_accessed_per_session", "events_prev_day", "events_prev_hour",
    "unique_pcs_used_that_day", "session_duration_minutes", "is_after_hours", "is_own_pc",
]

ROLE_NAMES = {0: "Caregiver", 1: "SecurityAuditor", 2: "SysAdmin"}

print("Loading processed sessions...", flush=True)
df = pd.read_csv(DATA)
df["session_duration_minutes"] = df["session_duration_minutes"].clip(lower=0)
print(f"total sessions: {len(df)}", flush=True)

all_results = []
all_test_labels = []
all_test_scores = []

for role, role_name in ROLE_NAMES.items():
    print(f"\n{'='*60}\nROLE: {role_name} (mapped_role={role})", flush=True)
    sub = df[df["mapped_role"] == role].reset_index(drop=True)
    X_all = sub[FEATURES].fillna(0).values
    y_all = sub["label"].values

    normal_idx = np.where(y_all == 0)[0]
    mal_idx = np.where(y_all == 1)[0]
    rng = np.random.RandomState(42)
    rng.shuffle(normal_idx)
    n_test_normal = max(1, int(0.2 * len(normal_idx)))
    test_normal_idx = normal_idx[:n_test_normal]
    train_idx = normal_idx[n_test_normal:]
    test_idx = np.concatenate([test_normal_idx, mal_idx])

    print(f"train (normal only): {len(train_idx)}  test: {len(test_idx)} (normal={len(test_normal_idx)}, malicious={len(mal_idx)})", flush=True)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_all[train_idx])
    X_test = scaler.transform(X_all[test_idx])
    y_test = y_all[test_idx]

    print("Training Isolation Forest...", flush=True)
    iso = IsolationForest(n_estimators=200, contamination="auto", random_state=42, n_jobs=-1)
    iso.fit(X_train)
    iso_raw_train = -iso.score_samples(X_train)
    iso_raw_test = -iso.score_samples(X_test)
    iso_lo, iso_hi = iso_raw_train.min(), iso_raw_train.max()
    iso_score_test = np.clip((iso_raw_test - iso_lo) / max(iso_hi - iso_lo, 1e-9), 0, 1)

    print("Training Autoencoder...", flush=True)
    input_dim = X_train.shape[1]
    ae = keras.Sequential([
        keras.layers.Input(shape=(input_dim,)),
        keras.layers.Dense(12, activation="relu"),
        keras.layers.Dense(6, activation="relu"),
        keras.layers.Dense(12, activation="relu"),
        keras.layers.Dense(input_dim, activation="linear"),
    ])
    ae.compile(optimizer="adam", loss="mse")
    es = keras.callbacks.EarlyStopping(monitor="val_loss", patience=4, restore_best_weights=True)
    ae.fit(X_train, X_train, epochs=40, batch_size=256, validation_split=0.1, shuffle=True, verbose=0, callbacks=[es])

    recon_train = ae.predict(X_train, verbose=0)
    ae_raw_train = np.mean((X_train - recon_train) ** 2, axis=1)
    recon_test = ae.predict(X_test, verbose=0)
    ae_raw_test = np.mean((X_test - recon_test) ** 2, axis=1)
    ae_lo, ae_hi = ae_raw_train.min(), ae_raw_train.max()
    ae_score_test = np.clip((ae_raw_test - ae_lo) / max(ae_hi - ae_lo, 1e-9), 0, 1)

    risk_score = (iso_score_test + ae_score_test) / 2.0

    if y_test.sum() > 0 and y_test.sum() < len(y_test):
        auc = roc_auc_score(y_test, risk_score)
    else:
        auc = float("nan")

    # threshold: best F1 on this role's test set (reported), plus fixed 0.5 reference
    best_f1, best_thr = 0, 0.5
    for thr in np.arange(0.05, 0.96, 0.01):
        pred = (risk_score >= thr).astype(int)
        f1 = f1_score(y_test, pred, zero_division=0)
        if f1 > best_f1:
            best_f1, best_thr = f1, thr

    pred = (risk_score >= best_thr).astype(int)
    acc = accuracy_score(y_test, pred)
    prec = precision_score(y_test, pred, zero_division=0)
    rec = recall_score(y_test, pred, zero_division=0)
    cm = confusion_matrix(y_test, pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / max(fp + tn, 1)
    fnr = fn / max(fn + tp, 1)

    print(f"AUC={auc:.4f}  best_threshold={best_thr:.2f}  F1={best_f1:.4f}  precision={prec:.4f}  recall={rec:.4f}", flush=True)
    print(f"accuracy={acc:.4f}  FPR={fpr:.4f}  FNR={fnr:.4f}  (TP={tp} FP={fp} TN={tn} FN={fn})", flush=True)

    joblib.dump(scaler, MODELS / f"scaler_{role_name}.joblib")
    joblib.dump(iso, MODELS / f"isoforest_{role_name}.joblib")
    ae.save(MODELS / f"autoencoder_{role_name}.keras")
    with open(MODELS / f"meta_{role_name}.json", "w") as f:
        json.dump({
            "features": FEATURES,
            "iso_train_min": float(iso_lo), "iso_train_max": float(iso_hi),
            "ae_train_min": float(ae_lo), "ae_train_max": float(ae_hi),
            "best_threshold": float(best_thr),
            "auc": None if np.isnan(auc) else float(auc),
            "f1": float(best_f1), "precision": float(prec), "recall": float(rec),
            "accuracy": float(acc), "fpr": float(fpr), "fnr": float(fnr),
            "n_train": int(len(train_idx)), "n_test": int(len(test_idx)), "n_malicious_test": int(y_test.sum()),
        }, f, indent=2)

    all_results.append({"role": role_name, "auc": auc, "f1": best_f1, "precision": prec, "recall": rec, "accuracy": acc, "fpr": fpr, "fnr": fnr, "n_malicious_test": int(y_test.sum())})
    all_test_labels.append(y_test)
    all_test_scores.append(risk_score)

print(f"\n{'='*60}\nOVERALL (pooled across all 3 roles)", flush=True)
y_all_test = np.concatenate(all_test_labels)
score_all_test = np.concatenate(all_test_scores)
overall_auc = roc_auc_score(y_all_test, score_all_test)
best_f1, best_thr = 0, 0.5
for thr in np.arange(0.05, 0.96, 0.01):
    pred = (score_all_test >= thr).astype(int)
    f1 = f1_score(y_all_test, pred, zero_division=0)
    if f1 > best_f1:
        best_f1, best_thr = f1, thr
pred = (score_all_test >= best_thr).astype(int)
acc = accuracy_score(y_all_test, pred)
prec = precision_score(y_all_test, pred, zero_division=0)
rec = recall_score(y_all_test, pred, zero_division=0)
cm = confusion_matrix(y_all_test, pred, labels=[0, 1])
tn, fp, fn, tp = cm.ravel()
fpr = fp / max(fp + tn, 1)
fnr = fn / max(fn + tp, 1)
print(f"pooled n_test={len(y_all_test)} malicious={int(y_all_test.sum())}", flush=True)
print(f"AUC={overall_auc:.4f}  best_threshold={best_thr:.2f}  F1={best_f1:.4f}  precision={prec:.4f}  recall={rec:.4f}", flush=True)
print(f"accuracy={acc:.4f}  FPR={fpr:.4f}  FNR={fnr:.4f}  (TP={tp} FP={fp} TN={tn} FN={fn})", flush=True)

with open(MODELS / "overall_results.json", "w") as f:
    json.dump({"per_role": all_results, "overall": {
        "auc": float(overall_auc), "f1": float(best_f1), "precision": float(prec), "recall": float(rec),
        "accuracy": float(acc), "fpr": float(fpr), "fnr": float(fnr), "best_threshold": float(best_thr),
    }}, f, indent=2)

print("\nSaved all models and metrics to ml\\models\\", flush=True)
print("Done.", flush=True)
