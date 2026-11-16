"""
Flask ML risk-scoring microservice.

Loads the per-role models trained by ml/scripts/02_train_models.py and
exposes a single scoring endpoint that the Node backend calls on every
risk-relevant action (login, child-record access, etc).

Reproduces the EXACT scoring formula from 02_train_models.py:
    iso_raw   = -IsolationForest.score_samples(X_scaled)
    iso_score = clip((iso_raw - iso_train_min) / (iso_train_max - iso_train_min), 0, 1)
    ae_raw    = mean((X_scaled - autoencoder.predict(X_scaled)) ** 2, axis=1)
    ae_score  = clip((ae_raw - ae_train_min) / (ae_train_max - ae_train_min), 0, 1)
    risk_score = (iso_score + ae_score) / 2.0

Thresholds come from ml/models/risk_tiers.json (review_threshold per role) --
that is the authoritative, documented production cutoff. It is NOT the same
as best_threshold in meta_<role>.json, which is just "best F1 on this role's
small held-out test set" and happens to be close, not the policy threshold.

Run:  .venv\\Scripts\\python.exe ml\\service\\app.py
Listens on http://127.0.0.1:5001 by default (override with ML_SERVICE_PORT).
"""
import hashlib
import json
import os
from pathlib import Path

import joblib
import numpy as np
from flask import Flask, jsonify, request
from tensorflow import keras

BASE = Path(__file__).resolve().parent.parent
MODELS = BASE / "models"

ROLES = ["Caregiver", "SecurityAuditor", "SysAdmin"]
# Roles scored with another role's trained models. CERT r4.2 has no teacher:
# an Educator is ordinary staff reading records, which is the group the
# "Caregiver" models were trained on (every CERT employee who is not an IT
# administrator or in the security department). An Educator keeps their own
# name, limit and "normal session" everywhere; only the fitted models are
# shared. Recorded in risk_tiers.json ("uses_models_of").
MODEL_OF = {"Educator": "Caregiver"}
ALL_ROLES = ROLES + list(MODEL_OF)

# A normal working session in THIS app, per role (docs/RISK_THRESHOLDS.md,
# "Normal working session"). Used only to explain a score: each feature in
# turn is reset to this value and the session re-scored; how much the score
# falls is how much that feature raised it. The CERT training averages are
# not used for this because ordinary app use differs from CERT office
# sessions (domain shift) and would make normal activity look like the cause.
NORMAL_SESSION = {
    "Caregiver": {"files_accessed_per_session": 3, "events_prev_hour": 4, "events_prev_day": 6,
                  "unique_pcs_used_that_day": 1, "session_duration_minutes": 20, "is_after_hours": 0, "is_own_pc": 1},
    "SecurityAuditor": {"files_accessed_per_session": 3, "events_prev_hour": 4, "events_prev_day": 8,
                        "unique_pcs_used_that_day": 1, "session_duration_minutes": 30, "is_after_hours": 0, "is_own_pc": 1},
    "SysAdmin": {"files_accessed_per_session": 2, "events_prev_hour": 3, "events_prev_day": 6,
                 "unique_pcs_used_that_day": 1, "session_duration_minutes": 30, "is_after_hours": 0, "is_own_pc": 1},
    # A teacher's ordinary sitting: a handful of the children they teach.
    "Educator": {"files_accessed_per_session": 5, "events_prev_hour": 8, "events_prev_day": 10,
                 "unique_pcs_used_that_day": 1, "session_duration_minutes": 20, "is_after_hours": 0, "is_own_pc": 1},
}

app = Flask(__name__)
_registry = {}


def load_registry():
    """Load all 3 roles' artifacts once at startup, kept in memory."""
    with open(MODELS / "risk_tiers.json") as f:
        tiers = json.load(f)

    for role in ROLES:
        with open(MODELS / f"meta_{role}.json") as f:
            meta = json.load(f)

        scaler = joblib.load(MODELS / f"scaler_{role}.joblib")
        iso = joblib.load(MODELS / f"isoforest_{role}.joblib")
        ae = keras.models.load_model(MODELS / f"autoencoder_{role}.keras")

        # Fingerprint of the exact model files, stored with every score so
        # a flag can always be traced to the model that produced it.
        digest = hashlib.sha256()
        for name in (f"meta_{role}.json", f"scaler_{role}.joblib", f"isoforest_{role}.joblib", f"autoencoder_{role}.keras"):
            digest.update((MODELS / name).read_bytes())

        _registry[role] = {
            "model_version": f"{role}-{digest.hexdigest()[:12]}",
            "features": meta["features"],
            "scaler": scaler,
            "iso": iso,
            "ae": ae,
            "iso_lo": meta["iso_train_min"],
            "iso_hi": meta["iso_train_max"],
            "ae_lo": meta["ae_train_min"],
            "ae_hi": meta["ae_train_max"],
            # deployment_threshold (live app) if set, else the research
            # review_threshold. See risk_tiers.json "_deployment_thresholds".
            "threshold": tiers[role].get("deployment_threshold", tiers[role]["review_threshold"]),
        }

    for role, source in MODEL_OF.items():
        _registry[role] = {
            **_registry[source],
            # Traceable to the exact files AND to the fact they are shared.
            "model_version": f"{role}-as-{_registry[source]['model_version']}",
            "threshold": tiers[role].get("deployment_threshold", _registry[source]["threshold"]),
        }

    print(f"[ml-service] loaded models for roles: {', '.join(_registry.keys())}", flush=True)


def score_one(role, features_dict):
    """Compute the risk score for one role using one set of 7 features.
    Raises ValueError (caught by the route) on bad input."""
    reg = _registry[role]
    feature_names = reg["features"]

    missing = [f for f in feature_names if f not in features_dict]
    if missing:
        raise ValueError(f"missing features: {', '.join(missing)}")

    try:
        x = np.array([[float(features_dict[f]) for f in feature_names]])
    except (TypeError, ValueError):
        raise ValueError("all feature values must be numeric")

    # Row 0 is the session itself; row i+1 is the same session with feature i
    # reset to a normal value (see NORMAL_SESSION). One batched call scores all.
    normal = NORMAL_SESSION[role]
    rows = np.repeat(x, len(feature_names) + 1, axis=0)
    for i, name in enumerate(feature_names):
        rows[i + 1, i] = normal[name]
    x_scaled = reg["scaler"].transform(rows)

    iso_raw = -reg["iso"].score_samples(x_scaled)
    iso_span = max(reg["iso_hi"] - reg["iso_lo"], 1e-9)
    iso_all = np.clip((iso_raw - reg["iso_lo"]) / iso_span, 0, 1)

    recon = reg["ae"].predict(x_scaled, verbose=0)
    ae_raw = np.mean((x_scaled - recon) ** 2, axis=1)
    ae_span = max(reg["ae_hi"] - reg["ae_lo"], 1e-9)
    ae_all = np.clip((ae_raw - reg["ae_lo"]) / ae_span, 0, 1)

    scores = (iso_all + ae_all) / 2.0
    iso_score, ae_score, risk_score = float(iso_all[0]), float(ae_all[0]), float(scores[0])
    threshold = reg["threshold"]

    # What raised the score: features whose reset lowers it by at least 0.005,
    # largest first.
    drivers = sorted(
        ({"feature": name, "value": float(x[0][i]), "raised_by": round(risk_score - float(scores[i + 1]), 4)}
         for i, name in enumerate(feature_names)),
        key=lambda d: d["raised_by"], reverse=True,
    )
    drivers = [d for d in drivers if d["raised_by"] >= 0.005][:3]

    return {
        "role": role,
        "model_version": reg["model_version"],
        "drivers": drivers,
        "risk_score": round(risk_score, 6),
        "iso_score": round(iso_score, 6),
        "ae_score": round(ae_score, 6),
        "threshold": threshold,
        "flagged": bool(risk_score >= threshold),
    }


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "roles_loaded": list(_registry.keys()),
                    "weekly_review": _weekly["model"].version if _weekly.get("model") else None})


# ---------------------------------------------------------------- layer 2
# The weekly review (ml/service/weekly.py, trained by
# ml/scripts/16_train_weekly.py). Ranks each person's week for a human to
# review; it never signs anyone out. Optional: if its files are missing the
# service still runs layer 1 and /score_week answers 503.
_weekly = {}
WEEKLY_DIR = MODELS / "weekly"
MAX_WEEKLY_SESSIONS = 200_000


def load_weekly():
    if not (WEEKLY_DIR / "layer2_meta.json").exists():
        print("[ml-service] weekly review model not found (run ml/scripts/16_train_weekly.py)", flush=True)
        return
    import weekly
    _weekly["module"] = weekly
    _weekly["model"] = weekly.Layer2.load(WEEKLY_DIR)
    print(f"[ml-service] loaded weekly review model {_weekly['model'].version}", flush=True)


@app.route("/score_week", methods=["POST"])
def score_week():
    """Body: {"date": "YYYY-MM-DD" (any day of the week to review),
              "sessions": [{"user": id, "role": "Caregiver", "start":
                "YYYY-MM-DDTHH:MM:SS" (local time), "pc": "...",
                <the 7 features>}, ...]}
    The sessions must cover that week and the 30 days before it."""
    if not _weekly.get("model"):
        return jsonify({"error": "weekly review model not loaded"}), 503
    import pandas as pd
    weekly = _weekly["module"]
    body = request.get_json(silent=True) or {}
    rows = body.get("sessions")
    if not isinstance(rows, list) or len(rows) > MAX_WEEKLY_SESSIONS:
        return jsonify({"error": f"sessions must be a list of at most {MAX_WEEKLY_SESSIONS}"}), 400
    try:
        day = pd.Timestamp(str(body.get("date")))
    except (TypeError, ValueError):
        return jsonify({"error": "date must be YYYY-MM-DD"}), 400
    week = str(day.to_period("W"))
    if not rows:
        return jsonify({"week": week, "people": [], "limits": _weekly["model"].limits}), 200
    try:
        s = pd.DataFrame(rows)
        missing = [c for c in ["user", "role", "start", "pc"] + weekly.BASE_FEATURES if c not in s]
        if missing:
            raise ValueError(f"missing fields: {', '.join(missing)}")
        if not s["role"].isin(ALL_ROLES).all():
            raise ValueError(f"role must be one of {ALL_ROLES}")
        s["start"] = pd.to_datetime(s["start"], format="%Y-%m-%dT%H:%M:%S")
        s["pc"] = s["pc"].fillna("unknown").astype(str)
        s["user"] = s["user"].astype(str)
        for f in weekly.BASE_FEATURES:
            s[f] = pd.to_numeric(s[f], errors="raise").astype(float)
    except (TypeError, ValueError) as e:
        return jsonify({"error": f"bad sessions: {e}"}), 400
    # The weekly model knows its three training roles; a shared-model role
    # is scored as its source role and reported under its own name.
    own_role = s.drop_duplicates("user", keep="last").set_index("user")["role"].to_dict()
    s["role"] = s["role"].replace(MODEL_OF)
    # Optional lines from the deployment's own calibration, keyed by the
    # model's roles ({"Caregiver": {"learned": .., "change": ..}}). They can
    # only raise a line, never lower it (weekly.Layer2.lines).
    local = body.get("local_lines")
    if local is not None and not isinstance(local, dict):
        return jsonify({"error": "local_lines must be an object"}), 400
    people = _weekly["model"].score_people(s, week, local=local)
    for p in people:
        p["role"] = own_role.get(p["user"], p["role"])
    learned, change = _weekly["model"].lines(local)
    limits = dict(learned)
    for role, source in MODEL_OF.items():
        limits[role] = limits[source]
    return jsonify({"week": week, "people": people, "limits": limits,
                    "lines": {r: {"learned": learned[r], "change": change[r]} for r in learned}}), 200


@app.route("/score", methods=["POST"])
def score():
    body = request.get_json(silent=True) or {}
    role = body.get("role")
    features = body.get("features")

    if role not in ALL_ROLES:
        return jsonify({"error": f"role must be one of {ALL_ROLES}"}), 400
    if not isinstance(features, dict):
        return jsonify({"error": "features must be an object of feature_name -> number"}), 400

    try:
        result = score_one(role, features)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify(result), 200


if __name__ == "__main__":
    load_registry()
    load_weekly()
    port = int(os.environ.get("ML_SERVICE_PORT", "5001"))
    app.run(host="127.0.0.1", port=port)
