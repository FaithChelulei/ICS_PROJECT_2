"""Re-evaluation of the models with a person-level split, limits chosen on a
validation set, and synthetic attack injection.

Why this exists (the weaknesses of 02_train_models.py's evaluation):
  1. Its split is by SESSION: the same person's sessions can be in both
     training and test, so the model is partly tested on people it already
     knows.
  2. Its limit (best F1) is chosen on the TEST set and then reported on the
     same test set, which makes precision and recall look a little better
     than they would on new data.
  3. The Security Auditor role has only 7 attack sessions, all from one
     person (JRG0207), so its test result is statistically weak.

What this script does instead, separately for each role:
  * Splits PEOPLE, not sessions: 60% of the people with no attacks train the
    models, 20% form a validation set and 20% a test set. People who carried
    out an attack are shared between validation and test only, never used for
    training. No person appears in two sets.
  * Trains the same two models as 02_train_models.py (Isolation Forest, 200
    trees; Autoencoder 7-12-6-12-7) on the training people's sessions.
  * Chooses the limit (best F1) on the VALIDATION set and reports it once on
    the TEST set, which played no part in any choice.
  * Adds SYNTHETIC ATTACKS: a normal session from a held-out person of the
    role is given the attack signature of a REAL CERT attack session taken
    from the other roles (scenario 1: after hours, long session, files;
    scenario 2: files, busy day, long session; scenario 3: other people's
    computers). Validation and test use different people and different
    donor attackers, so no attack signature is used twice.
    For the Security Auditor, whose only real attacker is in the test set,
    the limit is chosen on the synthetic validation attacks.

Synthetic results are reported separately and never mixed with the real
CERT results. The deployed models in ml/models/ are not changed: nothing
here is saved except the results file.

Run (from the repo root):
  .venv\\Scripts\\python.exe ml\\scripts\\12_validated_evaluation.py
  add --seeds 42,1,2,3,4 to repeat the split with other random people.
"""
import argparse
import json
import os
import time
from pathlib import Path

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data" / "processed" / "sessions_features.csv"
INSIDERS = BASE / "data" / "insiders.csv"
OUT = BASE / "models" / "validated_results.json"

FEATURES = [
    "files_accessed_per_session", "events_prev_day", "events_prev_hour",
    "unique_pcs_used_that_day", "session_duration_minutes", "is_after_hours", "is_own_pc",
]
ROLE_NAMES = {0: "Caregiver", 1: "SecurityAuditor", 2: "SysAdmin"}
# The live website's limits (ml/models/risk_tiers.json, deployment_threshold).
LIVE_LIMITS = {"Caregiver": 0.40, "SecurityAuditor": 0.65, "SysAdmin": 0.60}
# The limits reported in the original evaluation (chosen on the test set).
ORIGINAL = json.loads((BASE / "models" / "overall_results.json").read_text())["per_role"]

# Which features carry each CERT scenario's attack signature. Everything
# else stays as the held-out person's own normal session.
SCENARIO_FEATURES = {
    "1": ["is_after_hours", "session_duration_minutes", "files_accessed_per_session"],
    "2": ["files_accessed_per_session", "events_prev_day", "session_duration_minutes"],
    "3": ["is_own_pc", "unique_pcs_used_that_day", "events_prev_day", "is_after_hours"],
}
SYNTHETIC_PER_SCENARIO = 100
THRESHOLDS = np.round(np.arange(0.01, 0.96, 0.01), 2)


def split_people(users_normal, users_insider, rng):
    normal = np.array(sorted(users_normal))
    insider = np.array(sorted(users_insider))
    rng.shuffle(normal)
    rng.shuffle(insider)
    n_train = int(round(0.6 * len(normal)))
    n_val = int(round(0.2 * len(normal)))
    half = len(insider) // 2
    return {
        "train": set(normal[:n_train]),
        "val": set(normal[n_train:n_train + n_val]) | set(insider[:half]),
        "test": set(normal[n_train + n_val:]) | set(insider[half:]),
    }


def train_models(x_train, seed):
    tf.keras.utils.set_random_seed(seed)
    scaler = StandardScaler().fit(x_train)
    xs = scaler.transform(x_train)
    iso = IsolationForest(n_estimators=200, contamination="auto", random_state=seed, n_jobs=-1).fit(xs)
    ae = keras.Sequential([
        keras.layers.Input(shape=(xs.shape[1],)),
        keras.layers.Dense(12, activation="relu"),
        keras.layers.Dense(6, activation="relu"),
        keras.layers.Dense(12, activation="relu"),
        keras.layers.Dense(xs.shape[1], activation="linear"),
    ])
    ae.compile(optimizer="adam", loss="mse")
    es = keras.callbacks.EarlyStopping(monitor="val_loss", patience=4, restore_best_weights=True)
    ae.fit(xs, xs, epochs=40, batch_size=256, validation_split=0.1, shuffle=True, verbose=0, callbacks=[es])
    iso_raw = -iso.score_samples(xs)
    ae_raw = np.mean((xs - ae.predict(xs, verbose=0, batch_size=4096)) ** 2, axis=1)
    return {"scaler": scaler, "iso": iso, "ae": ae,
            "iso_lo": iso_raw.min(), "iso_hi": iso_raw.max(), "ae_lo": ae_raw.min(), "ae_hi": ae_raw.max()}


def score(m, x):
    xs = m["scaler"].transform(x)
    iso = np.clip((-m["iso"].score_samples(xs) - m["iso_lo"]) / max(m["iso_hi"] - m["iso_lo"], 1e-9), 0, 1)
    ae_raw = np.mean((xs - m["ae"].predict(xs, verbose=0, batch_size=4096)) ** 2, axis=1)
    ae = np.clip((ae_raw - m["ae_lo"]) / max(m["ae_hi"] - m["ae_lo"], 1e-9), 0, 1)
    return (iso + ae) / 2.0


def best_limit(y, s):
    best = (0.0, 0.5)
    for t in THRESHOLDS:
        f1 = f1_score(y, (s >= t).astype(int), zero_division=0)
        if f1 > best[0]:
            best = (f1, float(t))
    return best[1]


def metrics(y, s, limit):
    y = np.asarray(y)
    pred = (s >= limit).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    return {
        "limit": round(float(limit), 2),
        "auc": float(roc_auc_score(y, s)) if 0 < y.sum() < len(y) else None,
        "precision": precision_score(y, pred, zero_division=0),
        "recall": recall_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "false_alarm_rate": fp / max(fp + tn, 1),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "attacks": int(y.sum()), "normal": int(len(y) - y.sum()),
    }


def synthetic_attacks(base_normal, donors, rng):
    """base_normal: normal sessions of held-out people of this role.
    donors: real attack sessions (other roles) with a 'scenario' column."""
    rows = []
    for scen, feats in SCENARIO_FEATURES.items():
        pool = donors[donors["scenario"] == scen]
        if pool.empty:
            continue
        base = base_normal.sample(SYNTHETIC_PER_SCENARIO, replace=True, random_state=rng.integers(1 << 31))
        donor = pool.sample(SYNTHETIC_PER_SCENARIO, replace=True, random_state=rng.integers(1 << 31))
        made = base[FEATURES].to_numpy(dtype=float).copy()
        for f in feats:
            made[:, FEATURES.index(f)] = donor[f].to_numpy(dtype=float)
        rows.append(pd.DataFrame(made, columns=FEATURES).assign(scenario=scen))
    return pd.concat(rows, ignore_index=True)


def run(seed, df):
    rng = np.random.default_rng(seed)
    per_role = {}
    for role, name in ROLE_NAMES.items():
        t0 = time.time()
        sub = df[df["mapped_role"] == role]
        insiders = set(sub.loc[sub["label"] == 1, "user"])
        people = split_people(set(sub["user"]) - insiders, insiders, rng)
        part = {k: sub[sub["user"].isin(v)] for k, v in people.items()}
        x_train = part["train"].loc[part["train"]["label"] == 0, FEATURES].to_numpy(dtype=float)
        m = train_models(x_train, seed)

        # Donor attackers from the other roles, split so validation and test
        # never share one.
        others = df[(df["mapped_role"] != role) & (df["label"] == 1)]
        donor_users = np.array(sorted(others["user"].unique()))
        rng.shuffle(donor_users)
        half = len(donor_users) // 2
        donors = {"val": others[others["user"].isin(donor_users[:half])],
                  "test": others[others["user"].isin(donor_users[half:])]}

        out = {"people": {k: len(v) for k, v in people.items()},
               "insiders": {k: len(v & insiders) for k, v in people.items()},
               "train_sessions": int(len(x_train))}
        scored = {}
        for k in ("val", "test"):
            d = part[k]
            s_real = score(m, d[FEATURES].to_numpy(dtype=float))
            normal = d[d["label"] == 0]
            syn = synthetic_attacks(normal, donors[k], rng)
            s_syn = score(m, syn[FEATURES].to_numpy(dtype=float))
            s_norm = s_real[(d["label"] == 0).to_numpy()]
            scored[k] = {"y": d["label"].to_numpy(), "s": s_real, "s_norm": s_norm, "s_syn": s_syn, "syn": syn}

        val, test = scored["val"], scored["test"]
        y_syn_val = np.r_[np.zeros(len(val["s_norm"])), np.ones(len(val["s_syn"]))]
        s_syn_val = np.r_[val["s_norm"], val["s_syn"]]
        y_syn_test = np.r_[np.zeros(len(test["s_norm"])), np.ones(len(test["s_syn"]))]
        s_syn_test = np.r_[test["s_norm"], test["s_syn"]]

        has_real_val = val["y"].sum() > 0
        limit = best_limit(val["y"], val["s"]) if has_real_val else best_limit(y_syn_val, s_syn_val)
        out["limit_chosen_on"] = "validation (real CERT attacks)" if has_real_val else "validation (synthetic attacks; no real attacker left for validation)"
        out["limit"] = limit
        out["real_test"] = metrics(test["y"], test["s"], limit) if test["y"].sum() > 0 else None
        out["real_test_at_live_limit"] = metrics(test["y"], test["s"], LIVE_LIMITS[name]) if test["y"].sum() > 0 else None
        out["synthetic_test"] = metrics(y_syn_test, s_syn_test, limit)
        out["synthetic_test_at_live_limit"] = metrics(y_syn_test, s_syn_test, LIVE_LIMITS[name])
        out["synthetic_recall_by_scenario"] = {
            scen: {
                "at_validated_limit": float((test["s_syn"][(test["syn"]["scenario"] == scen).to_numpy()] >= limit).mean()),
                "at_live_limit": float((test["s_syn"][(test["syn"]["scenario"] == scen).to_numpy()] >= LIVE_LIMITS[name]).mean()),
                "n": int((test["syn"]["scenario"] == scen).sum()),
            }
            for scen in sorted(test["syn"]["scenario"].unique())
        }
        out["seconds"] = round(time.time() - t0, 1)
        per_role[name] = out
        r = out["real_test"]
        sy = out["synthetic_test"]
        print(f"  [{seed}] {name:15s} limit={limit:.2f} ({'real' if has_real_val else 'synthetic'} val)  "
              + (f"REAL test AUC={r['auc']:.3f} P={r['precision']:.3f} R={r['recall']:.3f} ({r['attacks']} attacks)  " if r else "REAL test: none  ")
              + f"SYNTH test AUC={sy['auc']:.3f} P={sy['precision']:.3f} R={sy['recall']:.3f}  ({out['seconds']}s)", flush=True)
    return per_role


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="42")
    seeds = [int(s) for s in ap.parse_args().seeds.split(",")]

    df = pd.read_csv(DATA)
    df["session_duration_minutes"] = df["session_duration_minutes"].clip(lower=0)
    ins = pd.read_csv(INSIDERS, dtype=str)
    scenario = ins[ins["dataset"] == "4.2"].set_index("user")["scenario"]
    df["scenario"] = df["user"].map(scenario)
    print(f"sessions: {len(df)}; seeds: {seeds}", flush=True)

    runs = {}
    for seed in seeds:
        runs[str(seed)] = run(seed, df)

    summary = {}
    for name in ROLE_NAMES.values():
        def collect(key, field):
            vals = [runs[s][name][key][field] for s in runs if runs[s][name][key] and runs[s][name][key][field] is not None]
            return {"mean": float(np.mean(vals)), "min": float(np.min(vals)), "max": float(np.max(vals)), "n_runs": len(vals)} if vals else None
        summary[name] = {
            "limit": collect_limits(runs, name),
            "real_test": {f: collect("real_test", f) for f in ("auc", "precision", "recall", "f1", "false_alarm_rate")},
            "synthetic_test": {f: collect("synthetic_test", f) for f in ("auc", "precision", "recall", "f1", "false_alarm_rate")},
            "original_evaluation": next(o for o in ORIGINAL if o["role"] == name),
        }

    OUT.write_text(json.dumps({
        "_about": "Person-level split, limit chosen on validation, reported once on test; synthetic attack injection reported separately. See ml/scripts/12_validated_evaluation.py and docs/MODEL_EVALUATION_VALIDATED.md.",
        "seeds": seeds, "summary": summary, "runs": runs,
    }, indent=2, default=float))
    print(f"\nSaved {OUT}", flush=True)


def collect_limits(runs, name):
    vals = [runs[s][name]["limit"] for s in runs]
    return {"mean": float(np.mean(vals)), "min": float(np.min(vals)), "max": float(np.max(vals))}


if __name__ == "__main__":
    main()
