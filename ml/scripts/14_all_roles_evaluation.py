"""Experiment: does the detector meet clear success targets, for all roles?

Success targets (measured per role on people never used for any choice):
  T1  insider catch rate   share of test insiders flagged in at least one
                           of their attack weeks              (goal >= 80%)
  T2  weekly false alarms  share of normal person-weeks flagged (goal <= 2%)
  T3  watch-list precision share of real attack weeks among the 10
                           highest-scored person-weeks of the role
                                                              (goal >= 33%)
The weekly limit is the 98th percentile of the role's NORMAL validation
person-weeks, so T2 is aimed at 2% by construction and checked on test.

Detectors compared (all scored per session, then per person-week):
  A  current      per-role Isolation Forest + Autoencoder, 7 features,
                  min-max scaled and averaged (the deployed design)
  B  pooled       one Isolation Forest + Autoencoder for all roles, with
                  the role as an input and the per-person 30-day features
                  of 13_improved_evaluation.py; rank-scaled and averaged
  C  stacked      B's two scores plus the features go into a gradient-
                  boosted classifier trained on a separate group of people
                  that includes some insiders (never the test insiders)
  D  weekly       like C, but the classifier sees a whole person-week
                  (counts, maxima and the top session scores of the week)

Split of people, separately inside each role and then combined:
  normal people   40% unsupervised training (A, B)
                  20% classifier training (C, D) | 20% validation | 20% test
  insiders        40% classifier training | 30% validation | 30% test
No person is in two groups. The unsupervised models never see an insider.
The classifier never sees a validation or test person.

Labels: the attack periods of insiders.csv (label_period); a person-week is
an attack week if any of its sessions is labelled. Session-level results
with CERT's exact-event labels are reported alongside.

Needs data/processed/sessions_improved.csv (built by 13_improved_evaluation.py).
Nothing used by the website is changed. Output: models/all_roles_results.json

Run from the repo root:
  .venv\\Scripts\\python.exe ml\\scripts\\14_all_roles_evaluation.py --seeds 42,1,2,3,4
"""
import argparse
import json
import os
import time
from pathlib import Path

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras

BASE = Path(__file__).resolve().parent.parent
DATA = BASE / "data" / "processed" / "sessions_improved.csv"
OUT = BASE / "models" / "all_roles_results.json"

BASE_FEATURES = [
    "files_accessed_per_session", "events_prev_day", "events_prev_hour",
    "unique_pcs_used_that_day", "session_duration_minutes", "is_after_hours", "is_own_pc",
]
DEV_FEATURES = [f"dev_{f}" for f in BASE_FEATURES]
USER_FEATURES = BASE_FEATURES + DEV_FEATURES + ["new_pc", "unusual_hour"]
ROLE_COLS = ["role_0", "role_1", "role_2"]
ROLE_NAMES = {0: "Caregiver", 1: "SecurityAuditor", 2: "SysAdmin"}
DETECTORS = ["A_current", "B_pooled", "C_stacked", "D_weekly"]
LABEL = "label_period"


# ---------------------------------------------------------------- models

def train_unsup(x, seed):
    tf.keras.utils.set_random_seed(seed)
    scaler = StandardScaler().fit(x)
    xs = scaler.transform(x)
    iso = IsolationForest(n_estimators=200, contamination="auto", random_state=seed, n_jobs=-1).fit(xs)
    d = xs.shape[1]
    hidden, code = max(12, int(1.7 * d)), max(6, d // 2)
    ae = keras.Sequential([
        keras.layers.Input(shape=(d,)),
        keras.layers.Dense(hidden, activation="relu"),
        keras.layers.Dense(code, activation="relu"),
        keras.layers.Dense(hidden, activation="relu"),
        keras.layers.Dense(d, activation="linear"),
    ])
    ae.compile(optimizer="adam", loss="mse")
    es = keras.callbacks.EarlyStopping(monitor="val_loss", patience=4, restore_best_weights=True)
    ae.fit(xs, xs, epochs=40, batch_size=512, validation_split=0.1, shuffle=True, verbose=0, callbacks=[es])
    m = {"scaler": scaler, "iso": iso, "ae": ae}
    r = raw(m, x)
    m["ref_iso"], m["ref_ae"] = np.sort(r["iso"]), np.sort(r["ae"])
    return m


def raw(m, x):
    xs = m["scaler"].transform(x)
    return {"iso": -m["iso"].score_samples(xs),
            "ae": np.mean((xs - m["ae"].predict(xs, verbose=0, batch_size=8192)) ** 2, axis=1)}


def minmax_avg(m, x):
    r = raw(m, x)
    f = lambda v, ref: np.clip((v - ref[0]) / max(ref[-1] - ref[0], 1e-9), 0, 1)
    return (f(r["iso"], m["ref_iso"]) + f(r["ae"], m["ref_ae"])) / 2


def ranks(m, x):
    r = raw(m, x)
    return (np.searchsorted(m["ref_iso"], r["iso"], side="right") / len(m["ref_iso"]),
            np.searchsorted(m["ref_ae"], r["ae"], side="right") / len(m["ref_ae"]))


def classifier(seed):
    return HistGradientBoostingClassifier(learning_rate=0.05, max_iter=300, max_leaf_nodes=15,
                                          l2_regularization=1.0, class_weight="balanced", random_state=seed)


# ---------------------------------------------------------------- weeks

def week_table(frame, score_col):
    """One row per person-week: label, a session-score summary (mean of the
    week's three highest), and the weekly features used by detector D."""
    d = frame.assign(week=frame["session_start"].dt.to_period("W").astype(str))
    d = d.sort_values(score_col, ascending=False)
    d["r"] = d.groupby(["user", "week"]).cumcount()
    g = d.groupby(["user", "week"])
    wk = pd.DataFrame({
        "mapped_role": g["mapped_role"].first(),
        "y": g[LABEL].max(),
        "score": d[d["r"] < 3].groupby(["user", "week"])[score_col].mean(),
        "n_sessions": g.size(),
        "files_sum": g["files_accessed_per_session"].sum(),
        "files_max": g["files_accessed_per_session"].max(),
        "events_day_max": g["events_prev_day"].max(),
        "events_hour_max": g["events_prev_hour"].max(),
        "pcs_max": g["unique_pcs_used_that_day"].max(),
        "duration_sum": g["session_duration_minutes"].sum(),
        "after_hours_sum": g["is_after_hours"].sum(),
        "not_own_pc_sum": (1 - d["is_own_pc"]).groupby([d["user"], d["week"]]).sum(),
        "new_pc_sum": g["new_pc"].sum(),
        "unusual_hour_sum": g["unusual_hour"].sum(),
        "iso_top": d[d["r"] < 3].groupby(["user", "week"])["iso_rank"].mean(),
        "ae_top": d[d["r"] < 3].groupby(["user", "week"])["ae_rank"].mean(),
    })
    for f in DEV_FEATURES:
        wk[f"{f}_max"] = g[f].max()
    for i, c in enumerate(ROLE_COLS):
        wk[c] = (wk["mapped_role"] == i).astype(float)
    return wk.reset_index()


WEEK_FEATURES = None  # filled on first use


def week_features(wk):
    global WEEK_FEATURES
    if WEEK_FEATURES is None:
        WEEK_FEATURES = [c for c in wk.columns if c not in ("user", "week", "mapped_role", "y", "score")]
    return wk[WEEK_FEATURES].to_numpy(dtype=float)


# ---------------------------------------------------------------- metrics

def targets(val_wk, test_wk, col):
    """T1-T3 for one role, the limit set on validation normal weeks."""
    vn = val_wk.loc[val_wk["y"] == 0, col]
    limit = float(np.quantile(vn, 0.98)) if len(vn) else float("inf")
    t = test_wk
    out = {"limit": limit, "test_weeks": int(len(t)), "attack_weeks": int(t["y"].sum())}
    normal = t[t["y"] == 0]
    out["T2_normal_weeks_flagged"] = float((normal[col] >= limit).mean()) if len(normal) else None
    ins = t[t["y"] == 1]
    caught = ins.groupby("user")[col].max() >= limit
    out["insiders_in_test"] = int(len(caught))
    out["T1_insiders_caught"] = float(caught.mean()) if len(caught) else None
    out["T3_precision_top10"] = float(t.nlargest(10, col)["y"].mean()) if len(t) >= 10 else None
    if 0 < t["y"].sum() < len(t):
        out["week_roc_auc"] = float(roc_auc_score(t["y"], t[col]))
        out["week_pr_auc"] = float(average_precision_score(t["y"], t[col]))
        out["week_attack_share"] = float(t["y"].mean())
    return out


def session_metrics(frame, col):
    res = {}
    for lab in ("label_period", "label_event"):
        y = frame[lab].to_numpy()
        if 0 < y.sum() < len(y):
            res[lab] = {"roc_auc": float(roc_auc_score(y, frame[col])),
                        "pr_auc": float(average_precision_score(y, frame[col])),
                        "attack_share": float(y.mean())}
    return res


# ---------------------------------------------------------------- experiment

def split(df, rng):
    groups = {k: set() for k in ("unsup", "clf", "val", "test")}
    for role in ROLE_NAMES:
        sub = df[df["mapped_role"] == role]
        ins = np.array(sorted(set(sub.loc[(sub["label_period"] == 1) | (sub["label_event"] == 1), "user"])))
        nor = np.array(sorted(set(sub["user"]) - set(ins)))
        rng.shuffle(ins)
        rng.shuffle(nor)
        n = len(nor)
        a, b, c = int(round(0.4 * n)), int(round(0.6 * n)), int(round(0.8 * n))
        groups["unsup"] |= set(nor[:a])
        groups["clf"] |= set(nor[a:b])
        groups["val"] |= set(nor[b:c])
        groups["test"] |= set(nor[c:])
        k = len(ins)
        i1, i2 = int(round(0.4 * k)), int(round(0.7 * k))
        groups["clf"] |= set(ins[:i1])
        groups["val"] |= set(ins[i1:i2])
        groups["test"] |= set(ins[i2:])
    return groups


def run(seed, df):
    t0 = time.time()
    rng = np.random.default_rng(seed)
    g = split(df, rng)
    part = {k: df[df["user"].isin(v)].copy() for k, v in g.items()}

    # A: the current per-role design.
    for role in ROLE_NAMES:
        tr = part["unsup"][part["unsup"]["mapped_role"] == role]
        m = train_unsup(tr[BASE_FEATURES].to_numpy(dtype=float), seed)
        for k in ("clf", "val", "test"):
            sel = part[k]["mapped_role"] == role
            if sel.any():
                part[k].loc[sel, "A_current"] = minmax_avg(m, part[k].loc[sel, BASE_FEATURES].to_numpy(dtype=float))

    # B: one pooled model with the role and the per-person features.
    feats = USER_FEATURES + ROLE_COLS
    pooled = train_unsup(part["unsup"][feats].to_numpy(dtype=float), seed)
    for k in ("clf", "val", "test"):
        iso_r, ae_r = ranks(pooled, part[k][feats].to_numpy(dtype=float))
        part[k]["iso_rank"], part[k]["ae_rank"] = iso_r, ae_r
        part[k]["B_pooled"] = (iso_r + ae_r) / 2

    # C: session classifier on the B scores + features (trained on 'clf' people).
    cfeats = feats + ["iso_rank", "ae_rank"]
    clf = classifier(seed).fit(part["clf"][cfeats].to_numpy(dtype=float), part["clf"][LABEL].to_numpy())
    for k in ("clf", "val", "test"):
        part[k]["C_stacked"] = clf.predict_proba(part[k][cfeats].to_numpy(dtype=float))[:, 1]

    # Person-weeks; D: week classifier.
    weeks = {}
    for k in ("clf", "val", "test"):
        base = week_table(part[k], "B_pooled")
        for det in ("A_current", "C_stacked"):
            other = week_table(part[k], det)[["user", "week", "score"]].rename(columns={"score": det})
            base = base.merge(other, on=["user", "week"])
        weeks[k] = base.rename(columns={"score": "B_pooled"})
    wclf = classifier(seed).fit(week_features(weeks["clf"]), weeks["clf"]["y"].to_numpy())
    for k in ("val", "test"):
        weeks[k]["D_weekly"] = wclf.predict_proba(week_features(weeks[k]))[:, 1]

    out = {}
    for role, name in ROLE_NAMES.items():
        out[name] = {}
        vw, tw = weeks["val"], weeks["test"]
        vw, tw = vw[vw["mapped_role"] == role], tw[tw["mapped_role"] == role]
        ts = part["test"][part["test"]["mapped_role"] == role]
        for det in DETECTORS:
            r = targets(vw, tw, det)
            if det != "D_weekly":
                r["session"] = session_metrics(ts, det)
            out[name][det] = r
        line = "  ".join(
            f"{det[0]}: T1={out[name][det]['T1_insiders_caught'] if out[name][det]['T1_insiders_caught'] is not None else float('nan'):.0%}"
            f" T2={out[name][det]['T2_normal_weeks_flagged']:.1%}"
            f" T3={out[name][det]['T3_precision_top10'] if out[name][det]['T3_precision_top10'] is not None else float('nan'):.0%}"
            for det in DETECTORS)
        print(f"  [{seed}] {name:15s} insiders={out[name]['A_current']['insiders_in_test']}  {line}", flush=True)
    out["unseen_attack_type"] = unseen_scenario_check(part, seed)
    out["people"] = {k: len(v) for k, v in g.items()}
    out["seconds"] = round(time.time() - t0, 1)
    return out


def unseen_scenario_check(part, seed):
    """Strict check: retrain classifier C without any insider of attack
    scenario s, then ask how many TEST insiders of scenario s it catches
    (limit from validation normal weeks, all roles together). This shows
    whether C finds new people doing a KNOWN kind of attack only, or also
    a kind of attack it was never shown."""
    feats = USER_FEATURES + ROLE_COLS + ["iso_rank", "ae_rank"]
    res = {}
    for s in sorted(part["test"]["scenario"].dropna().unique()):
        keep = part["clf"]["scenario"].ne(s) | part["clf"]["scenario"].isna()
        tr = part["clf"][keep]
        clf = classifier(seed).fit(tr[feats].to_numpy(dtype=float), tr[LABEL].to_numpy())
        r = {}
        for det in ("C_without_type", "B_pooled"):
            wk = {}
            for k in ("val", "test"):
                f = part[k].copy()
                if det == "C_without_type":
                    f[det] = clf.predict_proba(f[feats].to_numpy(dtype=float))[:, 1]
                wk[k] = week_table(f, det).rename(columns={"score": det})
            vn = wk["val"].loc[wk["val"]["y"] == 0, det]
            limit = float(np.quantile(vn, 0.98))
            t = wk["test"]
            users_s = set(part["test"].loc[part["test"]["scenario"] == s, "user"])
            ins = t[(t["y"] == 1) & t["user"].isin(users_s)]
            caught = ins.groupby("user")[det].max() >= limit
            r[det] = {"insiders": int(len(caught)), "caught": float(caught.mean()) if len(caught) else None,
                      "normal_weeks_flagged": float((t.loc[t["y"] == 0, det] >= limit).mean())}
        res[str(int(s))] = r
        print(f"        unseen attack type {int(s)}: C without it caught "
              f"{r['C_without_type']['caught'] if r['C_without_type']['caught'] is not None else float('nan'):.0%}"
              f" of {r['C_without_type']['insiders']}  (B, no labels: "
              f"{r['B_pooled']['caught'] if r['B_pooled']['caught'] is not None else float('nan'):.0%})", flush=True)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="42")
    seeds = [int(s) for s in ap.parse_args().seeds.split(",")]
    df = pd.read_csv(DATA, parse_dates=["session_start", "session_end"])
    for i, c in enumerate(ROLE_COLS):
        df[c] = (df["mapped_role"] == i).astype(float)
    ins = pd.read_csv(BASE / "data" / "insiders.csv", dtype=str)
    df["scenario"] = df["user"].map(ins[ins["dataset"] == "4.2"].set_index("user")["scenario"]).astype(float)
    print(f"sessions: {len(df)}; seeds: {seeds}", flush=True)
    runs = {str(s): run(s, df) for s in seeds}

    summary = {}
    print("\n=== Mean over seeds (test people) ===", flush=True)
    for name in ROLE_NAMES.values():
        summary[name] = {}
        print(f"\n{name}", flush=True)
        for det in DETECTORS:
            agg = {}
            for key in ("T1_insiders_caught", "T2_normal_weeks_flagged", "T3_precision_top10",
                        "week_roc_auc", "week_pr_auc", "week_attack_share", "insiders_in_test"):
                vals = [runs[s][name][det].get(key) for s in runs]
                vals = [v for v in vals if v is not None]
                if vals:
                    agg[key] = {"mean": float(np.mean(vals)), "min": float(np.min(vals)),
                                "max": float(np.max(vals)), "n_runs": len(vals)}
            for lab in ("label_period", "label_event"):
                for key in ("roc_auc", "pr_auc"):
                    vals = [runs[s][name][det].get("session", {}).get(lab, {}).get(key) for s in runs]
                    vals = [v for v in vals if v is not None]
                    if vals:
                        agg[f"session_{lab}_{key}"] = {"mean": float(np.mean(vals)), "n_runs": len(vals)}
            summary[name][det] = agg
            m = lambda k, fmt: (fmt.format(agg[k]["mean"]) if k in agg else "  n/a")
            print(f"  {det:10s} T1 caught={m('T1_insiders_caught', '{:.0%}')}"
                  f"  T2 false weeks={m('T2_normal_weeks_flagged', '{:.1%}')}"
                  f"  T3 top10={m('T3_precision_top10', '{:.0%}')}"
                  f"  week ROC={m('week_roc_auc', '{:.3f}')} PR={m('week_pr_auc', '{:.3f}')}"
                  f" (attack weeks {m('week_attack_share', '{:.1%}')})"
                  f"  session ROC={m('session_label_period_roc_auc', '{:.3f}')}"
                  f" PR={m('session_label_period_pr_auc', '{:.4f}')}"
                  f"  event-label PR={m('session_label_event_pr_auc', '{:.4f}')}", flush=True)
    OUT.write_text(json.dumps({"_about": __doc__.strip().splitlines()[0], "seeds": seeds,
                               "summary": summary, "runs": runs}, indent=2, default=float))
    print(f"\nSaved {OUT}", flush=True)


if __name__ == "__main__":
    main()
