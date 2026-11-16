"""Experiment: can the detector be improved without weakening the evaluation?

Same strict method as 12_validated_evaluation.py:
  * people, not sessions, are split 60/20/20 (train/validation/test);
    insiders are never used for training;
  * any choice (limit, model weight) is made on VALIDATION and reported
    once on TEST;
  * five random splits of people (seeds 42, 1, 2, 3, 4).

What changes, one step at a time (variants V0 to V3):
  V0  current      the deployed design: 7 features, each model's score
                   scaled by the training min and max, then averaged.
  V1  rank         same models, but each score is turned into its
                   percentile among the training scores before averaging,
                   so neither model is squashed by an outlier.
  V2  per-user     V1 plus features that compare each session with the
                   same person's own last 30 days (only the past is used,
                   so the live app can compute them too):
                     dev_<feature>   how far the value is from the
                                     person's 30-day mean, in their own
                                     standard deviations
                     new_pc          a computer this person has not used
                                     in the last 30 days
                     unusual_hour    the person was not active within an
                                     hour of this time on 3 or more
                                     earlier days in the last 30
  V3  weighted     V2, with the weight between the two models chosen on
                   the validation set (0.0 to 1.0 in steps of 0.1) by
                   PR-AUC, instead of a fixed 50/50.

Two ways of labelling the attacks are reported side by side:
  period  the current labels: every session that starts inside an
          insider's attack period (insiders.csv), including sessions in
          which the insider behaved normally;
  event   CERT's own answer files (answers.tar.bz2 from the official
          KiltHub page), which list the exact malicious events; a session
          is malicious only if one of those events happened in it.
The labels are used only to measure, never to train.

Nothing in ml/models/ that the website uses is changed. Output:
  ml/models/improved_results.json and the printed summary.

Run from the repo root:
  .venv\\Scripts\\python.exe ml\\scripts\\13_improved_evaluation.py --seeds 42,1,2,3,4
"""
import argparse
import glob
import json
import os
import time
from pathlib import Path

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score, roc_curve
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras

BASE = Path(__file__).resolve().parent.parent
SESSIONS = BASE / "data" / "processed" / "sessions_features.csv"
ANSWERS = BASE / "data" / "answers_dl" / "answers"
CACHE = BASE / "data" / "processed" / "sessions_improved.csv"
OUT = BASE / "models" / "improved_results.json"

BASE_FEATURES = [
    "files_accessed_per_session", "events_prev_day", "events_prev_hour",
    "unique_pcs_used_that_day", "session_duration_minutes", "is_after_hours", "is_own_pc",
]
DEV_FEATURES = [f"dev_{f}" for f in BASE_FEATURES]
USER_FEATURES = BASE_FEATURES + DEV_FEATURES + ["new_pc", "unusual_hour"]
ROLE_NAMES = {0: "Caregiver", 1: "SecurityAuditor", 2: "SysAdmin"}
THRESHOLDS = np.round(np.arange(0.01, 1.00, 0.01), 2)
WINDOW = np.timedelta64(30, "D")
DAY_NS = np.int64(86_400 * 10**9)


# ---------------------------------------------------------------- data

def event_labels(s):
    """1 for a session in which one of CERT's listed malicious events happened."""
    rows = []
    for f in glob.glob(str(ANSWERS / "r4.2-*" / "*.csv")):
        with open(f, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                p = line.split(",", 5)
                rows.append((p[2], p[3], p[4]))
    ev = pd.DataFrame(rows, columns=["date", "user", "pc"])
    ev["date"] = pd.to_datetime(ev["date"], format="%m/%d/%Y %H:%M:%S")
    ss = s[["session_id", "user", "pc", "session_start", "session_end"]].sort_values("session_start")
    m = pd.merge_asof(ev.sort_values("date"), ss, left_on="date", right_on="session_start",
                      by=["user", "pc"], direction="backward")
    cap = m["session_start"] + pd.Timedelta(days=1)
    ok = m["session_id"].notna() & (m["date"] <= m["session_end"].where(m["session_end"] <= cap, cap))
    print(f"malicious events: {len(ev)}, placed in a session: {int(ok.sum())}", flush=True)
    return s["session_id"].isin(set(m.loc[ok, "session_id"].astype(int))).astype(int)


def per_user_features(s):
    """Compare each session with the same person's previous 30 days only."""
    s = s.sort_values(["user", "session_start"]).reset_index(drop=True)
    n = len(s)
    dev = np.zeros((n, len(BASE_FEATURES)))
    unusual = np.zeros(n)
    X_all = s[BASE_FEATURES].to_numpy(dtype=float)
    t_all = s["session_start"].to_numpy().astype("datetime64[ns]")
    for _, idx in s.groupby("user").indices.items():
        X = X_all[idx]
        t = t_all[idx]
        lo = np.searchsorted(t, t - WINDOW, side="left")
        hi = np.arange(len(idx))                      # past only: rows lo..i-1
        cnt = (hi - lo).astype(float)
        cs = np.vstack([np.zeros(X.shape[1]), np.cumsum(X, axis=0)])
        cs2 = np.vstack([np.zeros(X.shape[1]), np.cumsum(X * X, axis=0)])
        with np.errstate(invalid="ignore", divide="ignore"):
            mean = (cs[hi] - cs[lo]) / cnt[:, None]
            var = (cs2[hi] - cs2[lo]) / cnt[:, None] - mean ** 2
        std = np.sqrt(np.clip(var, 0, None))
        d = (X - mean) / (std + 1.0)
        d[cnt < 3] = 0.0                              # too little history: no signal
        dev[idx] = np.nan_to_num(d)

        # unusual_hour: not active within an hour of this time on >= 3
        # earlier days in the last 30 (the website's caregiver rule).
        hour = s["session_start"].to_numpy()[idx].astype("datetime64[m]").astype(np.int64) % (24 * 60)
        day = t.astype(np.int64) // DAY_NS
        for i in range(len(idx)):
            if lo[i] == i:
                unusual[idx[i]] = 1.0
                continue
            dh = np.abs(hour[lo[i]:i] - hour[i])
            near = np.minimum(dh, 24 * 60 - dh) <= 60
            unusual[idx[i]] = float(len(np.unique(day[lo[i]:i][near])) < 3)
    for j, f in enumerate(DEV_FEATURES):
        s[f] = dev[:, j]
    s["unusual_hour"] = unusual
    prev = s.groupby(["user", "pc"])["session_start"].shift(1)
    s["new_pc"] = (prev.isna() | ((s["session_start"] - prev) > pd.Timedelta(days=30))).astype(float)
    return s


def load():
    if CACHE.exists():
        return pd.read_csv(CACHE, parse_dates=["session_start", "session_end"])
    t0 = time.time()
    s = pd.read_csv(SESSIONS, parse_dates=["session_start", "session_end"])
    s["session_duration_minutes"] = s["session_duration_minutes"].clip(lower=0)
    s = s.rename(columns={"label": "label_period"})
    s["label_event"] = event_labels(s)
    s = per_user_features(s)
    keep = ["session_id", "user", "pc", "session_start", "session_end", "mapped_role",
            "label_period", "label_event"] + USER_FEATURES
    s[keep].to_csv(CACHE, index=False)
    print(f"built {CACHE.name} in {time.time() - t0:.0f}s", flush=True)
    return s[keep]


# ---------------------------------------------------------------- models

def train(x, seed):
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
    ae.fit(xs, xs, epochs=40, batch_size=256, validation_split=0.1, shuffle=True, verbose=0, callbacks=[es])
    m = {"scaler": scaler, "iso": iso, "ae": ae}
    raw = raw_scores(m, x)
    m["train_iso"] = np.sort(raw["iso"])
    m["train_ae"] = np.sort(raw["ae"])
    return m


def raw_scores(m, x):
    xs = m["scaler"].transform(x)
    return {"iso": -m["iso"].score_samples(xs),
            "ae": np.mean((xs - m["ae"].predict(xs, verbose=0, batch_size=8192)) ** 2, axis=1)}


def minmax(v, ref):
    return np.clip((v - ref[0]) / max(ref[-1] - ref[0], 1e-9), 0, 1)


def rank(v, ref):
    return np.searchsorted(ref, v, side="right") / len(ref)


def scores(m, x, how, w=0.5):
    r = raw_scores(m, x)
    f = minmax if how == "minmax" else rank
    return w * f(r["iso"], m["train_iso"]) + (1 - w) * f(r["ae"], m["train_ae"])


# ---------------------------------------------------------------- metrics

def threshold_free(y, s):
    y = np.asarray(y)
    if not 0 < y.sum() < len(y):
        return None
    fpr, tpr, _ = roc_curve(y, s)
    k = max(1, int(round(0.01 * len(y))))
    top = np.argsort(-s)[:k]
    return {"roc_auc": float(roc_auc_score(y, s)),
            "pr_auc": float(average_precision_score(y, s)),
            "recall_at_1pct_fpr": float(tpr[np.searchsorted(fpr, 0.01, side="right") - 1]),
            "precision_top_1pct": float(y[top].mean()),
            "attack_share": float(y.mean()), "attacks": int(y.sum())}


def weekly(frame, lab, s):
    """The auditor's question: which person should I look at this week?
    One row per person per calendar week. Its score is the mean of the
    person's three highest session scores that week (so one odd session
    is not enough); it is an attack week if any session in it is."""
    d = pd.DataFrame({"user": frame["user"].to_numpy(),
                      "week": frame["session_start"].dt.to_period("W").astype(str).to_numpy(),
                      "y": frame[lab].to_numpy(), "s": s})
    d = d.sort_values("s", ascending=False)
    d["r"] = d.groupby(["user", "week"]).cumcount()
    wk = pd.DataFrame({"y": d.groupby(["user", "week"])["y"].max(),
                       "s": d[d["r"] < 3].groupby(["user", "week"])["s"].mean()})
    r = threshold_free(wk["y"].to_numpy(), wk["s"].to_numpy())
    if r:
        top = wk.sort_values("s", ascending=False)
        for k in (10, 25, 50):
            r[f"precision_top_{k}"] = float(top["y"].head(k).mean())
        r["weeks"] = int(len(wk))
    return r


def best_limit(y, s):
    best = (-1.0, 0.5)
    for t in THRESHOLDS:
        f1 = f1_score(y, (s >= t).astype(int), zero_division=0)
        if f1 > best[0]:
            best = (f1, float(t))
    return best[1]


def at_limit(y, s, limit):
    pred = (s >= limit).astype(int)
    return {"limit": limit, "precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred, zero_division=0)),
            "f1": float(f1_score(y, pred, zero_division=0)),
            "false_alarm_rate": float(((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1))}


# ---------------------------------------------------------------- experiment

def split_people(normal, insider, rng):
    normal, insider = np.array(sorted(normal)), np.array(sorted(insider))
    rng.shuffle(normal)
    rng.shuffle(insider)
    a, b = int(round(0.6 * len(normal))), int(round(0.8 * len(normal)))
    h = len(insider) // 2
    return {"train": set(normal[:a]), "val": set(normal[a:b]) | set(insider[:h]),
            "test": set(normal[b:]) | set(insider[h:])}


def run(seed, df, label):
    rng = np.random.default_rng(seed)
    out = {}
    for role, name in ROLE_NAMES.items():
        t0 = time.time()
        sub = df[df["mapped_role"] == role]
        # Anyone who is an insider under EITHER labelling is kept out of
        # training, so both label sets use the same people and models.
        insiders = set(sub.loc[(sub["label_period"] == 1) | (sub["label_event"] == 1), "user"])
        people = split_people(set(sub["user"]) - insiders, insiders, rng)
        part = {k: sub[sub["user"].isin(v)] for k, v in people.items()}
        tr = part["train"]
        m7 = train(tr[BASE_FEATURES].to_numpy(dtype=float), seed)
        mu = train(tr[USER_FEATURES].to_numpy(dtype=float), seed)

        res = {}
        for lab in label:
            yv, yt = part["val"][lab].to_numpy(), part["test"][lab].to_numpy()
            xv7, xt7 = part["val"][BASE_FEATURES].to_numpy(dtype=float), part["test"][BASE_FEATURES].to_numpy(dtype=float)
            xvu, xtu = part["val"][USER_FEATURES].to_numpy(dtype=float), part["test"][USER_FEATURES].to_numpy(dtype=float)
            # V3: weight chosen on validation by PR-AUC.
            w_best, ap_best = 0.5, -1
            if 0 < yv.sum() < len(yv):
                for w in np.round(np.arange(0, 1.01, 0.1), 1):
                    ap = average_precision_score(yv, scores(mu, xvu, "rank", w))
                    if ap > ap_best:
                        w_best, ap_best = float(w), ap
            variants = {
                "V0_current": (m7, xv7, xt7, "minmax", 0.5),
                "V1_rank": (m7, xv7, xt7, "rank", 0.5),
                "V2_per_user": (mu, xvu, xtu, "rank", 0.5),
                "V3_weighted": (mu, xvu, xtu, "rank", w_best),
            }
            res[lab] = {"forest_weight_V3": w_best}
            for v, (m, xv, xt, how, w) in variants.items():
                sv, st = scores(m, xv, how, w), scores(m, xt, how, w)
                r = {"test": threshold_free(yt, st)}
                if yv.sum() > 0 and yt.sum() > 0:
                    r["at_validated_limit"] = at_limit(yt, st, best_limit(yv, sv))
                r["weekly_watchlist"] = weekly(part["test"], lab, st)
                res[lab][v] = r
        res["seconds"] = round(time.time() - t0, 1)
        out[name] = res
        for lab in label:
            line = "  ".join(f"{v[:2]}={res[lab][v]['test']['pr_auc']:.3f}"
                             for v in ("V0_current", "V1_rank", "V2_per_user", "V3_weighted") if res[lab][v]["test"])
            print(f"  [{seed}] {name:15s} {lab:13s} PR-AUC  {line or 'no test attacks'}", flush=True)
    return out


def summarise(runs, labels):
    summary = {}
    for name in ROLE_NAMES.values():
        summary[name] = {}
        for lab in labels:
            summary[name][lab] = {}
            for v in ("V0_current", "V1_rank", "V2_per_user", "V3_weighted"):
                agg = {}
                for block in ("test", "at_validated_limit", "weekly_watchlist"):
                    vals = [runs[s][name][lab][v].get(block) for s in runs]
                    vals = [x for x in vals if x]
                    if vals:
                        agg[block] = {k: {"mean": float(np.mean([x[k] for x in vals])),
                                          "min": float(np.min([x[k] for x in vals])),
                                          "max": float(np.max([x[k] for x in vals])),
                                          "n_runs": len(vals)} for k in vals[0]}
                summary[name][lab][v] = agg
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="42")
    seeds = [int(s) for s in ap.parse_args().seeds.split(",")]
    df = load()
    labels = ["label_period", "label_event"]
    print(f"sessions: {len(df)}; seeds: {seeds}", flush=True)
    print(pd.crosstab(df["mapped_role"], [df["label_period"], df["label_event"]]), flush=True)
    runs = {str(s): run(s, df, labels) for s in seeds}
    summary = summarise(runs, labels)

    print("\n=== Mean over seeds (test set, people never seen) ===", flush=True)
    for name in ROLE_NAMES.values():
        for lab in labels:
            print(f"\n{name} / {lab}", flush=True)
            for v, agg in summary[name][lab].items():
                t = agg.get("test")
                if not t:
                    continue
                msg = (f"  {v:12s} ROC-AUC={t['roc_auc']['mean']:.3f}  PR-AUC={t['pr_auc']['mean']:.4f}"
                       f"  recall@1%FPR={t['recall_at_1pct_fpr']['mean']:.3f}  prec@top1%={t['precision_top_1pct']['mean']:.3f}")
                a = agg.get("at_validated_limit")
                if a:
                    msg += f"  | validated limit: P={a['precision']['mean']:.3f} R={a['recall']['mean']:.3f} F1={a['f1']['mean']:.3f}"
                print(msg, flush=True)
                wk = agg.get("weekly_watchlist")
                if wk:
                    print(f"  {'':12s} weekly: ROC-AUC={wk['roc_auc']['mean']:.3f}  PR-AUC={wk['pr_auc']['mean']:.3f}"
                          f"  (attack weeks {wk['attack_share']['mean']:.3%})  prec@top10={wk['precision_top_10']['mean']:.2f}"
                          f"  @top25={wk['precision_top_25']['mean']:.2f}  @top50={wk['precision_top_50']['mean']:.2f}", flush=True)
    OUT.write_text(json.dumps({"_about": __doc__.strip().splitlines()[0], "seeds": seeds,
                               "summary": summary, "runs": runs}, indent=2, default=float))
    print(f"\nSaved {OUT}", flush=True)


if __name__ == "__main__":
    main()
