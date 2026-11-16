"""Train, evaluate and save layer 2, the weekly review (ml/service/weekly.py).

The evaluation uses the SAME code that runs on the website, so the numbers
in the report are the numbers of the deployed model design.

Evaluation (5 random groupings of people, seeds 42, 1, 2, 3, 4), separately
inside each role:
  normal people   40% anomaly-model training | 20% weekly-classifier
                  training | 20% calibration (sets the limits) | 20% test
  insiders        40% weekly-classifier training | 30% calibration | 30% test
No person is in two groups; the anomaly models never see an insider; the
test people play no part in any choice. Compared with "today" -- the
deployed per-role layer-1 design (7 features, min-max average) -- turned
into a weekly score the same way (mean of the week's three highest
sessions), its limit set the same way (98th percentile of calibration
normal weeks).

Success targets, per role, on the test people:
  T1  share of insiders flagged in at least one attack week   (goal >= 80%)
  T2  share of normal person-weeks flagged                     (goal <= 2%)
  T3  share of real attack weeks among the role's 10 highest   (goal >= 33%)

Then the final model is trained on all people (normal people 40% anomaly
models / 35% classifier / 25% calibration; every insider to the
classifier) and saved to ml/models/weekly/ for the scoring service.

Run from the repo root (needs data/processed/sessions_improved.csv, built
by 13_improved_evaluation.py):
  .venv\\Scripts\\python.exe ml\\scripts\\16_train_weekly.py
  --skip-eval to only train the final model.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score
from sklearn.preprocessing import StandardScaler

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "service"))
import weekly as W  # noqa: E402

DATA = BASE / "data" / "processed" / "sessions_improved.csv"
OUTDIR = BASE / "models" / "weekly"
CHARTS = BASE / "models" / "charts"
ROLE_OF = {0: "Caregiver", 1: "SecurityAuditor", 2: "SysAdmin"}
LABEL_OF = {"Caregiver": "Caregiver", "SecurityAuditor": "Security Auditor", "SysAdmin": "System Administrator"}
RECALL_GRID = np.linspace(0, 1, 101)


def load():
    d = pd.read_csv(DATA, parse_dates=["session_start"])
    s = pd.DataFrame({"user": d["user"], "role": d["mapped_role"].map(ROLE_OF), "start": d["session_start"],
                      "pc": d["pc"], "y": d["label_period"].astype(int), "y_event": d["label_event"].astype(int)})
    for f in W.BASE_FEATURES:
        s[f] = d[f].astype(float)
    t0 = time.time()
    s = W.add_person_features(s)
    print(f"sessions: {len(s)}, person features in {time.time() - t0:.0f}s", flush=True)
    return s


def insiders_of(s):
    return set(s.loc[(s["y"] == 1) | (s["y_event"] == 1), "user"])


def split(s, rng, normal_parts, insider_parts):
    groups = {k: set() for k in normal_parts}
    ins_all = insiders_of(s)
    for r in W.ROLES:
        users = set(s.loc[s["role"] == r, "user"])
        ins = np.array(sorted(users & ins_all))
        nor = np.array(sorted(users - ins_all))
        rng.shuffle(ins)
        rng.shuffle(nor)
        for parts, arr in ((normal_parts, nor), (insider_parts, ins)):
            edges = np.round(np.cumsum([0] + list(parts.values())) * len(arr)).astype(int)
            for (k, _), a, b in zip(parts.items(), edges[:-1], edges[1:]):
                groups[k] |= set(arr[a:b])
    return groups


# ------------------------------------------------------------ today's design

def train_today(s_unsup, seed):
    """Layer 1 as deployed: per role, Isolation Forest + Autoencoder on the
    7 features, min-max scaled, averaged."""
    import tensorflow as tf
    from tensorflow import keras
    models = {}
    for r in W.ROLES:
        x = s_unsup.loc[s_unsup["role"] == r, W.BASE_FEATURES].to_numpy(dtype=float)
        tf.keras.utils.set_random_seed(seed)
        sc = StandardScaler().fit(x)
        xs = sc.transform(x)
        iso = IsolationForest(n_estimators=200, contamination="auto", random_state=seed, n_jobs=-1).fit(xs)
        ae = keras.Sequential([keras.layers.Input(shape=(7,)), keras.layers.Dense(12, activation="relu"),
                               keras.layers.Dense(6, activation="relu"), keras.layers.Dense(12, activation="relu"),
                               keras.layers.Dense(7, activation="linear")])
        ae.compile(optimizer="adam", loss="mse")
        es = keras.callbacks.EarlyStopping(monitor="val_loss", patience=4, restore_best_weights=True)
        ae.fit(xs, xs, epochs=40, batch_size=256, validation_split=0.1, verbose=0, callbacks=[es])
        ir = -iso.score_samples(xs)
        ar = np.mean((xs - ae.predict(xs, verbose=0, batch_size=8192)) ** 2, axis=1)
        models[r] = (sc, iso, ae, ir.min(), ir.max(), ar.min(), ar.max())
    return models


def today_session_scores(models, s):
    out = np.zeros(len(s))
    for r, (sc, iso, ae, il, ih, al, ah) in models.items():
        sel = (s["role"] == r).to_numpy()
        if not sel.any():
            continue
        xs = sc.transform(s.loc[sel, W.BASE_FEATURES].to_numpy(dtype=float))
        i = np.clip((-iso.score_samples(xs) - il) / max(ih - il, 1e-9), 0, 1)
        a = np.clip((np.mean((xs - ae.predict(xs, verbose=0, batch_size=8192)) ** 2, axis=1) - al) / max(ah - al, 1e-9), 0, 1)
        out[sel] = (i + a) / 2
    return out


def today_weeks(s, scores):
    d = s.assign(week=W.week_of(s["start"]), sc=scores).sort_values("sc", ascending=False)
    d["k"] = d.groupby(["user", "week"]).cumcount()
    g = d.groupby(["user", "week"])
    wk = pd.DataFrame({"role": g["role"].first(), "y": g["y"].max(),
                       "score": d[d["k"] < 3].groupby(["user", "week"])["sc"].mean()})
    return wk.reset_index()


# ------------------------------------------------------------ measuring

def targets(calib, test, r, fixed_limit=None, rank_col="score", rule_col=None):
    """T1-T3 for one role. A person-week is flagged when its score is above
    the limit (or, with rule_col, when an always-review rule fires). The
    weekly list is ordered by rank_col among flagged weeks first."""
    cn = calib[(calib["role"] == r) & (calib["y"] == 0)]["score"]
    limit = fixed_limit if fixed_limit is not None else float(np.quantile(cn, 0.98))
    t = test[test["role"] == r].copy()
    t["flag"] = t["score"] > limit
    if rule_col:
        t["flag"] |= t[rule_col].astype(bool)
    caught = t[t["y"] == 1].groupby("user")["flag"].max()
    order = t.sort_values(["flag", rank_col], ascending=False)
    out = {"limit": limit, "insiders": int(len(caught)),
           "T1_insiders_caught": float(caught.mean()) if len(caught) else None,
           "T2_normal_weeks_flagged": float(t.loc[t["y"] == 0, "flag"].mean()),
           "T3_precision_top10": float(order["y"].head(10).mean()) if t["y"].sum() else None,
           "precision_at_limit": float(t.loc[t["flag"], "y"].mean()) if t["flag"].any() else None}
    if 0 < t["y"].sum() < len(t):
        out["week_roc_auc"] = float(roc_auc_score(t["y"], t["score"]))
        out["week_pr_auc"] = float(average_precision_score(t["y"], t["score"]))
        out["attack_share"] = float(t["y"].mean())
        p, rc, _ = precision_recall_curve(t["y"], t["score"])
        out["pr_curve"] = [float(np.max(p[rc >= g])) if (rc >= g).any() else 0.0 for g in RECALL_GRID]
    return out


def evaluate(s, seeds):
    runs = {}
    normal_parts = {"unsup": 0.4, "clf": 0.2, "calib": 0.2, "test": 0.2}
    insider_parts = {"unsup": 0.0, "clf": 0.4, "calib": 0.3, "test": 0.3}
    for seed in seeds:
        t0 = time.time()
        g = split(s, np.random.default_rng(seed), normal_parts, insider_parts)
        part = {k: s[s["user"].isin(v)] for k, v in g.items()}
        unsup = part["unsup"][part["unsup"]["y"] == 0]

        m = W.Layer2()
        m.fit_unsup(unsup, seed)
        wk = {k: m.weeks(part[k]) for k in ("clf", "calib", "test")}
        m.fit_weekly(wk["clf"], seed)
        m.calibrate(wk["calib"])
        for k in ("calib", "test"):
            wk[k]["score"], wk[k]["learned"], _ = m.review_index(wk[k])
            # Always-review rule for the powerful roles (backend weeklyReview.js):
            # any work at night or from a device the person had not used before.
            wk[k]["rule"] = (wk[k]["role"].isin(["SysAdmin", "SecurityAuditor"])
                             & ((wk[k]["is_after_hours_max"] > 0) | (wk[k]["is_own_pc_mean"] < 1)))
        today = train_today(unsup, seed)
        tw = {k: today_weeks(part[k], today_session_scores(today, part[k])) for k in ("calib", "test")}

        today_limits = {r: float(np.quantile(tw["calib"].loc[(tw["calib"]["role"] == r) & (tw["calib"]["y"] == 0), "score"], 0.98))
                        for r in W.ROLES}
        synth = synthetic_check(m, today, part["test"], wk["test"], today_limits, seed)
        runs[str(seed)] = {r: {"today": targets(tw["calib"], tw["test"], r),
                               "layer2": targets(wk["calib"], wk["test"], r, fixed_limit=1.0, rank_col="learned"),
                               "layer2_rules": targets(wk["calib"], wk["test"], r, fixed_limit=1.0, rank_col="learned",
                                                       rule_col="rule"),
                               "synthetic": synth.get(r)} for r in W.ROLES}
        for r in W.ROLES:
            a, b = runs[str(seed)][r]["today"], runs[str(seed)][r]["layer2"]
            f = lambda v: "n/a" if v is None else f"{v:.0%}"
            print(f"  [{seed}] {r:15s} insiders={b['insiders']:2d}  today T1={f(a['T1_insiders_caught'])} "
                  f"T2={a['T2_normal_weeks_flagged']:.1%} T3={f(a['T3_precision_top10'])}  ->  layer 2 "
                  f"T1={f(b['T1_insiders_caught'])} T2={b['T2_normal_weeks_flagged']:.1%} "
                  f"T3={f(b['T3_precision_top10'])}", flush=True)
        for r in W.ROLES:
            sy = runs[str(seed)][r]["synthetic"]
            if sy:
                print(f"  [{seed}] {r:15s} synthetic (model / +rules / today): " + "  ".join(
                    f"{k}={v['model']:.0%}/{v['with_rules']:.0%}/{v['today']:.0%}" for k, v in sy.items()), flush=True)
        print(f"  [{seed}] {time.time() - t0:.0f}s", flush=True)
    return runs



# ------------------------------------------------------------ synthetic misuse
# CERT has one Security Auditor insider and about a dozen administrator
# insiders: too few to measure those roles. So, as a clearly labelled
# SYNTHETIC check, misuse is injected into one real week of a test person
# the models never saw, and we ask whether the weekly review lists it. The
# same person's unchanged week is the comparison. Same for all three roles.
def _more(x, k):
    return x * k + (k - 1)          # also raises zero counts

SYNTHETIC = {
    "burst": "two days with about 4x the usual actions",
    "slow_scraping": "every day of the week at about 2x the usual activity",
    "night": "two sessions at 23:00",
    "new_device": "two days on a computer never used before",
}


def _inject(sess, week, kind, rng):
    s = sess.copy()
    in_week = (W.week_of(s["start"]) == week).to_numpy()
    idx = np.flatnonzero(in_week)
    pick = rng.choice(idx, size=min(2, len(idx)), replace=False)
    if kind == "burst":
        for f, k in (("files_accessed_per_session", 4), ("events_prev_hour", 4), ("events_prev_day", 3),
                     ("session_duration_minutes", 2)):
            s.loc[s.index[pick], f] = _more(s.loc[s.index[pick], f], k)
    elif kind == "slow_scraping":
        for f, k in (("files_accessed_per_session", 2), ("events_prev_hour", 2), ("events_prev_day", 2),
                     ("session_duration_minutes", 1.5)):
            s.loc[s.index[idx], f] = _more(s.loc[s.index[idx], f], k)
    elif kind == "night":
        s.loc[s.index[pick], "start"] = s.loc[s.index[pick], "start"].dt.normalize() + pd.Timedelta(hours=23)
        s.loc[s.index[pick], "is_after_hours"] = 1
    elif kind == "new_device":
        s.loc[s.index[pick], "pc"] = "synthetic-unseen-pc"
        s.loc[s.index[pick], "is_own_pc"] = 0
        s.loc[s.index[pick], "unique_pcs_used_that_day"] = 2
    return s


def synthetic_check(m, today, test_raw, wk_test, today_limits, seed, per_role=25):
    rng = np.random.default_rng(seed + 1000)
    out = {}
    raw_cols = ["user", "role", "start", "pc", "y"] + W.BASE_FEATURES
    for r in W.ROLES:
        cand = wk_test[(wk_test["role"] == r) & (wk_test["y"] == 0) & (wk_test["n_sessions"] >= 3)]
        cand = cand[~cand["user"].isin(set(wk_test.loc[wk_test["y"] == 1, "user"]))]
        if cand.empty:
            continue
        rows = cand.sample(min(per_role, len(cand)), random_state=int(rng.integers(1 << 31)))
        res = {k: {"model": 0, "with_rules": 0, "today": 0} for k in ["unchanged", *SYNTHETIC]}
        for _, row in rows.iterrows():
            sess = test_raw.loc[test_raw["user"] == row["user"], raw_cols].sort_values("start").reset_index(drop=True)
            for kind in res:
                x = sess if kind == "unchanged" else _inject(sess, row["week"], kind, rng)
                P = W.add_person_features(x)
                wk = m.weeks(P)
                wk = wk[wk["week"] == row["week"]].reset_index(drop=True)
                index = m.review_index(wk)[0][0]
                rule = r in ("SysAdmin", "SecurityAuditor") and (wk["is_after_hours_max"].iloc[0] > 0 or wk["is_own_pc_mean"].iloc[0] < 1)
                tw = today_weeks(P, today_session_scores(today, P))
                tsc = tw.loc[tw["week"] == row["week"], "score"].iloc[0]
                res[kind]["model"] += int(index > 1.0)
                res[kind]["with_rules"] += int(index > 1.0 or rule)
                res[kind]["today"] += int(tsc > today_limits[r])
        n = len(rows)
        out[r] = {k: {d: v / n for d, v in res[k].items()} | {"n": n} for k in res}
    return out


def summarise(runs):
    keys = ["T1_insiders_caught", "T2_normal_weeks_flagged", "T3_precision_top10", "precision_at_limit",
            "week_roc_auc", "week_pr_auc", "attack_share", "insiders"]
    summary = {}
    for r in W.ROLES:
        summary[r] = {}
        for det in ("today", "layer2", "layer2_rules"):
            agg = {}
            for k in keys:
                v = [runs[s][r][det].get(k) for s in runs]
                v = [x for x in v if x is not None]
                if v:
                    agg[k] = {"mean": float(np.mean(v)), "min": float(np.min(v)), "max": float(np.max(v)), "n": len(v)}
            curves = [runs[s][r][det]["pr_curve"] for s in runs if "pr_curve" in runs[s][r][det]]
            if curves:
                c = np.array(curves)
                agg["pr_curve"] = {"recall": RECALL_GRID.tolist(), "mean": c.mean(0).tolist(),
                                   "min": c.min(0).tolist(), "max": c.max(0).tolist(), "n": len(curves)}
            summary[r][det] = agg
        syn = [runs[s][r]["synthetic"] for s in runs if runs[s][r].get("synthetic")]
        if syn:
            summary[r]["synthetic"] = {k: {d: float(np.mean([x[k][d] for x in syn])) for d in ("model", "with_rules", "today")}
                                       | {"people_weeks": int(sum(x[k]["n"] for x in syn))} for k in syn[0]}
    return summary


# ------------------------------------------------------------ charts

def charts(summary):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    CHARTS.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.family": "serif", "font.size": 10})
    files = []
    for r in W.ROLES:
        fig, ax = plt.subplots(figsize=(5.2, 3.8))
        for det, colour, name in (("today", "#9a3412", "Today (layer 1 per week)"),
                                  ("layer2", "#1f4e79", "Layer 2 weekly review")):
            c = summary[r][det].get("pr_curve")
            if not c:
                continue
            ax.plot(c["recall"], c["mean"], color=colour, lw=2,
                    label=f"{name}  (PR-AUC {summary[r][det]['week_pr_auc']['mean']:.3f})")
            ax.fill_between(c["recall"], c["min"], c["max"], color=colour, alpha=0.15, lw=0)
        share = summary[r]["layer2"].get("attack_share", {}).get("mean")
        if share:
            ax.axhline(share, color="grey", ls=":", lw=1, label=f"Random guess ({share:.1%})")
        ax.set_xlabel("Recall (share of attack weeks found)")
        ax.set_ylabel("Precision (share of flags that are real)")
        n = summary[r]["layer2"].get("pr_curve", {}).get("n", 0)
        ax.set_title(f"{LABEL_OF[r]}: person-weeks of unseen people\n(mean of {n} splits, band = lowest to highest)",
                     fontsize=10)
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1.02)
        ax.grid(alpha=0.3)
        ax.legend(fontsize=8, loc="upper right")
        fig.tight_layout()
        path = CHARTS / f"weekly_pr_{r}.png"
        fig.savefig(path, dpi=200)
        plt.close(fig)
        files.append(path.name)

    fig, axes = plt.subplots(1, 3, figsize=(10, 3.6))
    for ax, (k, title, goal, better) in zip(axes, (
            ("T1_insiders_caught", "T1 Insiders caught", 0.80, "higher"),
            ("T2_normal_weeks_flagged", "T2 Normal weeks flagged", 0.02, "lower"),
            ("T3_precision_top10", "T3 Real cases in weekly top 10", 0.33, "higher"))):
        x = np.arange(len(W.ROLES))
        for j, (det, colour, name) in enumerate((("today", "#9a3412", "Today"), ("layer2", "#1f4e79", "Layer 2"))):
            vals = [summary[r][det].get(k, {}).get("mean", np.nan) for r in W.ROLES]
            bars = ax.bar(x + (j - 0.5) * 0.38, vals, 0.38, color=colour, label=name)
            for b, v in zip(bars, vals):
                if not np.isnan(v):
                    label = f"{v:.1%}" if k == "T2_normal_weeks_flagged" else f"{v:.0%}"
                    ax.text(b.get_x() + b.get_width() / 2, v + (0.002 if k == "T2_normal_weeks_flagged" else 0.01),
                            label, ha="center", fontsize=7)
        ax.axhline(goal, color="grey", ls="--", lw=1)
        ax.set_xticks(x, ["Caregiver", "Auditor*", "Admin"])
        ax.set_title(f"{title}\n(goal {'>=' if better == 'higher' else '<='} {goal:.0%})", fontsize=9)
        ax.set_ylim(0, 1.05 if k != "T2_normal_weeks_flagged" else max(0.15, ax.get_ylim()[1]))
        ax.grid(axis="y", alpha=0.3)
    axes[0].legend(fontsize=8)
    fig.text(0.01, 0.01, "*Security Auditor: one insider in CERT r4.2, so T1 and T3 rest on one person.", fontsize=7)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    path = CHARTS / "weekly_targets.png"
    fig.savefig(path, dpi=200)
    plt.close(fig)
    files.append(path.name)
    return files


# ------------------------------------------------------------ final model

def train_final(s, seed=42):
    g = split(s, np.random.default_rng(seed),
              {"unsup": 0.40, "clf": 0.35, "calib": 0.25}, {"unsup": 0.0, "clf": 1.0, "calib": 0.0})
    part = {k: s[s["user"].isin(v)] for k, v in g.items()}
    m = W.Layer2()
    m.fit_unsup(part["unsup"][part["unsup"]["y"] == 0], seed)
    m.fit_weekly(m.weeks(part["clf"]), seed)
    m.calibrate(m.weeks(part["calib"]))
    return m, {k: len(v) for k, v in g.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="42,1,2,3,4")
    ap.add_argument("--skip-eval", action="store_true")
    ap.add_argument("--charts-only", action="store_true", help="redraw the charts from models/weekly/evaluation.json")
    ap.add_argument("--out", help="write the model, evaluation and charts to this folder instead (for experiments)")
    args = ap.parse_args()
    if args.out:
        global OUTDIR, CHARTS
        OUTDIR = Path(args.out)
        CHARTS = OUTDIR / "charts"
    if args.charts_only:
        print("charts:", charts(json.loads((OUTDIR / "evaluation.json").read_text())["summary"]))
        return
    s = load()
    meta = {}
    if not args.skip_eval:
        runs = evaluate(s, [int(x) for x in args.seeds.split(",")])
        summary = summarise(runs)
        meta["evaluation"] = {r: {det: ({k: v for k, v in summary[r][det].items() if k != "pr_curve"} if det != "synthetic" else summary[r][det])
                                  for det in summary[r]} for r in summary}
        OUTDIR.mkdir(parents=True, exist_ok=True)
        (OUTDIR / "evaluation.json").write_text(json.dumps({"seeds": args.seeds, "summary": summary, "runs": runs},
                                                           indent=2, default=float))
        print("\n=== Mean over seeds, test people ===", flush=True)
        for r in W.ROLES:
            for det in ("today", "layer2", "layer2_rules"):
                a = summary[r][det]
                f = lambda k, fmt: fmt.format(a[k]["mean"]) if k in a else "n/a"
                print(f"  {r:15s} {det:7s} T1={f('T1_insiders_caught', '{:.0%}'):>4s}  "
                      f"T2={f('T2_normal_weeks_flagged', '{:.1%}'):>5s}  T3={f('T3_precision_top10', '{:.0%}'):>4s}  "
                      f"prec@limit={f('precision_at_limit', '{:.0%}'):>4s}  weekROC={f('week_roc_auc', '{:.3f}')}  "
                      f"weekPR={f('week_pr_auc', '{:.3f}')}", flush=True)
        print("\n=== Synthetic misuse in real weeks of unseen people (share listed: model / with rules / today) ===", flush=True)
        for r in W.ROLES:
            sy = summary[r].get("synthetic")
            if sy:
                print(f"  {r:15s} " + "  ".join(f"{k}={v['model']:.0%}/{v['with_rules']:.0%}/{v['today']:.0%}" for k, v in sy.items())
                      + f"  ({sy['unchanged']['people_weeks']} person-weeks)", flush=True)
        print("charts:", charts(summary), flush=True)
    t0 = time.time()
    m, groups = train_final(s)
    m.save(OUTDIR, {"trained_on": "CERT r4.2, all 1,000 people", "groups": groups,
                    "label": "insiders.csv attack periods", **meta})
    print(f"final model saved to {OUTDIR} in {time.time() - t0:.0f}s; limits: "
          + ", ".join(f"{r}={v:.3f}" for r, v in m.limits.items()), flush=True)


if __name__ == "__main__":
    main()
