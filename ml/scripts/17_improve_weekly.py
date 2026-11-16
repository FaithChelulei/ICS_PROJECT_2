"""Experiment: can the weekly review (layer 2) be made more precise, and can
the privileged roles (Security Auditor, System Administrator) be measured
and listed better?

Uses EXACTLY the same people splits, model and targets as
16_train_weekly.py (seeds 42, 1, 2, 3, 4), so every number here is directly
comparable with the deployed model's report. Nothing the website uses is
changed. Output: models/weekly_improvement_results.json

Why: on CERT r4.2
  * "Security Auditor" is the Security department -- 20 people, mostly
    security guards, with ONE insider. Its line (98th/99th percentile of 20
    people's normal weeks) and its test both rest on very little.
  * The always-review rule for privileged staff (any night work or any new
    device) lists EVERY normal administrator week in CERT (T2 = 100%):
    CERT administrators routinely work late on many computers.

Variants (all on the same trained model per seed):
  base           the deployed design: listed when the review index > 1.0;
                 the list is ordered by the learned score
  base_rank_idx  same, ordered by the review index instead
  q995           stricter lines: 99.5th percentile instead of 99th
  rule_any       base + the deployed always-review rule for privileged
                 staff (any after-hours session or any non-own computer)
  rule_person    base + a PERSON-SPECIFIC rule for privileged staff: a
                 computer THIS person has not used in 30 days, or an
                 after-hours session at an hour THIS person does not
                 normally work
  priv_pooled    the Security Auditor and System Administrator lines are
                 set together from both roles' normal calibration weeks
  priv_pooled_rule_person   both of the above
  priv_pooled_rule_night    pooled lines + only the night part of the
                 person-specific rule (CERT administrators use new
                 computers almost every week, so the device part fires
                 constantly there)

Reported per role and for "Privileged" (Security Auditor + System
Administrator together, 13 insiders in CERT instead of 1 and 12).

Run from the repo root:
  .venv\\Scripts\\python.exe ml\\scripts\\17_improve_weekly.py --seeds 42,1,2,3,4
"""
import argparse
import importlib.util
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("t16", BASE / "scripts" / "16_train_weekly.py")
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
W = T.W
PRIV = ["SecurityAuditor", "SysAdmin"]
OUT = BASE / "models" / "weekly_improvement_results.json"


def session_week_flags(s):
    """Per person-week, from the sessions themselves (past-only features):
    new_pc_any      a computer this person has not used in the last 30 days
    night_unusual   an after-hours session at an hour this person does not
                    normally work (unusual_hour is computed from their own
                    previous 30 days)."""
    d = s.assign(week=W.week_of(s["start"]),
                 night_unusual=((s["is_after_hours"] > 0) & (s["unusual_hour"] > 0)).astype(int),
                 # only once the person has some history: a first-ever sign-in is not "new"
                 new_pc_seen=((s["new_pc"] > 0) & (s["history_sessions"] >= W.MIN_HISTORY)).astype(int))
    g = d.groupby(["user", "week"])
    return pd.DataFrame({"new_pc_any": g["new_pc_seen"].max(), "night_unusual": g["night_unusual"].max()}).reset_index()


def metrics(t, flag_col, rank_col):
    """T1-T3 and precision, on test weeks t (already for one role/group)."""
    caught = t[t["y"] == 1].groupby("user")[flag_col].max()
    order = t.sort_values([flag_col, rank_col], ascending=False)
    flagged = t[t[flag_col]]
    return {"insiders": int(len(caught)),
            "T1": float(caught.mean()) if len(caught) else None,
            "T2": float(t.loc[t["y"] == 0, flag_col].mean()),
            "T3": float(order["y"].head(10).mean()) if t["y"].sum() else None,
            "precision_at_line": float(flagged["y"].mean()) if len(flagged) else None,
            "flagged_per_100_people_weeks": float(100 * t[flag_col].mean())}


def run_seed(s, seed):
    normal_parts = {"unsup": 0.4, "clf": 0.2, "calib": 0.2, "test": 0.2}
    insider_parts = {"unsup": 0.0, "clf": 0.4, "calib": 0.3, "test": 0.3}
    g = T.split(s, np.random.default_rng(seed), normal_parts, insider_parts)
    part = {k: s[s["user"].isin(v)] for k, v in g.items()}
    unsup = part["unsup"][part["unsup"]["y"] == 0]
    m = W.Layer2()
    m.fit_unsup(unsup, seed)
    wk = {k: m.weeks(part[k]) for k in ("clf", "calib", "test")}
    m.fit_weekly(wk["clf"], seed)
    m.calibrate(wk["calib"])

    cal, test = wk["calib"], wk["test"].copy()
    test = test.merge(session_week_flags(part["test"]), on=["user", "week"], how="left").fillna({"new_pc_any": 0, "night_unusual": 0})
    p_test, c_test = m.week_scores(test), m.change_scores(test)
    normal = cal[cal["y"] == 0]
    p_cal, c_cal = m.week_scores(normal), m.change_scores(normal)
    priv_sel = normal["role"].isin(PRIV).to_numpy()

    def index_with(limits, change_limits):
        lp = test["role"].map(limits).to_numpy(dtype=float)
        lc = test["role"].map(change_limits).to_numpy(dtype=float)
        return np.maximum(p_test / lp, c_test / lc)

    def lines(q, pooled_priv):
        lp, lc = {}, {}
        for r in W.ROLES:
            sel = (normal["role"] == r).to_numpy()
            if pooled_priv and r in PRIV:
                sel = priv_sel
            enough = sel.sum() >= 200
            lp[r] = float(np.quantile(p_cal[sel], q)) if enough else float(np.quantile(p_cal, q))
            lc[r] = max(float(np.quantile(c_cal[sel], q)) if enough else float(np.quantile(c_cal, q)), 1e-6)
        return lp, lc

    priv_role = test["role"].isin(PRIV)
    rule_any = priv_role & ((test["is_after_hours_max"] > 0) | (test["is_own_pc_mean"] < 1))
    rule_person = priv_role & ((test["new_pc_any"] > 0) | (test["night_unusual"] > 0))

    test["learned"] = p_test
    v = {}
    idx_base = index_with(*lines(W.LIMIT_QUANTILE, False))
    idx_q995 = index_with(*lines(0.995, False))
    idx_priv = index_with(*lines(W.LIMIT_QUANTILE, True))
    test["idx_base"], test["idx_priv"] = idx_base, idx_priv
    v["base"] = (idx_base > 1.0, "learned")
    v["base_rank_idx"] = (idx_base > 1.0, "idx_base")
    v["q995"] = (idx_q995 > 1.0, "learned")
    v["rule_any"] = ((idx_base > 1.0) | rule_any.to_numpy(), "learned")
    v["rule_person"] = ((idx_base > 1.0) | rule_person.to_numpy(), "learned")
    v["priv_pooled"] = (idx_priv > 1.0, "learned")
    v["priv_pooled_rule_person"] = ((idx_priv > 1.0) | rule_person.to_numpy(), "learned")
    rule_night = priv_role & (test["night_unusual"] > 0)
    v["priv_pooled_rule_night"] = ((idx_priv > 1.0) | rule_night.to_numpy(), "learned")

    out = {}
    groups = {r: test["role"] == r for r in W.ROLES} | {"Privileged": priv_role}
    for name, (flag, rank_col) in v.items():
        test[f"f_{name}"] = flag
        out[name] = {grp: metrics(test[sel], f"f_{name}", rank_col) for grp, sel in groups.items()}
    return out


def summarise(runs):
    summary = {}
    for name in next(iter(runs.values())):
        summary[name] = {}
        for grp in next(iter(runs.values()))[name]:
            agg = {}
            for k in ("T1", "T2", "T3", "precision_at_line", "flagged_per_100_people_weeks", "insiders"):
                vals = [runs[sd][name][grp][k] for sd in runs if runs[sd][name][grp][k] is not None]
                if vals:
                    agg[k] = {"mean": float(np.mean(vals)), "min": float(np.min(vals)), "max": float(np.max(vals)), "n": len(vals)}
            summary[name][grp] = agg
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="42,1,2,3,4")
    args = ap.parse_args()
    seeds = [int(x) for x in args.seeds.split(",")]
    s = T.load()
    runs = {}
    for seed in seeds:
        t0 = time.time()
        runs[str(seed)] = run_seed(s, seed)
        print(f"  [{seed}] done in {time.time() - t0:.0f}s", flush=True)
    summary = summarise(runs)
    OUT.write_text(json.dumps({"_about": __doc__, "seeds": seeds, "summary": summary, "runs": runs}, indent=1))

    f = lambda a, k, pct=True: ("  n/a" if k not in a else (f"{a[k]['mean']:5.1%}" if pct else f"{a[k]['mean']:5.1f}"))
    print("\n=== Mean over seeds, test people ===")
    for name, groups in summary.items():
        print(f"\n{name}")
        for grp, a in groups.items():
            ins = a.get("insiders", {}).get("mean", 0)
            print(f"  {grp:15s} insiders/seed={ins:4.1f}  T1={f(a, 'T1')}  T2={f(a, 'T2')}  T3={f(a, 'T3')}  "
                  f"precision@line={f(a, 'precision_at_line')}  listed/100 weeks={f(a, 'flagged_per_100_people_weeks', False)}")
    print(f"\nSaved {OUT}")


if __name__ == "__main__":
    main()
