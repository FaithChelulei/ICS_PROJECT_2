"""Experiment: the best detector for EACH role, with and without web and
e-mail activity, measured against the success targets.

Builds on 14_all_roles_evaluation.py (same targets, same people split,
same detectors) and adds three things:

1. Web and e-mail features from the full CERT r4.2 download (http.csv,
   email.csv), per session, plus "for this person" versions over the past
   30 days (past only):
     emails_sent, external_recipients, attachments, http_visits,
     distinct_domains, new_domains (a site this person has not visited in
     the last 30 days)
   NOTE: ChildGuard has no web or e-mail activity, so detectors that use
   these ("_full") show what a platform WITH such signals could reach.
   Detectors marked "_app" use only what the website can compute.

2. Choosing a detector per role ON VALIDATION, never on test:
     * a role with at least 3 insiders in its validation people picks the
       detector with the best validation person-week PR-AUC;
     * the Security Auditor role (one insider in all of CERT) cannot be
       chosen by data, so a rule fixed in advance is used: it takes the
       same detector chosen for the System Administrator role, the other
       privileged role.
   The chosen detector is then reported once on the test people.

3. Synthetic attacks for every role (as in 12_validated_evaluation.py): a
   normal session of a held-out person of the role is given the features
   of a real CERT attack session of another person, for each of the three
   CERT scenarios. Reported separately; it is the only measurement
   possible for auditors beyond their single real insider.

Also fixes the weekly limit for small roles: a person-week is flagged only
if its score is ABOVE the 98th percentile of the role's normal validation
weeks (ties at the limit are not flagged).

Run from the repo root (after 13_improved_evaluation.py has built
data/processed/sessions_improved.csv):
  .venv\\Scripts\\python.exe ml\\scripts\\15_role_selection_web_email.py --seeds 42,1,2,3,4
Output: models/role_selection_results.json. Nothing the website uses changes.
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
SESSIONS = BASE / "data" / "processed" / "sessions_improved.csv"
RAW = BASE / "data" / "r4.2_dl"
CACHE = BASE / "data" / "processed" / "sessions_web_email_experiment.csv"
OUT = BASE / "models" / "role_selection_results.json"

BASE_FEATURES = [
    "files_accessed_per_session", "events_prev_day", "events_prev_hour",
    "unique_pcs_used_that_day", "session_duration_minutes", "is_after_hours", "is_own_pc",
]
DEV_FEATURES = [f"dev_{f}" for f in BASE_FEATURES]
APP_FEATURES = BASE_FEATURES + DEV_FEATURES + ["new_pc", "unusual_hour"]
WEB_EMAIL = ["emails_sent", "external_recipients", "attachments",
             "http_visits", "distinct_domains", "new_domains"]
WEB_EMAIL_DEV = [f"dev_{f}" for f in WEB_EMAIL]
FULL_FEATURES = APP_FEATURES + WEB_EMAIL + WEB_EMAIL_DEV
ROLE_COLS = ["role_0", "role_1", "role_2"]
ROLE_NAMES = {0: "Caregiver", 1: "SecurityAuditor", 2: "SysAdmin"}
LABEL = "label_period"
WINDOW = np.timedelta64(30, "D")

# Features that carry each CERT scenario's signature in the synthetic attacks.
SCENARIO = {
    1: ["is_after_hours", "unusual_hour", "session_duration_minutes", "files_accessed_per_session",
        "events_prev_hour", "events_prev_day", "http_visits", "new_domains", "distinct_domains"],
    2: ["files_accessed_per_session", "events_prev_day", "session_duration_minutes",
        "http_visits", "distinct_domains", "new_domains", "emails_sent", "external_recipients", "attachments"],
    3: ["is_own_pc", "new_pc", "unique_pcs_used_that_day", "events_prev_day", "is_after_hours",
        "unusual_hour", "emails_sent", "external_recipients", "attachments"],
}


# ---------------------------------------------------------------- web and e-mail

def find_file(name):
    hits = list(RAW.rglob(name))
    if not hits:
        raise SystemExit(f"{name} not found under {RAW}; unpack r4.2.tar.bz2 first")
    return hits[0]


def read_fields(path, keep):
    """Fast reader for the huge CERT csvs: take the first fields of each
    line only (the free-text content column at the end is skipped)."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        header = fh.readline().strip().split(",")
        idx = [header.index(k) for k in keep]
        n = max(idx) + 1
        cols = [[] for _ in keep]
        for line in fh:
            p = line.split(",", n)
            for c, i in zip(cols, idx):
                c.append(p[i])
    return pd.DataFrame(dict(zip(keep, cols)))


def http_chunks(path, size=3_000_000):
    """Yield (date, user, pc, domain) frames; the page text is never kept."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        header = fh.readline().strip().split(",")
        i_d, i_u, i_p, i_url = (header.index(k) for k in ("date", "user", "pc", "url"))
        n = max(i_d, i_u, i_p, i_url) + 1
        rows = []
        for line in fh:
            p = line.split(",", n)
            url = p[i_url]
            dom = url.split("/", 3)[2] if url.count("/") >= 2 else url
            rows.append((p[i_d], p[i_u], p[i_p], dom))
            if len(rows) >= size:
                yield pd.DataFrame(rows, columns=["date", "user", "pc", "domain"])
                rows = []
        if rows:
            yield pd.DataFrame(rows, columns=["date", "user", "pc", "domain"])


def assign(events, s):
    ss = s[["session_id", "user", "pc", "session_start", "session_end"]].sort_values("session_start")
    m = pd.merge_asof(events.sort_values("date"), ss, left_on="date", right_on="session_start",
                      by=["user", "pc"], direction="backward")
    cap = m["session_start"] + pd.Timedelta(days=1)
    ok = m["session_id"].notna() & (m["date"] <= m["session_end"].where(m["session_end"] <= cap, cap))
    return m[ok]


def web_email_features(s):
    t0 = time.time()
    print("reading email.csv ...", flush=True)
    em = read_fields(find_file("email.csv"), ["date", "user", "pc", "to", "cc", "bcc", "attachments"])
    em["date"] = pd.to_datetime(em["date"], format="%m/%d/%Y %H:%M:%S")
    rec = (em["to"] + ";" + em["cc"] + ";" + em["bcc"]).str.split(";")
    em["external"] = rec.apply(lambda r: sum(1 for a in r if a and not a.strip().endswith("@dtaa.com")))
    em["attachments"] = pd.to_numeric(em["attachments"], errors="coerce").fillna(0)
    em = assign(em[["date", "user", "pc", "external", "attachments"]], s)
    eg = em.groupby("session_id")
    print(f"  {len(em)} e-mails placed in sessions ({time.time() - t0:.0f}s)", flush=True)

    print("reading http.csv (large, in chunks) ...", flush=True)
    visits, new, pairs = [], [], []
    last_seen = pd.Series(dtype="datetime64[ns]")          # (user, domain) -> last visit
    for chunk in http_chunks(find_file("http.csv")):
        chunk["date"] = pd.to_datetime(chunk["date"], format="%m/%d/%Y %H:%M:%S")
        chunk = chunk.sort_values(["user", "domain", "date"])
        prev = chunk.groupby(["user", "domain"])["date"].shift(1)
        if len(last_seen):
            key = pd.MultiIndex.from_frame(chunk[["user", "domain"]])
            carried = pd.Series(last_seen.reindex(key).to_numpy(), index=chunk.index)
            prev = prev.fillna(carried)
        chunk["new"] = (prev.isna() | ((chunk["date"] - prev) > pd.Timedelta(days=30))).astype(int)
        last = chunk.groupby(["user", "domain"])["date"].max()
        last_seen = pd.concat([last_seen[~last_seen.index.isin(last.index)], last]) if len(last_seen) else last
        a = assign(chunk, s)
        visits.append(a.groupby("session_id").size())
        new.append(a.groupby("session_id")["new"].sum())
        pairs.append(a[["session_id", "domain"]].drop_duplicates())
        print(f"  ... {sum(v.sum() for v in visits):,} visits placed ({time.time() - t0:.0f}s)", flush=True)
    hv = pd.concat(visits).groupby(level=0).sum()
    hn = pd.concat(new).groupby(level=0).sum()
    hd = pd.concat(pairs).drop_duplicates().groupby("session_id").size()

    s = s.set_index("session_id")
    s["emails_sent"] = eg.size()
    s["external_recipients"] = eg["external"].sum()
    s["attachments"] = eg["attachments"].sum()
    s["http_visits"] = hv
    s["distinct_domains"] = hd
    s["new_domains"] = hn
    s[WEB_EMAIL] = s[WEB_EMAIL].fillna(0).astype(float)
    return s.reset_index()


def per_user_dev(s, cols):
    s = s.sort_values(["user", "session_start"]).reset_index(drop=True)
    X_all = s[cols].to_numpy(dtype=float)
    t_all = s["session_start"].to_numpy().astype("datetime64[ns]")
    dev = np.zeros_like(X_all)
    for _, idx in s.groupby("user").indices.items():
        X, t = X_all[idx], t_all[idx]
        lo = np.searchsorted(t, t - WINDOW, side="left")
        hi = np.arange(len(idx))
        cnt = (hi - lo).astype(float)
        cs = np.vstack([np.zeros(X.shape[1]), np.cumsum(X, axis=0)])
        cs2 = np.vstack([np.zeros(X.shape[1]), np.cumsum(X * X, axis=0)])
        with np.errstate(invalid="ignore", divide="ignore"):
            mean = (cs[hi] - cs[lo]) / cnt[:, None]
            var = (cs2[hi] - cs2[lo]) / cnt[:, None] - mean ** 2
        d = (X - mean) / (np.sqrt(np.clip(var, 0, None)) + 1.0)
        d[cnt < 3] = 0.0
        dev[idx] = np.nan_to_num(d)
    for j, c in enumerate(cols):
        s[f"dev_{c}"] = dev[:, j]
    return s


def load():
    if CACHE.exists():
        df = pd.read_csv(CACHE, parse_dates=["session_start", "session_end"])
    else:
        s = pd.read_csv(SESSIONS, parse_dates=["session_start", "session_end"])
        s = web_email_features(s)
        s = per_user_dev(s, WEB_EMAIL)
        s.to_csv(CACHE, index=False)
        df = s
    for i, c in enumerate(ROLE_COLS):
        df[c] = (df["mapped_role"] == i).astype(float)
    ins = pd.read_csv(BASE / "data" / "insiders.csv", dtype=str)
    df["scenario"] = df["user"].map(ins[ins["dataset"] == "4.2"].set_index("user")["scenario"]).astype(float)
    return df


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


# ---------------------------------------------------------------- person-weeks

def week_table(frame, score_col, feats, tag):
    d = frame.assign(week=frame["session_start"].dt.to_period("W").astype(str))
    d = d.sort_values(score_col, ascending=False)
    d["r"] = d.groupby(["user", "week"]).cumcount()
    g = d.groupby(["user", "week"])
    top = d[d["r"] < 3].groupby(["user", "week"])
    wk = pd.DataFrame({"mapped_role": g["mapped_role"].first(), "y": g[LABEL].max(),
                       "score": top[score_col].mean(), "n_sessions": g.size(),
                       "iso_top": top[f"iso_{tag}"].mean(), "ae_top": top[f"ae_{tag}"].mean()})
    for f in feats:
        if f in ROLE_COLS:
            continue
        wk[f"{f}_sum"] = g[f].sum()
        wk[f"{f}_max"] = g[f].max()
    for i, c in enumerate(ROLE_COLS):
        wk[c] = (wk["mapped_role"] == i).astype(float)
    return wk.reset_index()


def wfeats(wk):
    return [c for c in wk.columns if c not in ("user", "week", "mapped_role", "y", "score")]


# ---------------------------------------------------------------- metrics

def targets(val_wk, test_wk, col):
    vn = val_wk.loc[val_wk["y"] == 0, col]
    limit = float(np.quantile(vn, 0.98)) if len(vn) else float("inf")
    t = test_wk
    out = {"limit": limit}
    normal = t[t["y"] == 0]
    out["T2_normal_weeks_flagged"] = float((normal[col] > limit).mean()) if len(normal) else None
    caught = t[t["y"] == 1].groupby("user")[col].max() > limit
    out["insiders_in_test"] = int(len(caught))
    out["T1_insiders_caught"] = float(caught.mean()) if len(caught) else None
    out["T3_precision_top10"] = float(t.nlargest(10, col)["y"].mean()) if t["y"].sum() > 0 else None
    if 0 < t["y"].sum() < len(t):
        out["week_roc_auc"] = float(roc_auc_score(t["y"], t[col]))
        out["week_pr_auc"] = float(average_precision_score(t["y"], t[col]))
    return out


def val_pr(wk, col):
    y = wk["y"].to_numpy()
    return float(average_precision_score(y, wk[col])) if 0 < y.sum() < len(y) else None


def synthetic(normal, donors, rng, n=100):
    rows = []
    for scen, cols in SCENARIO.items():
        pool = donors[donors["scenario"] == scen]
        if pool.empty or normal.empty:
            continue
        base = normal.sample(n, replace=True, random_state=rng.integers(1 << 31)).reset_index(drop=True)
        don = pool.sample(n, replace=True, random_state=rng.integers(1 << 31)).reset_index(drop=True)
        for c in cols:
            base[c] = don[c].to_numpy()
            if f"dev_{c}" in base:
                base[f"dev_{c}"] = don[f"dev_{c}"].to_numpy()
        rows.append(base.assign(syn_scenario=scen))
    return pd.concat(rows, ignore_index=True) if rows else None


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
        groups["unsup"] |= set(nor[:a]); groups["clf"] |= set(nor[a:b])
        groups["val"] |= set(nor[b:c]); groups["test"] |= set(nor[c:])
        k = len(ins)
        i1, i2 = int(round(0.4 * k)), int(round(0.7 * k))
        groups["clf"] |= set(ins[:i1]); groups["val"] |= set(ins[i1:i2]); groups["test"] |= set(ins[i2:])
    return groups


def score_session_detectors(part, seed):
    """Adds columns A_current, B_<tag>, C_<tag> (tag app/full) to each part."""
    for role in ROLE_NAMES:
        tr = part["unsup"][part["unsup"]["mapped_role"] == role]
        m = train_unsup(tr[BASE_FEATURES].to_numpy(dtype=float), seed)
        for k in ("clf", "val", "test", "syn_val", "syn_test"):
            if part.get(k) is None:
                continue
            sel = part[k]["mapped_role"] == role
            if sel.any():
                part[k].loc[sel, "A_current"] = minmax_avg(m, part[k].loc[sel, BASE_FEATURES].to_numpy(dtype=float))
    models = {}
    for tag, base in (("app", APP_FEATURES), ("full", FULL_FEATURES)):
        feats = base + ROLE_COLS
        pooled = train_unsup(part["unsup"][feats].to_numpy(dtype=float), seed)
        for k in ("clf", "val", "test", "syn_val", "syn_test"):
            if part.get(k) is None:
                continue
            i_r, a_r = ranks(pooled, part[k][feats].to_numpy(dtype=float))
            part[k][f"iso_{tag}"], part[k][f"ae_{tag}"] = i_r, a_r
            part[k][f"B_{tag}"] = (i_r + a_r) / 2
        cf = feats + [f"iso_{tag}", f"ae_{tag}"]
        clf = classifier(seed).fit(part["clf"][cf].to_numpy(dtype=float), part["clf"][LABEL].to_numpy())
        for k in ("clf", "val", "test", "syn_val", "syn_test"):
            if part.get(k) is None:
                continue
            part[k][f"C_{tag}"] = clf.predict_proba(part[k][cf].to_numpy(dtype=float))[:, 1]
        models[tag] = feats
    return models


def run(seed, df):
    t0 = time.time()
    rng = np.random.default_rng(seed)
    g = split(df, rng)
    part = {k: df[df["user"].isin(v)].copy() for k, v in g.items()}

    # Synthetic attacks for every role; validation and test use different
    # base people and different donor attackers.
    attackers = df[(df[LABEL] == 1) & df["scenario"].notna()]
    donors = np.array(sorted(attackers["user"].unique()))
    rng.shuffle(donors)
    half = len(donors) // 2
    for k, dset in (("syn_val", donors[:half]), ("syn_test", donors[half:])):
        base_k = "val" if k == "syn_val" else "test"
        chunks = []
        for role in ROLE_NAMES:
            nor = part[base_k][(part[base_k]["mapped_role"] == role) & (part[base_k][LABEL] == 0)]
            don = attackers[attackers["user"].isin(dset) & (attackers["mapped_role"] != role)]
            sy = synthetic(nor, don, rng)
            if sy is not None:
                chunks.append(sy)
        part[k] = pd.concat(chunks, ignore_index=True)

    tags = score_session_detectors(part, seed)

    # Weekly tables and the weekly classifiers D_app / D_full.
    weeks = {k: None for k in ("clf", "val", "test")}
    for tag, feats in tags.items():
        tabs = {k: week_table(part[k], f"B_{tag}", feats, tag) for k in weeks}
        clf = classifier(seed).fit(tabs["clf"][wfeats(tabs["clf"])].to_numpy(dtype=float), tabs["clf"]["y"].to_numpy())
        for k in weeks:
            t = tabs[k][["user", "week", "mapped_role", "y", "score"]].rename(columns={"score": f"B_{tag}"})
            t[f"D_{tag}"] = clf.predict_proba(tabs[k][wfeats(tabs[k])].to_numpy(dtype=float))[:, 1]
            weeks[k] = t if weeks[k] is None else weeks[k].merge(t.drop(columns=["mapped_role", "y"]), on=["user", "week"])
    for k in weeks:
        for det in ("A_current", "C_app", "C_full"):
            t = week_table(part[k].assign(iso_x=0.0, ae_x=0.0), det, [], "x")[["user", "week", "score"]]
            weeks[k] = weeks[k].merge(t.rename(columns={"score": det}), on=["user", "week"])

    dets = ["A_current", "B_app", "C_app", "D_app", "B_full", "C_full", "D_full"]
    out = {}
    for role, name in ROLE_NAMES.items():
        vw = weeks["val"][weeks["val"]["mapped_role"] == role]
        tw = weeks["test"][weeks["test"]["mapped_role"] == role]
        r = {"val_insiders": int(vw.loc[vw["y"] == 1, "user"].nunique())}
        for det in dets:
            res = targets(vw, tw, det)
            res["val_week_pr_auc"] = val_pr(vw, det)
            if not det.startswith("D_"):
                sv = part["syn_test"][part["syn_test"]["mapped_role"] == role]
                tn = part["test"][(part["test"]["mapped_role"] == role) & (part["test"][LABEL] == 0)]
                y = np.r_[np.zeros(len(tn)), np.ones(len(sv))]
                s = np.r_[tn[det].to_numpy(), sv[det].to_numpy()]
                res["synthetic_session_roc_auc"] = float(roc_auc_score(y, s))
                res["synthetic_session_pr_auc"] = float(average_precision_score(y, s))
                res["synthetic_attack_share"] = float(y.mean())
            r[det] = res
        out[name] = r

    # Choice per role on VALIDATION only.
    for name in ("Caregiver", "SysAdmin"):
        for family, cands in (("app", ["A_current", "B_app", "C_app", "D_app"]),
                              ("full", ["A_current", "B_app", "C_app", "D_app", "B_full", "C_full", "D_full"])):
            vals = {d: out[name][d]["val_week_pr_auc"] for d in cands if out[name][d]["val_week_pr_auc"] is not None}
            out[name][f"chosen_{family}"] = max(vals, key=vals.get) if out[name]["val_insiders"] >= 3 and vals else "C_" + family
    for family in ("app", "full"):
        out["SecurityAuditor"][f"chosen_{family}"] = out["SysAdmin"][f"chosen_{family}"]
    for name in ROLE_NAMES.values():
        msg = []
        for family in ("app", "full"):
            d = out[name][f"chosen_{family}"]
            r = out[name][d]
            f = lambda v, fmt: fmt.format(v) if v is not None else "n/a"
            msg.append(f"{family}: {d} T1={f(r['T1_insiders_caught'], '{:.0%}')} T2={f(r['T2_normal_weeks_flagged'], '{:.1%}')}"
                       f" T3={f(r['T3_precision_top10'], '{:.0%}')}")
        print(f"  [{seed}] {name:15s} insiders(test)={out[name]['A_current']['insiders_in_test']}  " + "  |  ".join(msg), flush=True)
    out["seconds"] = round(time.time() - t0, 1)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="42")
    seeds = [int(s) for s in ap.parse_args().seeds.split(",")]
    df = load()
    print(f"sessions: {len(df)}; seeds: {seeds}", flush=True)
    print(df.groupby("mapped_role")[WEB_EMAIL].mean().round(2), flush=True)
    runs = {str(s): run(s, df) for s in seeds}

    dets = ["A_current", "B_app", "C_app", "D_app", "B_full", "C_full", "D_full"]
    keys = ["T1_insiders_caught", "T2_normal_weeks_flagged", "T3_precision_top10", "week_roc_auc",
            "week_pr_auc", "synthetic_session_roc_auc", "synthetic_session_pr_auc", "insiders_in_test"]
    summary = {}
    print("\n=== Mean over seeds (test people) ===", flush=True)
    for name in ROLE_NAMES.values():
        summary[name] = {}
        print(f"\n{name}", flush=True)
        for det in dets:
            agg = {}
            for k in keys:
                vals = [runs[s][name][det].get(k) for s in runs]
                vals = [v for v in vals if v is not None]
                if vals:
                    agg[k] = {"mean": float(np.mean(vals)), "min": float(np.min(vals)),
                              "max": float(np.max(vals)), "n_runs": len(vals)}
            summary[name][det] = agg
            f = lambda k, fmt: fmt.format(agg[k]["mean"]) if k in agg else "n/a"
            print(f"  {det:10s} T1={f('T1_insiders_caught', '{:.0%}'):>4s}  T2={f('T2_normal_weeks_flagged', '{:.1%}'):>5s}"
                  f"  T3={f('T3_precision_top10', '{:.0%}'):>4s}  weekROC={f('week_roc_auc', '{:.3f}')}"
                  f"  weekPR={f('week_pr_auc', '{:.3f}')}  synthROC={f('synthetic_session_roc_auc', '{:.3f}')}"
                  f"  synthPR={f('synthetic_session_pr_auc', '{:.3f}')}", flush=True)
        for family in ("app", "full"):
            chosen = [runs[s][name][f"chosen_{family}"] for s in runs]
            picked = {}
            for k in ("T1_insiders_caught", "T2_normal_weeks_flagged", "T3_precision_top10"):
                vals = [runs[s][name][runs[s][name][f"chosen_{family}"]].get(k) for s in runs]
                vals = [v for v in vals if v is not None]
                picked[k] = float(np.mean(vals)) if vals else None
            summary[name][f"chosen_{family}"] = {"per_seed": chosen, "mean": picked}
            f = lambda v, fmt: fmt.format(v) if v is not None else "n/a"
            print(f"  CHOSEN ({family}) per seed {chosen}: T1={f(picked['T1_insiders_caught'], '{:.0%}')}"
                  f"  T2={f(picked['T2_normal_weeks_flagged'], '{:.1%}')}  T3={f(picked['T3_precision_top10'], '{:.0%}')}", flush=True)
    OUT.write_text(json.dumps({"_about": __doc__.strip().splitlines()[0], "seeds": seeds,
                               "summary": summary, "runs": runs}, indent=2, default=float))
    print(f"\nSaved {OUT}", flush=True)


if __name__ == "__main__":
    main()
