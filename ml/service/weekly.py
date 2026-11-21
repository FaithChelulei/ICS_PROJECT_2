"""Layer 2: the weekly review ("People to review this week").

One module, used in three places, so they can never drift apart:
  * ml/scripts/16_train_weekly.py   trains and evaluates it on CERT r4.2
  * ml/service/app.py /score_week   scores the live website's weeks
  * ml/scripts/test_weekly.py       checks the two give the same answer

What it does
------------
Input: a person's SESSIONS, each with the 7 features layer 1 already uses
(for a Caregiver or Security Auditor a session is a calendar day, for a
System Administrator one sign-in -- the same units as layer 1).

1. "Unusual for you" features, from the same person's previous 30 days only
   (never the future, so the website can compute them the same way):
     dev_<feature>  distance from the person's 30-day mean, in their own
                    standard deviations (0 until there are 3 earlier sessions)
     new_pc         a device this person has not used in the last 30 days
     unusual_hour   not active within an hour of this time of day on 3 or
                    more earlier days in the last 30
2. One pooled Isolation Forest + Autoencoder (all roles, the role as an
   input), trained on normal people only -- the unsupervised part, which
   still reacts to kinds of behaviour it has never been shown.
3. Each person's week is summarised (sums and maxima of every feature, the
   number of sessions, the three most unusual sessions' model scores).
4. A gradient-boosted classifier, trained on OTHER people's weeks including
   known CERT insiders, turns the summary into a score between 0 and 1.
5. The limit of each role is the 98th percentile of normal weeks of people
   kept aside for calibration (2% of normal weeks above it, by design).
6. Reasons: each group of features in turn is reset to the role's typical
   value and the week re-scored; the groups whose reset lowers the score
   most are the reasons shown to the auditor.

Layer 2 never signs anyone out. It ranks people for a human to review.
"""
import hashlib
import json
import os
from pathlib import Path

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import joblib
import numpy as np
import pandas as pd

BASE_FEATURES = [
    "files_accessed_per_session", "events_prev_day", "events_prev_hour",
    "unique_pcs_used_that_day", "session_duration_minutes", "is_after_hours", "is_own_pc",
]
# Scale-free design. CERT office days last about 8 hours with dozens of
# events; a ChildGuard caregiver's day is a few minutes and a few actions.
# A model that learns absolute amounts from CERT therefore finds every
# normal ChildGuard user unusual (seen in the first live test). Layer 2 only
# uses signals that mean the same in both places:
#   counts and durations  -> how far from THIS person's usual, on a log
#                            scale ("three times your usual" looks the same
#                            for 3 -> 9 records as for 30 -> 90 files)
#   yes/no signals        -> as they are, and how unusual for this person
COUNT_FEATURES = ["files_accessed_per_session", "events_prev_day", "events_prev_hour", "session_duration_minutes"]
BINARY_FEATURES = ["is_after_hours", "is_own_pc"]
DEV_FEATURES = [f"dev_{f}" for f in COUNT_FEATURES + BINARY_FEATURES]
PERSON_FEATURES = DEV_FEATURES + ["is_after_hours", "is_own_pc", "unique_pcs_used_that_day", "new_pc", "unusual_hour"]
# The "big change from your own usual" half of layer 2 (unsupervised, no
# CERT attack pattern needed): the largest of these, over the week.
# Only the amount of activity counts here, not session length: in ChildGuard
# a caregiver's or auditor's unit is a calendar day, whose length mostly
# measures the gap between two visits. In the 5-week simulation of the app
# it listed about 1 in 10 normal people on its own; the counts measure what
# a quiet insider actually raises (records and pages read).
CHANGE_FEATURES = ["dev_files_accessed_per_session", "dev_events_prev_day", "dev_events_prev_hour"]
LIMIT_QUANTILE = 0.99   # each half flags ~1% of normal weeks, ~2% together
# "Sustained" means on most days, not on average: the change half uses the
# MEDIAN of the week's sessions (one unusually busy day cannot list anyone,
# a rise every day does), and only sessions with at least a week of the
# person's own history count (no judging newcomers on a few days).
CHANGE_MIN_HISTORY = 7
CHANGE_MIN_SESSIONS = 3
LOG_FLOOR = 0.25   # smallest spread allowed, in log units (so a very regular person is not over-sensitive)
ROLES = ["Caregiver", "SecurityAuditor", "SysAdmin"]
ROLE_COLS = [f"role_{r}" for r in ROLES]
# Roles whose review lines are set together, from all their normal weeks.
# CERT's Security department is 20 people (mostly guards, one insider); its
# own 99th percentile rested on a handful of people. Pooling the two
# privileged roles (ml/scripts/17_improve_weekly.py, 5 seeds) cut normal
# auditor weeks listed from 6.4% to 0.4% and privileged staff overall from
# 5.6% to 3.3%, with administrators caught going from 20% to 25%.
LINE_GROUPS = {"SecurityAuditor": ["SecurityAuditor", "SysAdmin"], "SysAdmin": ["SecurityAuditor", "SysAdmin"]}
WINDOW = np.timedelta64(30, "D")
DAY_NS = np.int64(86_400 * 10**9)


class DenseNumpy:
    """Runs a saved Keras autoencoder made only of Dense layers with plain
    numpy, using its trained weights. Same numbers as Keras (float32 matrix
    products), but no deep-learning engine is needed at scoring time and
    each call takes about a millisecond -- on a small hosted server Keras
    took 1-9 s per call. Anything that is not a plain Dense stack keeps the
    Keras model (see fast_predictor)."""
    _ACT = {"relu": lambda z: np.maximum(z, 0), "linear": lambda z: z,
            "sigmoid": lambda z: 1 / (1 + np.exp(-z)), "tanh": np.tanh}

    def __init__(self, layers):
        self.layers = layers  # [(W, b, activation), ...]

    def predict(self, x, verbose=0, batch_size=None):
        h = np.asarray(x, dtype=np.float32)
        for w, b, act in self.layers:
            h = self._ACT[act](h @ w + b)
        return h


def fast_predictor(model):
    """DenseNumpy for a plain Dense stack, otherwise the Keras model itself."""
    layers = []
    for layer in model.layers:
        act = getattr(getattr(layer, "activation", None), "__name__", None)
        weights = layer.get_weights()
        if type(layer).__name__ != "Dense" or act not in DenseNumpy._ACT or len(weights) != 2:
            return model
        layers.append((weights[0].astype(np.float32), weights[1].astype(np.float32), act))
    return DenseNumpy(layers) if layers else model
MIN_HISTORY = 3
# How the pooled anomaly models' session scores reach the weekly classifier:
# "reference" ranks them against all CERT training sessions, "person"
# against the same person's own previous 30 days (scale-free, like the
# other inputs). Stored in the model's meta so live scoring matches training.
RANKS = os.environ.get("WEEKLY_RANKS", "reference")

# Plain-language reasons. Each is a group of weekly features.
SUSTAINED = ("sustained_increase", "Activity well above this person's usual for the whole week")
REASONS = {
    "more_than_usual": ("Much more activity than this person's usual",
                        ["dev_files_accessed_per_session", "dev_events_prev_day", "dev_events_prev_hour"]),
    "new_device": ("A device this person had not used before",
                   ["new_pc", "is_own_pc", "unique_pcs_used_that_day", "dev_is_own_pc"]),
    "unusual_hours": ("Activity at hours this person does not normally work",
                      ["is_after_hours", "unusual_hour", "dev_is_after_hours"]),
    "long_sessions": ("Much longer sessions than this person's usual", ["dev_session_duration_minutes"]),
    "odd_pattern": ("An unusual combination of activity (anomaly models)", ["iso_top", "ae_top"]),
}


# ------------------------------------------------------------ person features

def add_person_features(s):
    """s: one row per session with columns user, role, start (datetime), pc
    and BASE_FEATURES. Returns a copy sorted by user and start, with
    PERSON_FEATURES added. Uses each person's previous 30 days only."""
    s = s.sort_values(["user", "start"]).reset_index(drop=True)
    n = len(s)
    dev_cols = COUNT_FEATURES + BINARY_FEATURES
    X_all = s[dev_cols].to_numpy(dtype=float, copy=True)
    X_all[:, :len(COUNT_FEATURES)] = np.log1p(np.clip(X_all[:, :len(COUNT_FEATURES)], 0, None))
    is_count = np.array([True] * len(COUNT_FEATURES) + [False] * len(BINARY_FEATURES))
    t_all = s["start"].to_numpy().astype("datetime64[ns]")
    minute = (t_all.astype("datetime64[m]").astype(np.int64)) % (24 * 60)
    day = t_all.astype(np.int64) // DAY_NS
    dev = np.zeros((n, len(dev_cols)))
    hist = np.zeros(n)
    unusual = np.ones(n)
    for _, idx in s.groupby("user", sort=False).indices.items():
        X, t = X_all[idx], t_all[idx]
        lo = np.searchsorted(t, t - WINDOW, side="left")
        hi = np.arange(len(idx))
        cnt = (hi - lo).astype(float)
        cs = np.vstack([np.zeros(X.shape[1]), np.cumsum(X, axis=0)])
        cs2 = np.vstack([np.zeros(X.shape[1]), np.cumsum(X * X, axis=0)])
        with np.errstate(invalid="ignore", divide="ignore"):
            mean = (cs[hi] - cs[lo]) / cnt[:, None]
            var = (cs2[hi] - cs2[lo]) / cnt[:, None] - mean ** 2
        spread = np.sqrt(np.clip(var, 0, None)) + LOG_FLOOR
        d = np.where(is_count, (X - mean) / spread, X - mean)
        hist[idx] = cnt
        d[cnt < MIN_HISTORY] = 0.0
        # Rounded: running sums over a long history leave noise such as
        # -4.8e-15 where the true value is 0, and a tree must not learn it.
        dev[idx] = np.round(np.nan_to_num(d), 6)
        m, dy = minute[idx], day[idx]
        for i in range(len(idx)):
            if lo[i] == i:
                continue
            dh = np.abs(m[lo[i]:i] - m[i])
            near = np.minimum(dh, 24 * 60 - dh) <= 60
            unusual[idx[i]] = float(len(np.unique(dy[lo[i]:i][near])) < 3)
    for j, f in enumerate(DEV_FEATURES):
        s[f] = dev[:, j]
    s["unusual_hour"] = unusual
    s["history_sessions"] = hist   # earlier sessions in the 30 days (not a model input)
    prev = s.groupby(["user", "pc"], sort=False)["start"].shift(1)
    s["new_pc"] = (prev.isna() | ((s["start"] - prev) > pd.Timedelta(days=30))).astype(float)
    for r, c in zip(ROLES, ROLE_COLS):
        s[c] = (s["role"] == r).astype(float)
    return s


def person_rank(s, raw):
    """Rank of each session's anomaly score among the SAME person's sessions
    in the previous 30 days (0 = lowest, 1 = highest); 0.5 with fewer than
    MIN_HISTORY earlier sessions. s must be sorted by user and start, as
    add_person_features returns it."""
    out = np.full(len(s), 0.5)
    t_all = s["start"].to_numpy().astype("datetime64[ns]")
    for _, idx in s.groupby("user", sort=False).indices.items():
        t, r = t_all[idx], raw[idx]
        lo = np.searchsorted(t, t - WINDOW, side="left")
        for i in range(len(idx)):
            n = i - lo[i]
            if n >= MIN_HISTORY:
                past = r[lo[i]:i]
                out[idx[i]] = (np.count_nonzero(past < r[i]) + 0.5 * np.count_nonzero(past == r[i])) / n
    return out


def week_of(start):
    return start.dt.to_period("W").astype(str)


def week_table(s, b_score, iso_rank, ae_rank):
    """One row per person-week. s must have PERSON_FEATURES (see above),
    columns user, role, start and optionally y (attack label)."""
    d = s.assign(week=week_of(s["start"]), b=b_score, iso_r=iso_rank, ae_r=ae_rank)
    d = d.sort_values("b", ascending=False)
    d["rank_in_week"] = d.groupby(["user", "week"]).cumcount()
    g = d.groupby(["user", "week"])
    top = d[d["rank_in_week"] < 3].groupby(["user", "week"])
    wk = pd.DataFrame({"role": g["role"].first(), "n_sessions": g.size(),
                       "iso_top": top["iso_r"].mean(), "ae_top": top["ae_r"].mean()})
    if "y" in d:
        wk["y"] = g["y"].max()
    for f in PERSON_FEATURES:
        wk[f"{f}_mean"] = g[f].mean()
        wk[f"{f}_max"] = g[f].max()
    # The unsupervised half: largest week-median rise over sessions with
    # enough history; 0 when fewer than CHANGE_MIN_SESSIONS such sessions.
    ok = d["history_sessions"] >= CHANGE_MIN_HISTORY
    med = d[ok].groupby(["user", "week"])[CHANGE_FEATURES].median().max(axis=1)
    n_ok = d[ok].groupby(["user", "week"]).size()
    wk["change"] = med.where(n_ok >= CHANGE_MIN_SESSIONS).reindex(wk.index).fillna(0).clip(lower=0)
    for r, c in zip(ROLES, ROLE_COLS):
        wk[c] = (wk["role"] == r).astype(float)
    return wk.reset_index()


def week_feature_names():
    # n_sessions is kept in the table for the auditor but not given to the
    # model: how often people sign in differs between CERT and ChildGuard.
    names = ["iso_top", "ae_top"]
    for f in PERSON_FEATURES:
        names += [f"{f}_mean", f"{f}_max"]
    return names + ROLE_COLS


def reason_columns(group_features):
    cols = []
    for f in group_features:
        if f in ("iso_top", "ae_top"):
            cols.append(f)
        else:
            cols += [f"{f}_mean", f"{f}_max"]
    return cols


# ------------------------------------------------------------ the model

class Layer2:
    """Pooled anomaly models + weekly classifier + per-role limits."""

    def __init__(self):
        self.scaler = self.iso = self.ae = None
        self.ref_iso = self.ref_ae = None
        self.clf = None
        self.limits = {}
        self.change_limits = {}
        self.typical = {}
        self.version = None
        self.ranks = RANKS

    # -- unsupervised part
    def _x(self, s):
        return s[PERSON_FEATURES + ROLE_COLS].to_numpy(dtype=float)

    def fit_unsup(self, s, seed):
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        import tensorflow as tf
        from tensorflow import keras
        tf.keras.utils.set_random_seed(seed)
        x = self._x(s)
        self.scaler = StandardScaler().fit(x)
        xs = self.scaler.transform(x)
        self.iso = IsolationForest(n_estimators=200, contamination="auto", random_state=seed, n_jobs=-1).fit(xs)
        d = xs.shape[1]
        hidden, code = max(12, int(1.7 * d)), max(6, d // 2)
        self.ae = keras.Sequential([
            keras.layers.Input(shape=(d,)),
            keras.layers.Dense(hidden, activation="relu"),
            keras.layers.Dense(code, activation="relu"),
            keras.layers.Dense(hidden, activation="relu"),
            keras.layers.Dense(d, activation="linear"),
        ])
        self.ae.compile(optimizer="adam", loss="mse")
        es = keras.callbacks.EarlyStopping(monitor="val_loss", patience=4, restore_best_weights=True)
        self.ae.fit(xs, xs, epochs=40, batch_size=512, validation_split=0.1, shuffle=True, verbose=0, callbacks=[es])
        iso_raw, ae_raw = self._raw(s)
        self.ref_iso, self.ref_ae = np.sort(iso_raw), np.sort(ae_raw)

    def _raw(self, s):
        xs = self.scaler.transform(self._x(s))
        return (-self.iso.score_samples(xs),
                np.mean((xs - self.ae.predict(xs, verbose=0, batch_size=8192)) ** 2, axis=1))

    def session_ranks(self, s):
        iso_raw, ae_raw = self._raw(s)
        if self.ranks == "person":
            return person_rank(s, iso_raw), person_rank(s, ae_raw)
        iso_r = np.searchsorted(self.ref_iso, iso_raw, side="right") / len(self.ref_iso)
        ae_r = np.searchsorted(self.ref_ae, ae_raw, side="right") / len(self.ref_ae)
        return iso_r, ae_r

    def weeks(self, s):
        iso_r, ae_r = self.session_ranks(s)
        return week_table(s, (iso_r + ae_r) / 2, iso_r, ae_r)

    # -- weekly classifier
    def fit_weekly(self, wk, seed):
        from sklearn.ensemble import HistGradientBoostingClassifier
        self.clf = HistGradientBoostingClassifier(learning_rate=0.05, max_iter=300, max_leaf_nodes=15,
                                                  l2_regularization=1.0, class_weight="balanced",
                                                  random_state=seed)
        self.clf.fit(wk[week_feature_names()].to_numpy(dtype=float), wk["y"].to_numpy())

    def week_scores(self, wk):
        return self.clf.predict_proba(wk[week_feature_names()].to_numpy(dtype=float))[:, 1]

    # -- the unsupervised half: a sustained rise above the person's own usual
    @staticmethod
    def change_scores(wk):
        return wk["change"].to_numpy(dtype=float)

    # -- limits and reasons, from calibration people's NORMAL weeks
    def calibrate(self, wk, min_weeks=200):
        normal = wk[wk["y"] == 0] if "y" in wk else wk
        p, c = self.week_scores(normal), self.change_scores(normal)
        pooled_p, pooled_c = float(np.quantile(p, LIMIT_QUANTILE)), float(np.quantile(c, LIMIT_QUANTILE))
        for r in ROLES:
            # Privileged staff share one line (LINE_GROUPS): set from 20
            # Security department people alone it swung from seed to seed
            # and listed 6% of normal auditor weeks; shared, 0.4% (17).
            sel = normal["role"].isin(LINE_GROUPS.get(r, [r])).to_numpy()
            enough = sel.sum() >= min_weeks
            self.limits[r] = float(np.quantile(p[sel], LIMIT_QUANTILE)) if enough else pooled_p
            self.change_limits[r] = max(float(np.quantile(c[sel], LIMIT_QUANTILE)) if enough else pooled_c, 1e-6)
            # The "typical week" used for reasons stays the role's own.
            own = (normal["role"] == r).to_numpy()
            self.typical[r] = normal.loc[own, week_feature_names()].median().to_dict() if own.any() else {}

    def lines(self, local=None):
        """The lines in force: the CERT-calibrated ones, raised (never
        lowered) per role by a deployment's own calibration. `local` is
        {role: {"learned": x, "change": y}}, computed by the live system from
        its own ordinary past weeks (see backend services/weeklyReview.js)."""
        lp, lc = dict(self.limits), dict(self.change_limits)
        for role, v in (local or {}).items():
            if role in lp and isinstance(v, dict):
                lp[role] = max(lp[role], float(v.get("learned", 0) or 0))
                lc[role] = max(lc[role], float(v.get("change", 0) or 0))
        return lp, lc

    def review_index(self, wk, p=None, local=None):
        """One number per person-week: 1.0 is the review line. It is the
        larger of (learned score / its limit) and (change / its limit), so
        a week goes on the list if EITHER half crosses its limit."""
        p = self.week_scores(wk) if p is None else p
        c = self.change_scores(wk)
        limits, change_limits = self.lines(local)
        lp = wk["role"].map(limits).to_numpy(dtype=float)
        lc = wk["role"].map(change_limits).to_numpy(dtype=float)
        return np.maximum(p / lp, c / lc), p, c

    def reasons(self, wk, scores, top=3, min_drop=0.02):
        out = []
        X = wk[week_feature_names()]
        for key, (_, feats) in REASONS.items():
            cols = [c for c in reason_columns(feats) if c in X.columns]
            Xr = X.copy()
            for r in ROLES:
                sel = (wk["role"] == r).to_numpy()
                if sel.any() and self.typical.get(r):
                    for c in cols:
                        Xr.loc[sel, c] = self.typical[r][c]
            out.append(scores - self.clf.predict_proba(Xr.to_numpy(dtype=float))[:, 1])
        drops = np.vstack(out).T
        keys = list(REASONS)
        res = []
        for row in drops:
            order = np.argsort(-row)
            res.append([{"code": keys[i], "text": REASONS[keys[i]][0], "raised_by": round(float(row[i]), 4)}
                        for i in order[:top] if row[i] >= min_drop])
        return res

    # -- save / load
    def save(self, folder, extra_meta=None):
        folder = Path(folder)
        folder.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.scaler, folder / "layer2_scaler.joblib")
        joblib.dump(self.iso, folder / "layer2_isoforest.joblib")
        self.ae.save(folder / "layer2_autoencoder.keras")
        np.savez_compressed(folder / "layer2_reference.npz", iso=self.ref_iso, ae=self.ref_ae)
        joblib.dump(self.clf, folder / "layer2_weekly_classifier.joblib")
        meta = {"limits": self.limits, "change_limits": self.change_limits, "typical": self.typical,
                "limit_quantile": LIMIT_QUANTILE, "change_features": CHANGE_FEATURES,
                "change_min_history": CHANGE_MIN_HISTORY, "change_min_sessions": CHANGE_MIN_SESSIONS, "person_features": PERSON_FEATURES,
                "week_features": week_feature_names(), "roles": ROLES, "ranks": self.ranks, **(extra_meta or {})}
        (folder / "layer2_meta.json").write_text(json.dumps(meta, indent=2, default=float))

    @classmethod
    def load(cls, folder):
        import keras  # TensorFlow on a laptop, or KERAS_BACKEND=jax when hosted (see app.py)
        folder = Path(folder)
        m = cls()
        m.scaler = joblib.load(folder / "layer2_scaler.joblib")
        m.iso = joblib.load(folder / "layer2_isoforest.joblib")
        m.ae = fast_predictor(keras.models.load_model(folder / "layer2_autoencoder.keras"))
        ref = np.load(folder / "layer2_reference.npz")
        m.ref_iso, m.ref_ae = ref["iso"], ref["ae"]
        m.clf = joblib.load(folder / "layer2_weekly_classifier.joblib")
        meta = json.loads((folder / "layer2_meta.json").read_text())
        m.limits, m.change_limits, m.typical = meta["limits"], meta["change_limits"], meta["typical"]
        m.ranks = meta.get("ranks", "reference")
        digest = hashlib.sha256()
        for name in sorted(p.name for p in folder.glob("layer2_*")):
            digest.update((folder / name).read_bytes())
        m.version = f"weekly-{digest.hexdigest()[:12]}"
        return m

    # -- live scoring
    def score_people(self, sessions, week, local=None):
        """sessions: DataFrame (user, role, start, pc, BASE_FEATURES) covering
        the target week AND the 30 days before it. week: a period string as
        produced by week_of(), e.g. '2026-11-09/2026-11-15'.
        Returns one dict per person active in that week."""
        s = add_person_features(sessions)
        wk = self.weeks(s)
        wk = wk[wk["week"] == week].reset_index(drop=True)
        if wk.empty:
            return []
        index, p, c = self.review_index(wk, local=local)
        limits, change_limits = self.lines(local)
        why = self.reasons(wk, p)
        res = []
        for i, row in wk.iterrows():
            lp, lc = limits[row["role"]], change_limits[row["role"]]
            reasons = why[i]
            if c[i] > lc:
                reasons = [{"code": SUSTAINED[0], "text": SUSTAINED[1], "raised_by": round(float(c[i] / lc), 4)}] + reasons[:2]
            res.append({"user": row["user"], "role": row["role"], "week": week,
                        "score": round(float(min(index[i], 9.99)), 6), "limit": 1.0,
                        "above_limit": bool(index[i] > 1.0), "reasons": reasons,
                        "parts": {"learned": round(float(p[i]), 4), "learned_limit": round(lp, 4),
                                  "change": round(float(c[i]), 4), "change_limit": round(lc, 4)},
                        "sessions": int(row["n_sessions"]), "model_version": self.version})
        return res
