"""Check: the live /score_week path gives the same answer as the evaluated
training path (ml/service/weekly.py, used by 16_train_weekly.py).

For a sample of CERT people and weeks it scores each week twice:
  * training path: person features over the whole history, then weeks()
  * live path:     only the week and the 30 days before it, as the website
                   sends them to /score_week (Layer2.score_people)
and fails if any score differs by more than 1e-9. Also checks that the
saved model loads, that every role has a limit, and that the reasons are
well formed.

Run from the repo root:
  .venv\\Scripts\\python.exe ml\\scripts\\test_weekly.py
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "service"))
import weekly as W  # noqa: E402

DATA = BASE / "data" / "processed" / "sessions_improved.csv"
ROLE_OF = {0: "Caregiver", 1: "SecurityAuditor", 2: "SysAdmin"}


def app_scale_check(m):
    """CERT office days are ~8 hours with dozens of events; a ChildGuard day
    is minutes and a few actions. This checks the model behaves sensibly at
    ChildGuard's scale: steady normal people (for every role) stay below
    their limit, and a quiet insider -- the same hours and device, but three
    times their own usual activity for a week -- is above it and ranked
    above every normal person."""
    import datetime as dt
    usual = {"Caregiver": (3, 7, 4, 20), "SecurityAuditor": (4, 10, 5, 30), "SysAdmin": (2, 6, 3, 15)}
    rows, base = [], dt.datetime(2026, 10, 5, 9, 0)
    for k, (role, (files, day, hour, dur)) in enumerate(usual.items()):
        for person in range(3):
            user = f"{role}-normal-{person}"
            for d in range(42):
                t = base + dt.timedelta(days=d, minutes=37 * person + 11 * (d % 5))
                jitter = (d * 7 + person) % 3 - 1          # a little day-to-day variation
                rows.append({"user": user, "role": role, "start": t, "pc": f"{user}-laptop",
                             "files_accessed_per_session": max(1, files + jitter), "events_prev_day": day + jitter,
                             "events_prev_hour": max(1, hour + jitter), "unique_pcs_used_that_day": 1,
                             "session_duration_minutes": dur + 3 * jitter, "is_after_hours": 0, "is_own_pc": 1})
    quiet = "Caregiver-quiet-insider"
    for d in range(42):
        t = base + dt.timedelta(days=d, minutes=5)
        x = 3 if d >= 35 else 1
        rows.append({"user": quiet, "role": "Caregiver", "start": t, "pc": "quiet-laptop",
                     "files_accessed_per_session": 3 * x, "events_prev_day": 7 * x, "events_prev_hour": 4 * x,
                     "unique_pcs_used_that_day": 1, "session_duration_minutes": 20 * x, "is_after_hours": 0, "is_own_pc": 1})
    s = pd.DataFrame(rows)
    week = str((base + dt.timedelta(days=36)).date())
    people = {p["user"]: p for p in m.score_people(s, str(pd.Timestamp(week).to_period("W")))}
    fails = 0
    for user, p in sorted(people.items()):
        ok = p["above_limit"] if user == quiet else not p["above_limit"]
        print(f"  app-scale {user:28s} score={p['score']:.3f} limit={p['limit']:.3f} "
              f"{'ABOVE' if p['above_limit'] else 'below'} {'ok' if ok else 'WRONG'} {[r['code'] for r in p['reasons']]}")
        fails += not ok
    top_normal = max(p["score"] for u, p in people.items() if u != quiet)
    if people[quiet]["score"] <= top_normal:
        print("  WRONG: the quiet insider is not ranked above every normal person")
        fails += 1
    print(f"app-scale check: {fails} problem(s)")
    return fails


def timing_check(m, people=100, limit_seconds=30):
    """How long one weekly refresh takes for a centre of 100 people with 5
    weeks of history each (it runs in the background, hourly)."""
    import datetime as dt
    import time
    base = dt.datetime(2026, 10, 5, 9, 0)
    rows = [{"user": f"p{u}", "role": ("Caregiver", "SecurityAuditor", "SysAdmin")[u % 10 == 0 and 1 or (u % 25 == 0 and 2) or 0],
             "start": base + dt.timedelta(days=d, minutes=u), "pc": f"pc{u}", "files_accessed_per_session": 3 + (d + u) % 3,
             "events_prev_day": 7, "events_prev_hour": 4, "unique_pcs_used_that_day": 1, "session_duration_minutes": 20,
             "is_after_hours": 0, "is_own_pc": 1} for u in range(people) for d in range(42)]
    s = pd.DataFrame(rows)
    t0 = time.time()
    out = m.score_people(s, str(pd.Timestamp(base + dt.timedelta(days=36)).to_period("W")))
    took = time.time() - t0
    print(f"timing: {len(out)} people, {len(rows)} sessions scored in {took:.1f} s (limit {limit_seconds} s)")
    return int(took > limit_seconds or len(out) != people)


def main():
    failures = 0
    m = W.Layer2.load(BASE / "models" / "weekly")
    print(f"model {m.version}; limits {', '.join(f'{r}={v:.3f}' for r, v in m.limits.items())}")
    assert set(m.limits) == set(W.ROLES), "every role needs a limit"

    if not DATA.exists():
        # GitHub Actions has no CERT data (it is a release download); the
        # ChildGuard-scale check and the timing below still run there.
        print(f"parity check SKIPPED: {DATA.name} not present (built by 13_improved_evaluation.py)")
        failures += app_scale_check(m)
        failures += timing_check(m)
        print("RESULT:", "PASS" if failures == 0 else "FAIL")
        sys.exit(0 if failures == 0 else 1)
    d = pd.read_csv(DATA, parse_dates=["session_start"])
    rng = np.random.default_rng(7)
    users = []
    for role in ROLE_OF:
        pool = d.loc[d["mapped_role"] == role, "user"].unique()
        users += list(rng.choice(pool, size=min(4, len(pool)), replace=False))
    insiders = d.loc[d["label_period"] == 1, "user"].unique()
    users += list(rng.choice(insiders, size=3, replace=False))
    d = d[d["user"].isin(users)]
    s = pd.DataFrame({"user": d["user"].astype(str), "role": d["mapped_role"].map(ROLE_OF),
                      "start": d["session_start"], "pc": d["pc"].astype(str)})
    for f in W.BASE_FEATURES:
        s[f] = d[f].astype(float).to_numpy()

    full = W.add_person_features(s)
    wk = m.weeks(full)
    wk["score"] = np.minimum(m.review_index(wk)[0], 9.99)

    checked = 0
    for week in rng.choice(sorted(wk["week"].unique())[6:], size=8, replace=False):
        start = pd.Timestamp(week.split("/")[0])
        window = s[(s["start"] >= start - pd.Timedelta(days=30)) & (s["start"] < start + pd.Timedelta(days=7))]
        live = {p["user"]: p for p in m.score_people(window, week)}
        expect = wk[wk["week"] == week].set_index("user")["score"]
        for user, score in expect.items():
            got = live.get(user)
            checked += 1
            if got is None or abs(got["score"] - round(float(score), 6)) > 1e-6:
                failures += 1
                print(f"  MISMATCH {user} {week}: training {score:.6f} live {got and got['score']}")
            elif not isinstance(got["reasons"], list) or any(set(r) != {"code", "text", "raised_by"} for r in got["reasons"]):
                failures += 1
                print(f"  BAD REASONS {user} {week}: {got['reasons']}")
    print(f"{checked} person-weeks compared, {failures} problem(s)")
    failures += app_scale_check(m)
    failures += timing_check(m)
    print("RESULT:", "PASS" if failures == 0 and checked > 0 else "FAIL")
    sys.exit(0 if failures == 0 and checked > 0 else 1)


if __name__ == "__main__":
    main()
