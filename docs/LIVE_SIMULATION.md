# Live traffic simulation and threshold calibration

The anomaly models were trained on CERT r4.2: synthetic office workers in
2010. The research results (AUC 0.77 / 0.66 / 0.72) say how well the models
separate CERT insiders from normal CERT sessions. They do not say how the
same models behave on **this app's** users. `backend/scripts/simulate-traffic.js`
measures that, as recommended in the mentorship review (section 06, step 5).

## Method

| | |
|---|---|
| Accounts | 30 caregivers, 5 security auditors, 3 system administrators, plus 7 scripted insiders (dedicated `@childguard-sim.test` accounts, deleted after the run) |
| Period | 14 simulated days. Week 1 (days 1–7) calibrates, week 2 (days 8–14) evaluates |
| Scoring path | Each action goes through the live system's own code: `access_requests` row → `computeFeatures()` → Flask `/score`, with a simulated clock |
| Side effects | None: no emails, no session revocation, no `risk_scores` rows |
| Reproducible | Seeded random numbers (`--seed`); two seeds reported below |

**Normal behaviour.** Caregivers sign in on 55–85% of days, mostly once a
day, in a morning, midday or early-evening slot; 3 of the 30 use the app in
the late evening (19:30–21:00). One in five also uses a phone besides the
laptop. A session holds 1–10 data actions (mostly viewing records, some
submitting records), 1–6 minutes apart. Auditors and administrators work on
weekdays in office hours (2–6 and 1–3 actions per session).

**Insiders** (normal in week 1, attack in week 2):

| Tag | Scenario |
|---|---|
| cg-bulk | Caregiver reads 40 records in about 30 minutes, in usual hours (CERT scenario 2) |
| cg-night | Caregiver reads 6 records at 23:10 (CERT scenario 1) |
| cg-stolen | Stolen password used from an unrecognised device at 15:00, after the owner worked that morning |
| cg-quiet | Quiet insider: reads about twice the usual amount, in usual hours, all week |
| aud-scrape | Auditor: 25 report downloads and audit-log reads in about 40 minutes |
| adm-burst | Administrator: 15 privileged actions in about 20 minutes (CERT scenario 3) |
| adm-night | Administrator: 3 privileged actions at 22:00 on a Saturday |

Every action is scored as if no earlier flag had ended the session, so one
run can be evaluated at any threshold. "Caught at action *n*" means the first
attack action whose score reached the threshold. The report-download limit
(10 per hour) and the consent check are not simulated: this measures the
model alone.

## Results (seeds 42 and 7, run 7 November 2026)

About 1,800–2,000 scored actions per run, two minutes each.

### Normal scores, calibration week

| Role | Actions | Median | 90th pct | 95th pct | Max |
|---|---|---|---|---|---|
| Caregiver | 668 / 585 | 0.32 / 0.31 | 0.81 / 0.84 | 0.94 / 0.92 | 1.00 / 0.98 |
| Security Auditor | 121 / 129 | 0.39 / 0.39 | 0.45 / 0.45 | 0.48 / 0.47 | 0.53 / 0.53 |
| System Administrator | 45 / 62 | 0.30 / 0.32 | 0.34 / 0.35 | 0.34 / 0.35 | 0.35 / 0.35 |

### Evaluation week at the current thresholds

| Role (threshold) | False sign-outs per user per week | Why normal users were flagged | Insiders caught |
|---|---|---|---|
| Caregiver (0.40) | 0.63 / 0.60 (8 and 10 of 30 users) | after hours 33 / 34, new or second device 13 / 7, heavy use 1 / 4 (flagged actions) | 4 of 4 |
| Security Auditor (0.65) | 0 / 0 | – | 1 of 1 (at action 19 / 22) |
| System Administrator (0.60) | 0 / 0 | – | 1 of 2: the night case; **the burst is missed** (highest score 0.56) |

Caregiver insiders were caught at action 8 / 12 (bulk read), at the first
action (night, stolen password) and after 18 / 22 actions (quiet insider,
which scored only 0.42 / 0.41).

### Calibrated thresholds (alert budget: at most 1% of normal week-1 actions)

| Role | Calibrated | Effect in the evaluation week |
|---|---|---|
| Caregiver | none below 1.0 (seed 42) / 0.98 (seed 7) | no false sign-outs, but **no insider caught** |
| Security Auditor | 0.52 / 0.51 | 0 / 0.2 false sign-outs per user per week; insider caught at action 12 / 8 |
| System Administrator | 0.35 / 0.36 | no false sign-outs; **both insiders caught** (burst at action 4) |

## Findings

1. **For caregivers the problem is not the threshold.** Daytime work on the
   usual device is almost never flagged at 0.40 (1–4 flagged actions a
   week across 30 caregivers). The false sign-outs come from two normal
   caregiver habits that look like CERT misuse: **using the app after 20:00**
   (the 3 evening caregivers score 0.87–1.0 after 20:00) and **using a second device**
   such as a phone. No threshold separates these from the night-time and
   stolen-password attacks, because they produce the same feature values.
   Raising the threshold to fit the evening users stops all detection.
2. **The administrator threshold of 0.60 is too high.** Normal administrator
   actions never scored above 0.35, while the burst scored 0.56. Any threshold
   from 0.40 to 0.55 catches both scripted administrator insiders with no
   false sign-outs in either run (only 3 simulated administrators).
3. **The auditor threshold of 0.65 works, but late.** 0.55 catches the
   scrape earlier (at action 14–15 instead of 19–22) with no false
   sign-outs in either run; in the live system the 10-downloads-per-hour
   limit stops it sooner anyway.
4. **The quiet insider is only just caught** (0.41–0.42 against 0.40), two
   days into the week. Volume alone gives a weak signal.

## Recommendations

- **Caregivers:** keep 0.40 for now, but change the features rather than
  the threshold: treat a user's own usual hours as normal (per-user
  baseline instead of a fixed 20:00–06:00 rule), and remember devices a
  caregiver has confirmed with "This was me". Then rerun this simulation.
- **System Administrator:** consider lowering the threshold from 0.60 to
  about 0.50.
- **Security Auditor:** 0.55 would catch scraping earlier at no cost in
  these runs.
- Treat these numbers as directional: the users are simulated, and there
  are only 5 auditors and 3 administrators.

## Running it

From `backend/`, with the ML service running on :5001 (the backend API is
not needed):

```powershell
npm run sim:traffic                 # seed 42, alert budget 1%
npm run sim:traffic -- --seed 7     # another simulated fortnight
npm run sim:traffic -- --budget 0.02 --keep   # 2% budget, keep the simulated rows
```

Results are saved in `backend/test/results/` as `simulation_<time>.json`
(summary, thresholds, false alarms, insiders, threshold sweep) and
`simulation_<time>_actions.csv` (every scored action with its features and
scores).
