# Risk thresholds: research vs. deployment

`ml/models/risk_tiers.json` holds two thresholds per role.

| Role | `review_threshold` (research) | `deployment_threshold` (live app) | Live scoring |
|---|---|---|---|
| Caregiver | 0.110 | 0.350 | on |
| SecurityAuditor | 0.310 | *(not set)* | wired, held at log-only |
| SysAdmin | 0.220 | 0.600 | on |

The Flask service (`ml/service/app.py`) uses `deployment_threshold` when it is
set and falls back to `review_threshold` otherwise. Changing either needs a
restart of the ML service (it reads the file once at start-up).

## Why two numbers

**`review_threshold`** is the value chosen on the CERT r4.2 held-out test
set. Its precision/recall (also in `risk_tiers.json`) are the figures for the
evaluation chapter. They describe how well the models separate CERT insider
sessions from normal CERT sessions.

**`deployment_threshold`** is what the running web app enforces. The live
system feeds the same 7 features from its own activity, but its usage
pattern is different from CERT's: most normal CERT sessions touch 0–1
files, while a caregiver or admin doing ordinary work in this app performs
several data actions a day. At the research thresholds that ordinary work
sits in CERT's tail and was being logged out constantly (a SysAdmin's very
first approval scored 0.30 against a 0.22 threshold). The deployment values
were calibrated by scoring realistic sessions from this app through the
trained models:

| Scenario (live features) | Caregiver | SecurityAuditor | SysAdmin |
|---|---|---|---|
| First action of the day | 0.19 | 0.28 | 0.30 |
| Normal working session | 0.33–0.34 | 0.40–0.53 | 0.38–0.49 |
| Heavy but legitimate day | 0.41–0.45 | 0.60–0.71 | 0.49 |
| Burst (20–40 data actions in 5–30 min) | 0.45–0.55 | 0.71–1.00 | 0.70–1.00 |
| Mass access (60–100 actions) | 0.82 | 1.00 | 1.00 |
| Any activity 20:00–06:00 | 0.93–1.00 | 0.98–1.00 | 0.79–0.99 |
| Data action from an unrecognised device | 0.42–0.83 | 0.53–0.55 | 0.26–0.28 |

## What the live system therefore catches

- **Activity outside 06:00–20:00** — the model learned that normal CERT
  users don't work then (insider scenario 1 in CERT is exactly this). Any
  data action at night is flagged for every role. *Demo during the day, or
  expect to be signed out.*
- **Bursts / mass access** of child records, approvals or unlocks.
- **A data action from a browser this account hasn't used before**
  (Caregiver). Each browser gets a device id (`X-Device-Name`); the first
  session on a new one is flagged once, the owner clicks "This was me", and
  that browser is trusted afterwards.

## Honest limitation (say this in the defence)

At the deployment thresholds, recall on the **CERT test set** would be far
lower than the research figures (see `ml/scripts/ptx_log.txt`: Caregiver
recall is 66% at 0.10 but ~4% at 0.30). The two thresholds answer different
questions: the research one measures the model on CERT; the deployment one
is a usability calibration for this app's own traffic, where the patterns
above score far higher than subtle CERT insiders do. A real deployment
would re-train on the organisation's own activity logs so both converge.

## SecurityAuditor: pending decision

Auditor actions (reading the audit log, reviewing flags) call the scorer,
but `backend/src/services/actionScoring.js` keeps the role log-only because
at 0.31 an auditor is logged out after 2–3 normal actions. From the table,
**0.80** passes every normal auditor session and still flags bursts, mass
scraping and night-time use. To enable it: add
`"deployment_threshold": 0.800` to `SecurityAuditor` in `risk_tiers.json`,
add `'SecurityAuditor'` to `ROLES_SCORED_LIVE` in `actionScoring.js`, and
restart the ML service and backend.
