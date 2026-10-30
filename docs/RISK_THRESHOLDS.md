# Risk thresholds: research vs. deployment

`ml/models/risk_tiers.json` holds two thresholds per role.

| Role | `review_threshold` (research) | `deployment_threshold` (live app) | Live scoring |
|---|---|---|---|
| Caregiver | 0.110 | 0.400 | on |
| SecurityAuditor | 0.310 | 0.650 | on (plus 10 report downloads/hour cap) |
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

### Caregiver raised from 0.35 to 0.40 (2026-10-30)

At 0.35 caregivers were still being logged out during ordinary work. Two
causes were found and fixed together:

1. **Inflated activity counts (bug).** The children list that loads on every
   Dashboard / Consent / Child Record page was logged as
   `view_own_child_records`, so plain navigation counted as record reads in
   `files_accessed_per_session`; React StrictMode also fired each list load
   twice. The list is now logged as `list_own_children` (an event, not a
   file) and the frontend shares in-flight GET requests.
2. **Threshold too tight (calibration).** Even with correct counts, clean
   caregiver work crosses 0.35 after about five real data actions
   (registering a child, viewing or submitting records):

   | Real data actions | Within 30 min | Over 2 hours |
   |---|---|---|
   | 1 | 0.27 | 0.21 |
   | 3 | 0.34 | 0.29 |
   | 5 | 0.36 | 0.33 |
   | 6 | 0.37 | 0.35 |
   | 10 | 0.40 | 0.39 |
   | 15 | 0.43 | 0.42 |

3. **Why 0.40, not higher.** 0.45 was tried first and gave caregivers more
   room, but it stopped catching the most important new-device case: a
   stolen password used on another browser *while the real caregiver has
   already worked on their usual device that day* (2 devices in a day, the
   new one unrecognised):

   | New-device scenario | Score |
   |---|---|
   | First activity of the day, on a new browser | 0.80 |
   | After the usual device was used today | 0.43 |
   | Same, mid-morning (5 actions, 60 min in) | 0.45 |

   0.40 catches all three, plus after-hours activity (0.93+), mass access
   (0.82) and bursts (0.45–0.55), while a caregiver can still do about 8
   data actions in 30 minutes, or 10 spread over a couple of hours, without
   interruption. Trade-off accepted: a caregiver doing more than that in one
   sitting gets a "was this you?" email and a re-login, which is
   reversible and costs seconds.

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

## SecurityAuditor: scored live at 0.65 (2026-10-30)

At the research threshold (0.31) an auditor was logged out after 2–3 normal
actions, so the role was held at log-only. An earlier note proposed 0.80.
Re-scoring realistic auditor sessions, now that auditors also download
reports and record breach decisions, showed 0.80 would miss a 20-report
scrape, so the role was calibrated again:

| Auditor scenario (live features) | Score |
|---|---|
| First action of the day | 0.26 |
| Normal triage, 3 reviews in 20 min | 0.38 |
| 5 reviews + 1 report over 1 h | 0.45 |
| Busy morning, 10 actions over 3 h | 0.51 |
| Incident day, 12 actions in 1 h | 0.57 |
| Heavy day, 15 actions over 4 h | 0.61 |
| Very heavy day, 20 actions over 6 h | 0.68 |
| **Scrape: 12 exports in 5 min** | 0.54 |
| **Scrape: 15 exports in 10 min** | 0.61 |
| **Scrape: 20 exports in 10 min** | 0.76 |
| **Mass export, 40 in 15 min** | 1.00 |
| **2 actions at 23:00** | 0.93 |
| **New device after own device used today** | 0.53 |

There is no clean cut: heavy legitimate days (0.57–0.68) overlap small
scrapes (0.54–0.61). The chosen design uses **two controls**:

1. **`deployment_threshold` 0.65** passes every normal, busy and incident
   day (up to 15 actions over 4 h) and catches large scrapes, mass export
   and any night-time use. Only an exceptionally heavy day (20+ actions)
   gets a "was this you?" and a re-login.
2. **A hard limit of 10 report downloads per hour per auditor**
   (`REPORT_EXPORTS_PER_HOUR`, `backend/src/routes/auditorRoutes.js`) for
   the small, slow scrapes the model can't separate from real work. Hitting
   it returns 429 and writes `report_export_rate_limited` to the audit log.

In the automated test suite (about 10 auditor actions in under 2 minutes)
the test auditor peaks at 0.46. **Not caught:** an auditor working from a
new device (0.45–0.53), the same limitation SysAdmin has. Auditors cannot
see child identities or records at all (row-level security), which limits
what a compromised auditor account could take.
