# Child Data Security System — ML Anomaly Detection

Insider-threat anomaly detection component of a capstone project
("Child Data Security System Using Encryption, Role-Based Access
Control and Machine Learning Anomaly Detection"), built on the CERT
Insider Threat Dataset r4.2. Trains an Isolation Forest + Autoencoder
pair per system role (Caregiver, Security Auditor, SysAdmin) to score
sessions for anomalous behaviour.

## Setup

Requires Python 3.10+ and Git.

```
git clone <repo URL>
cd ICS_PROJECT_2
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

(Use `.venv\Scripts\activate.bat` on cmd, or `source .venv/bin/activate`
on Mac/Linux.)

## Run the demo

```
python ml\scripts\03_run_inference_demo.py
```

Loads the already-trained models and scores every session, printing how
many were flagged and how many real malicious sessions were caught per
role. Takes under a minute; no training happens.

## Retrain (optional)

```
python ml\scripts\02_train_models.py
```

Retrains all 6 models from `ml\data\processed\sessions_features.csv`
(included) and overwrites `ml\models\`.

## Data

The 5 CSVs used (`ml\data\`: logon, file, device, ldap, insiders) and
the processed feature table are included. `logon.csv`, `file.csv`, and
`device.csv` are excluded from git — `file.csv` alone is ~193MB, over
GitHub's limit — and are only needed to rerun `01_preprocess.py` from
raw logs.

## Other scripts

`ml\scripts\04`–`11` are diagnostic scripts used to test design
decisions during development (feature selection, threshold behaviour).
Not part of the main pipeline (01 → 02 → 03); kept for reference.

## Running the full web system

Three services, each in its own terminal, started in this order. Needs
PostgreSQL 17 running with the `ics_project_2` database (`backend/db/schema.sql`
plus the `migration_*.sql` files applied) and `backend/.env` filled in from
`backend/.env.example`.

| # | Service | Command (from the repo root) | Ready when you see |
|---|---|---|---|
| 1 | ML risk service (Flask, :5001) | `.venv\Scripts\python.exe ml\service\app.py` | `Running on http://127.0.0.1:5001` |
| 2 | Backend API (Express, :4000) | `cd backend` then `npm run dev` | `Backend listening on http://localhost:4000` |
| 3 | Frontend (React/Vite, :5173) | `cd frontend` then `npm run dev` | `Local: http://localhost:5173/` |

First time only: `npm install` in both `backend` and `frontend`.

Checks: `npm test` (encryption unit tests) and `npm run test:api` (47
end-to-end API checks against the running backend + ML service, using
dedicated test accounts; non-destructive) in `backend/`.

Encryption keys: `npm run key:status`, `key:verify`, `key:new`,
`key:reencrypt` in `backend/` (see `backend/.env.example`).

Risk thresholds (research vs. live app): `docs/RISK_THRESHOLDS.md`.
