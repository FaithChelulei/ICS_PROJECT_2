# ChildGuard — Child Data Security System

Capstone project (Strathmore University, BSc Informatics and Computer
Science): *Child Data Security System Using Encryption, Role-Based Access
Control and Machine Learning Anomaly Detection*. Author: Faith Chelulei
(163446).

ChildGuard stores children's identity details and developmental records
for an early childhood development platform and protects them with three
layers that act on every request:

1. **Encryption with data separation.** Identity fields and developmental
   records sit in separate tables, each value encrypted with AES-256-GCM.
   Data keys carry a key id (so they can be rotated) and are wrapped by a
   master key in Azure Key Vault.
2. **Role-based access control with consent enforcement.** Three roles
   (Caregiver, Security Auditor, SysAdmin), a permission map on every
   route, PostgreSQL row-level security so a caregiver only reaches their
   own children, and a consent check before any record is released.
3. **Machine learning anomaly detection.** Every data action is scored by
   a per-role Isolation Forest + Autoencoder trained on the CERT Insider
   Threat Dataset r4.2. A flagged action ends the session, emails the
   account owner "This was me / This was NOT me" links and puts the
   session in the Security Auditor's queue.

All roles sign in with a password and a one-time code sent by email.

## Repository layout

```
ml/
  data/                 CERT r4.2 files (raw logon/file/device CSVs not in git)
  data/processed/       sessions_features.csv (~470k sessions, 7 features)
  scripts/              01 preprocess -> 02 train -> 03 demo; 04-11 diagnostics
  models/               per-role scaler, Isolation Forest, Autoencoder, thresholds
  service/app.py        Flask scoring service (:5001, /score and /health)
backend/                Node/Express API (:4000, HTTPS, TLS 1.3 only)
  db/                   schema.sql, migration_*.sql, seed.js
  src/                  routes, controllers, services, middleware, utils
  scripts/              certificate, encryption-key, key-vault and retention tools
  test/                 unit, API, performance, anomaly-injection and penetration tests
frontend/               React + Vite (:5173) pages for the three roles
docs/RISK_THRESHOLDS.md research thresholds vs. thresholds used in the live app
```

## Requirements

- Python 3.10+ (developed on 3.13) and Git
- Node.js (developed on version 24)
- PostgreSQL 17
- Optional: Azure CLI (`az login`) if the data keys are wrapped in Azure Key Vault

## Setup (first time)

**1. Python environment** (from the repo root)

```
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

(`.venv\Scripts\activate.bat` on cmd, `source .venv/bin/activate` on Mac/Linux.)

**2. Database.** Create the database and the restricted account the
backend connects as, then apply the schema and the migrations in this
order (as the `postgres` owner). Messages saying an object already exists
are harmless: `schema.sql` already contains some of the later tables.

```
psql -U postgres -c "CREATE DATABASE ics_project_2;"
psql -U postgres -c "CREATE ROLE app_user LOGIN PASSWORD 'choose-a-password';"
cd backend\db
psql -U postgres -d ics_project_2 -f schema.sql
psql -U postgres -d ics_project_2 -f migration_registration.sql
psql -U postgres -d ics_project_2 -f migration_risk_scoring.sql
psql -U postgres -d ics_project_2 -f migration_username.sql
psql -U postgres -d ics_project_2 -f migration_rls.sql
psql -U postgres -d ics_project_2 -f migration_kdpa.sql
```

Then give `app_user` its rights. It may read and add audit entries but
never change or delete them:

```
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;
REVOKE UPDATE, DELETE ON audit_log FROM app_user;
```

**3. Backend.** In `backend/`: `npm install`, copy `.env.example` to
`.env` and fill it in (`DATABASE_URL` uses `app_user`), then:

- `npm run cert:new` creates a local TLS certificate in `backend/certs/`
  (gitignored), and `npm run cert:trust` adds it to your Windows user's
  trusted certificates (click **Yes** on the prompt). Firefox keeps its
  own store, so use Chrome/Edge or accept the certificate manually.
- `npm run key:new` creates a data encryption key.
- `node db\seed.js` creates one demo account per role. Their password is
  `DEMO_ACCOUNT_PASSWORD` from `.env`; it is never stored in the code.

**4. Frontend.** In `frontend/`: `npm install`.

## Running the system

Three services, each in its own terminal, started in this order:

| # | Service | Command (from the repo root) | Ready when you see |
|---|---|---|---|
| 1 | ML risk service (Flask, :5001) | `.venv\Scripts\python.exe ml\service\app.py` | `Running on http://127.0.0.1:5001` |
| 2 | Backend API (Express, :4000) | `cd backend` then `npm run dev` | `Backend listening on https://localhost:4000` |
| 3 | Frontend (React/Vite, :5173) | `cd frontend` then `npm run dev` | `Local: https://localhost:5173/` |

Browser ↔ backend traffic is HTTPS with TLS 1.3 only. The backend → ML
service hop stays plain HTTP because it never leaves the machine
(loopback only). If the ML service is down, actions still go through and
are logged without a score.

## Tests

In `backend/`, with all three services running for every test except
`npm test`:

| Command | What it checks |
|---|---|
| `npm test` | Unit tests: encryption, key vault wrapping (stand-in vault), CSV/PDF report formats |
| `npm run test:api` | End-to-end API checks: roles, consent, row-level security, archiving, retention, reports, risk flagging, breach decisions (dedicated test accounts, non-destructive) |
| `npm run test:perf` | Response time of access decisions against the < 1 second requirement |
| `npm run test:anomaly` | Ten insider and normal-use scenarios acted out against the live system |
| `npm run test:pen` | Penetration-style attacks on identity, passwords, roles, other families' data, consent, injection and transport |
| `test\manual_test.ps1`, `test\full_flow_test.ps1` | Interactive walk-throughs with real emailed one-time codes |

Performance, anomaly and penetration results are saved as JSON in
`backend/test/results/` (gitignored).

## Encryption keys

`npm run key:status`, `key:verify`, `key:new` and `key:reencrypt` in
`backend/` (see `backend/.env.example`). Keys are stored wrapped by a
master key in Azure Key Vault (`KEY_VAULT_URL`, `KEY_VAULT_KEY_NAME`):
`npm run key:wrap` moves plain keys under it and `key:check` proves this
machine can unlock them. Sign in with `az login` first, or the backend
will refuse to start. Without those two settings, plain keys in `.env`
still work for local development.

## Data protection features

Opt-in consent per scope (identity consent is required and cannot be
withdrawn), correction of a child's details, archive and restore (an
archived profile is frozen by the database), anonymisation after the
retention period (`npm run retention:status` / `retention:apply`,
`RETENTION_DAYS`, default 365), privacy-notice versions recorded at
registration, and breach decisions against a 72-hour window for the
Security Auditor. Auditor reports (audit log, flagged sessions, consent
activity) download as CSV or PDF, at most `REPORT_EXPORTS_PER_HOUR`
(default 10) per hour.

## ML pipeline

```
python ml\scripts\03_run_inference_demo.py
```

Loads the trained models and scores every session, printing how many were
flagged and how many real malicious sessions were caught per role. Takes
under a minute; no training happens.

```
python ml\scripts\02_train_models.py
```

Retrains all 6 models from `ml\data\processed\sessions_features.csv`
(included) and overwrites `ml\models\`. `logon.csv`, `file.csv` and
`device.csv` are not in git (`file.csv` alone is ~193 MB, over GitHub's
limit) and are only needed to rerun `01_preprocess.py` from the raw logs.
`ml\scripts\04`–`11` are diagnostic scripts used to test design decisions
(feature selection, threshold behaviour); they are not part of the main
pipeline (01 → 02 → 03).

Risk thresholds (research vs. live app): `docs/RISK_THRESHOLDS.md`.

## Known limitations

- The models were trained on CERT r4.2, synthetic office-worker data, not
  caregiver activity. The live thresholds were calibrated on scripted app
  sessions and need recalibrating on real use.
- The research thresholds were chosen on the test set, and the test set's
  share of malicious sessions is higher than in the full data.
- In progress: on-screen management of risk thresholds, user roles and
  system settings (issue #20).
