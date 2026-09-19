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
