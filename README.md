# Child Data Security System — ML Anomaly Detection

Insider-threat anomaly detection component of Faith Chelulei's (163446)
capstone project, *"Child Data Security System Using Encryption,
Role-Based Access Control and Machine Learning Anomaly Detection."*
Built on the CERT Insider Threat Dataset r4.2. Trains one Isolation
Forest + Autoencoder pair per system role (Caregiver, Security Auditor,
SysAdmin) and scores sessions for anomalous behaviour.

A line-by-line explanation of every script (`CODE_EXPLAINED.docx`) and
the full write-up of the feature/threshold/tier design are kept
separately from this repository — ask for them if you'd like to see
them alongside the code.

## What's included here vs. not

This repository is the **code + data** side only. Write-ups, diagrams,
slides, the proposal, the line-by-line code explanation, and the
original full CERT dataset download are all kept outside this
repository — ask for them separately if you need them.

Included: the 5 CSVs actually used (`ml/data/logon.csv`, `file.csv`,
`device.csv`, `ldap.csv`, `insiders.csv`), the engineered feature table
(`ml/data/processed/sessions_features.csv`), all trained models
(`ml/models/`), and all pipeline/diagnostic scripts (`ml/scripts/`).

**Note:** `logon.csv`, `file.csv`, and `device.csv` are excluded from
git itself (see `.gitignore`) — `file.csv` alone is ~193MB, over
GitHub's 100MB per-file limit, and none of the three are needed to run
the already-trained models. They stay on this machine in `ml/data/` and
are only needed if you want to rerun `01_preprocess.py` from scratch.

## How to run this on another machine

### 1. Prerequisites

- Python 3.13 (any recent Python 3.10+ should work)
- Git

### 2. Clone and set up

```
git clone <the GitHub URL you'll get after pushing>
cd ICS_PROJECT_2
python -m venv .venv
```

Activate the virtual environment:
- Windows (PowerShell): `.venv\Scripts\Activate.ps1`
- Windows (cmd): `.venv\Scripts\activate.bat`
- Mac/Linux: `source .venv/bin/activate`

Then install dependencies:

```
pip install -r requirements.txt
```

### 3. See it work (no training needed — models are already trained)

```
python ml\scripts\03_run_inference_demo.py
```

This loads the already-trained models for all 3 roles and scores every
real session, printing how many were flagged and how many real
(ground-truth) malicious sessions were caught per role. It finishes in
under a minute and produces identical numbers every time it's run
(nothing is retrained or randomized at this stage).

### 4. (Optional) Retrain the models from scratch

Only needed if you want to reproduce the training itself, not just see
the result:

```
python ml\scripts\02_train_models.py
```

This retrains all 6 models (Isolation Forest + Autoencoder for each of
the 3 roles) using `ml\data\processed\sessions_features.csv`, which is
already included, and overwrites the files in `ml\models\`.

### 5. (Optional) Regenerate the feature table from raw logs

Only possible if you also have the raw CERT log files
(`logon.csv`, `file.csv`, `device.csv`) — these are excluded from this
repo due to size (see above). If you have them, place them in
`ml\data\` and run:

```
python ml\scripts\01_preprocess.py
```

### 6. What the other scripts are

`ml\scripts\04` through `11` (plus `check_role_mapping.py`,
`diagnose.py`) are diagnostic/evidence scripts written during
development to test specific design decisions (feature selection,
threshold behaviour, the device.csv question). They aren't part of the
"official" pipeline (that's just 01 → 02 → 03) but are kept for
transparency — their output logs (`*_log.txt`) are the evidence behind
the final feature/threshold decisions.

## Project structure, features, models, and the final design decisions

The folder layout, the 7 finalized features and why each was chosen,
the model architecture, training process, results per role, and the
final threshold/risk-tier response design are documented separately
from this repository — ask for that write-up if you'd like the full
detail behind what's here.
