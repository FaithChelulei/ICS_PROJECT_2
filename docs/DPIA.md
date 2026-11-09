# Data protection impact assessment (DPIA) and threat model

ChildGuard, November 2026. Prepared by Faith Chelulei Cherop for the
Strathmore ICS Project II submission.

**Status.** ChildGuard is a prototype and holds made-up data only. The Kenya
Data Protection Act 2019 (s.31) requires a DPIA before processing that is
likely to be high risk, and this processing is: it concerns children, it
includes health and family details, and it monitors staff behaviour
automatically. This document is that assessment for the system as built.
A centre deploying it must review it with its own data protection officer,
and consult the Office of the Data Protection Commissioner if a high risk
remains. Section numbers refer to the Act.

## 1. What is processed, and why

| Data | Whose | Why | Protection | Kept for |
|---|---|---|---|---|
| Name, date of birth, family background | Child | Identify the child to their own caregiver | AES-256-GCM per field, separate table from records, row-level security (caregiver's own children only), key wrapped by Azure Key Vault | Until archived + retention period (365 days by default), then anonymised |
| Developmental and health records | Child | The service itself | As above; only with the caregiver's opt-in consent for this scope, checked on every request | As above; kept after anonymisation, linked only to a profile number |
| Consent grants and withdrawals | Child, caregiver | Prove consent (s.32, s.33) | Append-only history | With the profile |
| Name, email, username, role, password hash | Staff and caregivers | Run accounts | bcrypt hashes, emailed sign-in codes, step-up password for dangerous actions | While the account exists |
| Every action: who, what, which profile number, browser id, IP address, time | Staff and caregivers | Detect misuse (s.41 security safeguards) | Readable only by the Security Auditor; the app's database account cannot change or delete the audit log | **No limit yet (see gap G1)** |
| Risk scores, the 7 features behind each, model version | Staff and caregivers | Explain and review each flag | As above | **No limit yet (G1)** |

Children's health and family details are sensitive personal data. The
system never shows a child's name to the auditor or the administrator.

## 2. Lawful basis and necessity

- **Children's data:** consent of the parent or caregiver, recorded per
  scope (s.30, s.32, s.33). Identity is required while a profile exists;
  health and development records are optional and can be withdrawn.
- **Account and activity data:** needed to keep the children's data secure
  (s.41). Monitoring is limited to actions inside ChildGuard; nothing
  outside the system is collected.
- **Transparency (s.29):** a short notice with a tick box is shown before
  any account request or child registration, and the version accepted is
  stored. Since version 2026-11 the account notice also says that activity
  is checked automatically, that this can sign the person out, and that a
  person reviews every alert (s.35).
- **Minimisation:** the browser id is random, not a device fingerprint; the
  audit log names corrected fields but never their values; reports and the
  auditor's screens carry profile numbers, never names.

## 3. Risks to people, measures, and what remains

| # | Risk | Measures in the system | Residual |
|---|---|---|---|
| R1 | A staff member misuses legitimate access to children's data | Role permissions, ownership check, row-level security in PostgreSQL, consent check, every action scored by the anomaly models, refused attempts logged, auditor review | Medium: subtle misuse is hard to detect (docs/MODEL_EVALUATION_VALIDATED.md) |
| R2 | The database or a backup is stolen | Field encryption; the data key is wrapped by a master key that never leaves Azure Key Vault; every unwrap is logged by Azure | Low |
| R3 | Data kept longer than needed (s.39) | Archive, then anonymise identity after the retention period, set by the administrator | Medium until G1 is closed |
| R4 | Unfair automated decisions about staff (s.35) | The automatic step is reversible (sign-out plus an email asking "was this you?"); locking happens only if the owner says "not me"; breach decisions are made by the auditor; the queue shows what raised each score; notice updated | Medium: false sign-outs happen and can feel accusatory |
| R5 | An email scanner acts on an alert link | Links open a page; only its button acts | Low |
| R6 | Account takeover | Emailed sign-in code (signed challenge, 5 tries), password change on first sign-in, step-up password for dangerous actions, rate limits, new-device detection for caregivers | Low to medium: the browser id is set by the client (G4) |
| R7 | A breach is not assessed in time (s.43) | Escalated and "not me" flags need a breach decision, with a 72-hour timer on screen | Medium: notifying the Commissioner is a manual step outside the system |
| R8 | Someone with the database owner account bypasses the controls | The app connects as a restricted account that cannot bypass row-level security or edit the audit log | Medium: needs separation of duties in deployment (G3) |
| R9 | Personal data leaves Kenya | Only the key-encryption operation happens in Azure (South Africa North); no personal data is sent there | Low |

## 4. Threat model (STRIDE)

| Threat | Example | Main control | Tested by |
|---|---|---|---|
| Spoofing | Stolen password used elsewhere | Sign-in code, new-device scoring, session revocation | Penetration groups 1 and 2, anomaly scenario 2 |
| Tampering | Changing records or the audit log | Ownership + row-level security; app account has no UPDATE/DELETE on the audit log; GCM authentication tags | API test, penetration group 4 |
| Repudiation | "I never opened that file" | Append-only audit log linked to each risk score | API test |
| Information disclosure | Reading another family's child; mass reading | Ownership, row-level security, scoring before any record is sent, report download limit | Penetration groups 3 to 5, anomaly scenarios 1, 3 and 4 |
| Denial of service | Password guessing, flooding | Rate limits on sign-in, codes, step-up and reports; request size limit | Penetration groups 2 and 6 |
| Elevation of privilege | Caregiver acting as admin | Role permissions on every route; roles changed only by an admin with a password and a reason, never their own | Penetration group 3, API test |

## 5. Gaps to close before real use

- **G1. Retention for monitoring data.** Activity records, risk scores and
  the audit log are kept without limit. Set a period (for example two
  years, or the centre's policy), then delete or aggregate older entries.
- **G2. Real-use calibration.** Thresholds were calibrated on scripted and
  simulated traffic; measure false sign-outs with real staff before
  relying on them, and tell staff how to respond to an alert.
- **G3. Separation of duties.** The database owner password and the Azure
  role that can delete the master key should sit with someone other than
  the application administrator; turn on Key Vault soft-delete and purge
  protection.
- **G4. Device identity.** The browser id is a header the client sets. A
  stronger signal (a signed, server-issued device cookie) would make the
  new-device check harder to defeat.
- **G5. Fail-open scoring.** If the ML service is down, actions are logged
  but not scored. Add an alert so an administrator notices.
- **G6. Data subject requests.** Correction, archive and consent withdrawal
  are built in; access and export requests are handled manually.

## 6. Review

To be reviewed by the deploying centre's data protection officer before any
real child data is entered, and again whenever the models, thresholds or
data collected change.
