// Child profile + developmental record endpoints. This is where the
// encryption util (AES-256-GCM) and the RBAC permission checks actually
// get exercised against real data, not just sitting unused.
//
// Two layers of access control on every route below:
//   1. requirePermission(...) in the route — does this ROLE do this at all?
//   2. the ownership check inside each handler — does this SPECIFIC
//      caregiver own THIS SPECIFIC child? A Caregiver role check alone
//      would let any caregiver read any other caregiver's child data —
//      the ownership check is what actually prevents that.
const db = require('../config/db');
const { encryptField, decryptField } = require('../utils/encryption');
const { logAction } = require('../utils/auditLog');
const { recordAndScore, logAccessRequest } = require('../services/riskEngine');
const { getPcName, getIpAddress } = require('../utils/requestMeta');
const { hasConsent } = require('../services/consent');
const { checkPrivacyNotice, PRIVACY_NOTICE_VERSION } = require('../services/privacyNotice');

const RISK_NOTICE = 'Unusual activity detected during this action. You have been logged out as a precaution — check your email to confirm or report it.';

// Shared by every handler below: logs this action to access_requests and
// scores it. If it crosses this role's review_threshold, the session has
// already been revoked by the time this returns -- the handler still
// returns its normal success response (the action itself already
// happened), but adds a riskNotice so the caller knows to expect a 401 on
// its next request.
async function scoreAction(req, actionType, childProfileId = null) {
  return recordAndScore({
    userId: req.user.id,
    role: req.user.role,
    actionType,
    childProfileId,
    pcName: getPcName(req),
    ipAddress: getIpAddress(req),
    sessionId: req.user.sessionId,
  });
}

// listMyChildren fires automatically on every dashboard load, the instant
// a caregiver logs in -- before they've done anything. Scoring it hits the
// exact same problem riskEngine.js already documents for login itself:
// the live feature vector is near-empty (~0 session duration, ~0 events),
// which doesn't resemble ANY completed training session, so it reads as
// maximally anomalous almost every time regardless of role -- not a 20%
// false-positive rate, closer to 100%. That's what was logging caregivers
// out before they could do anything. Treat it the same way login is
// treated: logged for the audit trail and for feature computation, not
// scored. The genuinely scoreable moments -- viewing a SPECIFIC child's
// records, submitting a record, registering a child -- are unchanged below.
async function logOnlyAction(req, actionType, childProfileId = null) {
  return logAccessRequest({
    userId: req.user.id,
    actionType,
    childProfileId,
    pcName: getPcName(req),
    ipAddress: getIpAddress(req),
    sessionId: req.user.sessionId,
  });
}

// Throws-and-is-caught-by-caller style helper: confirms child_profile_id
// belongs to this caregiver, or returns null if not found / not theirs.
// Also returns the archive state, for refuseIfArchived below.
async function findOwnChildProfile(childProfileId, caregiverId) {
  const { rows } = await db.query(
    'SELECT id, archived_at, identity_anonymised_at FROM child_profiles WHERE id = $1 AND caregiver_id = $2',
    [childProfileId, caregiverId]
  );
  return rows[0] || null;
}

// An archived profile is restricted (KDPA s.40(3)): kept as evidence but no
// longer processed -- no records viewed or added, no corrections, no
// consent changes. The database's row-level security enforces the same
// freeze; this gives the caller a clear reason instead of a bare failure.
// Returns true if it already sent the 409.
function refuseIfArchived(res, profile) {
  if (!profile.archived_at) return false;
  res.status(409).json({
    error: 'This child profile is archived. Its data is kept but can’t be viewed or changed. Restore it first to continue.',
    code: 'PROFILE_ARCHIVED',
  });
  return true;
}

// The consent step of the request pipeline: runs after the role and
// ownership checks and BEFORE any record is read, written or scored. A
// refusal is written to the audit log (a caregiver whose consent is off is
// not an anomaly to score, but the blocked attempt is still evidence the
// enforcement works). Returns true if it already sent the 403.
async function denyWithoutRecordsConsent(req, res, childProfileId, attemptedAction) {
  if (await hasConsent(childProfileId, 'developmental_records')) return false;

  await logAction({
    userId: req.user.id,
    action: 'access_denied_no_consent',
    detail: `child_profile_id=${childProfileId}, scope=developmental_records, attempted=${attemptedAction}`,
  });
  res.status(403).json({
    error: 'Consent for developmental & health records has not been granted for this child. Grant it in Consent Management to view or add records.',
    code: 'CONSENT_REQUIRED',
    scope: 'developmental_records',
  });
  return true;
}

// POST /children — a Caregiver registers a child profile under their own
// account. Identity fields are encrypted before they ever reach the DB.
// developmentalRecordsConsent (optional boolean) lets the caregiver opt in
// to records at registration instead of a separate trip to Consent
// Management; leaving it out means not granted (opt-in).
async function createChildProfile(req, res) {
  const { fullName, dateOfBirth, familyBackground, developmentalRecordsConsent } = req.body;
  if (!fullName || !dateOfBirth) {
    return res.status(400).json({ error: 'fullName and dateOfBirth are required' });
  }
  if (developmentalRecordsConsent !== undefined && typeof developmentalRecordsConsent !== 'boolean') {
    return res.status(400).json({ error: 'developmentalRecordsConsent must be a boolean' });
  }
  const noticeError = checkPrivacyNotice(req.body);
  if (noticeError) {
    return res.status(400).json({ error: noticeError, code: 'PRIVACY_NOTICE_REQUIRED' });
  }
  // A child can't have been born after today -- checked server-side too,
  // not just as a UI date-picker limit, since the API is reachable
  // directly.
  const dob = new Date(dateOfBirth);
  if (Number.isNaN(dob.getTime()) || dob > new Date()) {
    return res.status(400).json({ error: 'Date of birth cannot be in the future' });
  }

  try {
    // db.transaction applies the caregiver's identity, so the row-level
    // security policies allow these inserts only for their own child.
    const { childProfileId, createdAt } = await db.transaction(async (client) => {
      const { rows } = await client.query(
        'INSERT INTO child_profiles (caregiver_id, privacy_notice_version) VALUES ($1, $2) RETURNING id, created_at',
        [req.user.id, PRIVACY_NOTICE_VERSION]
      );
      const id = rows[0].id;

      await client.query(
        `INSERT INTO child_identifiers
           (child_profile_id, full_name_enc, date_of_birth_enc, family_background_enc)
         VALUES ($1, $2, $3, $4)`,
        [
          id,
          encryptField(fullName),
          encryptField(dateOfBirth),
          familyBackground ? encryptField(familyBackground) : null,
        ]
      );

      // Registering a child is itself the consenting act for storing their
      // identity -- record it as the first real row in consent_records
      // (previously defined in the schema but never written to).
      await client.query(
        `INSERT INTO consent_records (child_profile_id, caregiver_id, consent_given, scope)
         VALUES ($1, $2, TRUE, 'profile_identity')`,
        [id, req.user.id]
      );
      if (developmentalRecordsConsent) {
        await client.query(
          `INSERT INTO consent_records (child_profile_id, caregiver_id, consent_given, scope)
           VALUES ($1, $2, TRUE, 'developmental_records')`,
          [id, req.user.id]
        );
      }
      return { childProfileId: id, createdAt: rows[0].created_at };
    });

    await logAction({
      userId: req.user.id,
      action: 'create_child_profile',
      detail: `Created child_profile_id=${childProfileId}`,
    });
    if (developmentalRecordsConsent) {
      await logAction({
        userId: req.user.id,
        action: 'consent_granted',
        detail: `child_profile_id=${childProfileId}, scope=developmental_records`,
      });
    }

    const risk = await scoreAction(req, 'create_child_profile', childProfileId);
    res.status(201).json({
      childProfileId,
      createdAt,
      ...(risk.flagged ? { riskNotice: RISK_NOTICE } : {}),
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create child profile' });
  }
}

// PATCH /children/:childProfileId — correct a child's identity details
// (KDPA s.26(d): the right to correction of false or misleading data).
// Only the fields sent are changed. The audit log records WHICH fields were
// corrected, never their old or new values -- writing a child's name into
// the audit log in plain text would undo the encryption that protects it.
const CORRECTABLE_FIELDS = {
  fullName: 'full_name_enc',
  dateOfBirth: 'date_of_birth_enc',
  familyBackground: 'family_background_enc',
};

async function updateChildDetails(req, res) {
  const childProfileId = Number(req.params.childProfileId);
  const fields = Object.keys(CORRECTABLE_FIELDS).filter((f) => req.body[f] !== undefined);
  if (fields.length === 0) {
    return res.status(400).json({ error: `Send at least one of: ${Object.keys(CORRECTABLE_FIELDS).join(', ')}` });
  }
  const { fullName, dateOfBirth, familyBackground } = req.body;
  if (fullName !== undefined && (typeof fullName !== 'string' || !fullName.trim())) {
    return res.status(400).json({ error: 'fullName cannot be empty' });
  }
  if (dateOfBirth !== undefined) {
    const dob = new Date(dateOfBirth);
    if (typeof dateOfBirth !== 'string' || Number.isNaN(dob.getTime()) || dob > new Date()) {
      return res.status(400).json({ error: 'Date of birth must be a valid date, not in the future' });
    }
  }
  if (familyBackground !== undefined && familyBackground !== null && typeof familyBackground !== 'string') {
    return res.status(400).json({ error: 'familyBackground must be text' });
  }

  const owned = await findOwnChildProfile(childProfileId, req.user.id);
  if (!owned) {
    return res.status(403).json({ error: 'Not authorized for this child profile' });
  }
  if (refuseIfArchived(res, owned)) return;

  const values = fields.map((f) => {
    if (f === 'fullName') return encryptField(fullName.trim());
    if (f === 'familyBackground') return familyBackground && familyBackground.trim() ? encryptField(familyBackground.trim()) : null;
    return encryptField(dateOfBirth);
  });
  const sets = fields.map((f, i) => `${CORRECTABLE_FIELDS[f]} = $${i + 1}`);
  await db.query(
    `UPDATE child_identifiers SET ${sets.join(', ')} WHERE child_profile_id = $${fields.length + 1}`,
    [...values, childProfileId]
  );

  await logAction({
    userId: req.user.id,
    action: 'correct_child_details',
    detail: `child_profile_id=${childProfileId}, fields=${fields.join(',')}`,
  });

  const risk = await scoreAction(req, 'correct_child_details', childProfileId);
  res.json({ childProfileId, updatedFields: fields, ...(risk.flagged ? { riskNotice: RISK_NOTICE } : {}) });
}

// POST /children/:childProfileId/archive — restrict processing of a child
// profile (KDPA s.40(3)) instead of erasing it: nothing is deleted, but the
// profile is frozen. The optional reason is stored on the profile, not in
// the audit log (free text may name the child). After the retention period
// an archived profile's identity is anonymised -- see services/retention.js.
async function archiveChild(req, res) {
  const childProfileId = Number(req.params.childProfileId);
  const reason = typeof req.body.reason === 'string' ? req.body.reason.trim().slice(0, 500) : '';

  const owned = await findOwnChildProfile(childProfileId, req.user.id);
  if (!owned) return res.status(403).json({ error: 'Not authorized for this child profile' });
  if (owned.archived_at) return res.status(409).json({ error: 'This profile is already archived' });

  const { rows } = await db.query(
    'UPDATE child_profiles SET archived_at = now(), archive_reason = $1 WHERE id = $2 RETURNING archived_at',
    [reason || null, childProfileId]
  );
  await logAction({
    userId: req.user.id,
    action: 'archive_child_profile',
    detail: `child_profile_id=${childProfileId}${reason ? ', reason given' : ''}`,
  });

  const risk = await scoreAction(req, 'archive_child_profile', childProfileId);
  res.json({ childProfileId, archivedAt: rows[0].archived_at, ...(risk.flagged ? { riskNotice: RISK_NOTICE } : {}) });
}

// POST /children/:childProfileId/restore — lift the restriction (e.g. it
// was archived by mistake). Not possible once the identity has been
// anonymised: that is the point of retention.
async function restoreChild(req, res) {
  const childProfileId = Number(req.params.childProfileId);

  const owned = await findOwnChildProfile(childProfileId, req.user.id);
  if (!owned) return res.status(403).json({ error: 'Not authorized for this child profile' });
  if (!owned.archived_at) return res.status(409).json({ error: 'This profile is not archived' });
  if (owned.identity_anonymised_at) {
    return res.status(409).json({ error: 'This profile’s identity was anonymised after the retention period and can’t be restored' });
  }

  await db.query('UPDATE child_profiles SET archived_at = NULL, archive_reason = NULL WHERE id = $1', [childProfileId]);
  await logAction({ userId: req.user.id, action: 'restore_child_profile', detail: `child_profile_id=${childProfileId}` });

  const risk = await scoreAction(req, 'restore_child_profile', childProfileId);
  res.json({ childProfileId, archivedAt: null, ...(risk.flagged ? { riskNotice: RISK_NOTICE } : {}) });
}

// GET /children — list this caregiver's own children, decrypted for
// display. Proves decryption works, and that it's scoped to req.user.id
// (not "all children in the system").
async function listMyChildren(req, res) {
  const { rows } = await db.query(
    `SELECT cp.id AS child_profile_id, cp.created_at, cp.archived_at, cp.identity_anonymised_at,
            ci.full_name_enc, ci.date_of_birth_enc, ci.family_background_enc
     FROM child_profiles cp
     JOIN child_identifiers ci ON ci.child_profile_id = cp.id
     WHERE cp.caregiver_id = $1
     ORDER BY cp.created_at DESC`,
    [req.user.id]
  );

  const children = rows.map((r) => ({
    childProfileId: r.child_profile_id,
    createdAt: r.created_at,
    fullName: decryptField(r.full_name_enc),
    dateOfBirth: decryptField(r.date_of_birth_enc),
    familyBackground: r.family_background_enc ? decryptField(r.family_background_enc) : null,
    archivedAt: r.archived_at,
    anonymisedAt: r.identity_anonymised_at,
  }));

  await logAction({ userId: req.user.id, action: 'view_own_children', detail: `${children.length} profile(s)` });

  // Own label, NOT 'view_own_child_records': this list loads on every
  // Dashboard / Consent / Child Record page visit, so counting it as a file
  // access (FILE_ACTION_TYPES) made plain navigation look like a burst of
  // record reads and got caregivers logged out after their first real action.
  await logOnlyAction(req, 'list_own_children');
  res.json({ children });
}

// POST /children/:childProfileId/records — submit a developmental record
// for one of the caregiver's own children. This is the ownership check in
// action: a Caregiver role permission alone would not stop them submitting
// a record against someone ELSE's child_profile_id.
async function submitRecord(req, res) {
  const childProfileId = Number(req.params.childProfileId);
  const { milestone, healthIndicator, assessmentScore, progressNotes } = req.body;

  if (!milestone || !healthIndicator || assessmentScore === undefined) {
    return res.status(400).json({
      error: 'milestone, healthIndicator and assessmentScore are required',
    });
  }

  const owned = await findOwnChildProfile(childProfileId, req.user.id);
  if (!owned) {
    // Deliberately the same 403 whether the child doesn't exist or just
    // isn't theirs — don't leak which other childProfileIds exist.
    return res.status(403).json({ error: 'Not authorized for this child profile' });
  }
  if (refuseIfArchived(res, owned)) return;
  if (await denyWithoutRecordsConsent(req, res, childProfileId, 'submit_developmental_record')) return;

  const { rows } = await db.query(
    `INSERT INTO developmental_records
       (child_profile_id, milestone_enc, health_indicator_enc, assessment_score_enc, progress_notes_enc, created_by)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, created_at`,
    [
      childProfileId,
      encryptField(milestone),
      encryptField(healthIndicator),
      encryptField(String(assessmentScore)),
      progressNotes ? encryptField(progressNotes) : null,
      req.user.id,
    ]
  );

  await logAction({
    userId: req.user.id,
    action: 'submit_developmental_record',
    detail: `child_profile_id=${childProfileId}, record_id=${rows[0].id}`,
  });

  const risk = await scoreAction(req, 'submit_developmental_record', childProfileId);
  res.status(201).json({
    recordId: rows[0].id,
    createdAt: rows[0].created_at,
    ...(risk.flagged ? { riskNotice: RISK_NOTICE } : {}),
  });
}

// GET /children/:childProfileId/records — view a child's developmental
// records, decrypted. Same ownership check as submitRecord.
async function listRecords(req, res) {
  const childProfileId = Number(req.params.childProfileId);

  const owned = await findOwnChildProfile(childProfileId, req.user.id);
  if (!owned) {
    return res.status(403).json({ error: 'Not authorized for this child profile' });
  }
  if (refuseIfArchived(res, owned)) return;
  if (await denyWithoutRecordsConsent(req, res, childProfileId, 'view_developmental_records')) return;

  const { rows } = await db.query(
    `SELECT id, milestone_enc, health_indicator_enc, assessment_score_enc,
            progress_notes_enc, created_at
     FROM developmental_records
     WHERE child_profile_id = $1
     ORDER BY created_at DESC`,
    [childProfileId]
  );

  const records = rows.map((r) => ({
    id: r.id,
    createdAt: r.created_at,
    milestone: decryptField(r.milestone_enc),
    healthIndicator: decryptField(r.health_indicator_enc),
    assessmentScore: decryptField(r.assessment_score_enc),
    progressNotes: r.progress_notes_enc ? decryptField(r.progress_notes_enc) : null,
  }));

  await logAction({
    userId: req.user.id,
    action: 'view_developmental_records',
    detail: `child_profile_id=${childProfileId}, count=${records.length}`,
  });

  const risk = await scoreAction(req, 'view_own_child_records', childProfileId);
  res.json({ records, ...(risk.flagged ? { riskNotice: RISK_NOTICE } : {}) });
}

module.exports = {
  createChildProfile,
  updateChildDetails,
  archiveChild,
  restoreChild,
  listMyChildren,
  submitRecord,
  listRecords,
};
