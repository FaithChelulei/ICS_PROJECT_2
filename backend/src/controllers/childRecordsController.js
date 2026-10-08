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
const { recordAndScore } = require('../services/riskEngine');
const { getPcName, getIpAddress } = require('../utils/requestMeta');

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

// Throws-and-is-caught-by-caller style helper: confirms child_profile_id
// belongs to this caregiver, or returns null if not found / not theirs.
async function findOwnChildProfile(childProfileId, caregiverId) {
  const { rows } = await db.query(
    'SELECT id FROM child_profiles WHERE id = $1 AND caregiver_id = $2',
    [childProfileId, caregiverId]
  );
  return rows[0] || null;
}

// POST /children — a Caregiver registers a child profile under their own
// account. Identity fields are encrypted before they ever reach the DB.
async function createChildProfile(req, res) {
  const { fullName, dateOfBirth, familyBackground } = req.body;
  if (!fullName || !dateOfBirth) {
    return res.status(400).json({ error: 'fullName and dateOfBirth are required' });
  }

  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');

    const { rows } = await client.query(
      'INSERT INTO child_profiles (caregiver_id) VALUES ($1) RETURNING id, created_at',
      [req.user.id]
    );
    const childProfileId = rows[0].id;

    await client.query(
      `INSERT INTO child_identifiers
         (child_profile_id, full_name_enc, date_of_birth_enc, family_background_enc)
       VALUES ($1, $2, $3, $4)`,
      [
        childProfileId,
        encryptField(fullName),
        encryptField(dateOfBirth),
        familyBackground ? encryptField(familyBackground) : null,
      ]
    );

    await client.query('COMMIT');

    await logAction({
      userId: req.user.id,
      action: 'create_child_profile',
      detail: `Created child_profile_id=${childProfileId}`,
    });

    const risk = await scoreAction(req, 'create_child_profile', childProfileId);
    res.status(201).json({
      childProfileId,
      createdAt: rows[0].created_at,
      ...(risk.flagged ? { riskNotice: RISK_NOTICE } : {}),
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Failed to create child profile' });
  } finally {
    client.release();
  }
}

// GET /children — list this caregiver's own children, decrypted for
// display. Proves decryption works, and that it's scoped to req.user.id
// (not "all children in the system").
async function listMyChildren(req, res) {
  const { rows } = await db.query(
    `SELECT cp.id AS child_profile_id, cp.created_at,
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
  }));

  await logAction({ userId: req.user.id, action: 'view_own_children', detail: `${children.length} profile(s)` });

  const risk = await scoreAction(req, 'view_own_child_records');
  res.json({ children, ...(risk.flagged ? { riskNotice: RISK_NOTICE } : {}) });
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

module.exports = { createChildProfile, listMyChildren, submitRecord, listRecords };
