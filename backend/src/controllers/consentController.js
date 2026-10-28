// Consent capture for a caregiver's own children. consent_records existed
// in the schema since Day 1 (and 'manage_own_consent' in the RBAC map)
// but nothing read or wrote it until now. This is deliberately scoped to
// the two things the system actually stores about a child -- profile
// identity and developmental/health records -- not a fictional
// "third-party sharing" toggle for a feature that doesn't exist anywhere
// in this app.
//
// consent_records is append-only (one row per grant/revoke event, never
// updated), so "current status" for a scope is its most recent row, and
// the full row history IS the consent change log for free.
const db = require('../config/db');
const { logAction } = require('../utils/auditLog');

const SCOPES = {
  profile_identity: { label: 'Profile & Identity', required: true },
  developmental_records: { label: 'Developmental & Health Records', required: false },
};

async function findOwnChildProfile(childProfileId, caregiverId) {
  const { rows } = await db.query(
    'SELECT id FROM child_profiles WHERE id = $1 AND caregiver_id = $2',
    [childProfileId, caregiverId]
  );
  return rows[0] || null;
}
// GET /children/:childProfileId/consent — current status per scope (the
// latest row for each) plus the full history, for this caregiver's own
// child only.
async function getConsent(req, res) {
  const childProfileId = Number(req.params.childProfileId);
  const owned = await findOwnChildProfile(childProfileId, req.user.id);
  if (!owned) return res.status(403).json({ error: 'Not authorized for this child profile' });

  const { rows } = await db.query(
    `SELECT id, scope, consent_given, recorded_at
     FROM consent_records
     WHERE child_profile_id = $1
     ORDER BY recorded_at DESC`,
    [childProfileId]
  );

  const current = {};
  for (const row of rows) {
    if (!(row.scope in current)) current[row.scope] = row; // first seen = most recent, already DESC
  }

  const statuses = Object.entries(SCOPES).map(([scope, meta]) => ({
    scope,
    label: meta.label,
    required: meta.required,
    consentGiven: current[scope] ? current[scope].consent_given : meta.required,
    recordedAt: current[scope] ? current[scope].recorded_at : null,
  }));

  res.json({ statuses, history: rows });
}
// POST /children/:childProfileId/consent — record a new grant/revoke
// event. Never updates an old row (that would erase the trail); every
// change is a fresh insert, which is what makes the history view honest.
async function setConsent(req, res) {
  const childProfileId = Number(req.params.childProfileId);
  const { scope, consentGiven } = req.body;

  if (!(scope in SCOPES)) {
    return res.status(400).json({ error: `scope must be one of: ${Object.keys(SCOPES).join(', ')}` });
  }
  if (typeof consentGiven !== 'boolean') {
    return res.status(400).json({ error: 'consentGiven must be a boolean' });
  }
  if (SCOPES[scope].required && consentGiven === false) {
    return res.status(400).json({ error: `${SCOPES[scope].label} is required and cannot be revoked while this profile exists` });
  }

  const owned = await findOwnChildProfile(childProfileId, req.user.id);
  if (!owned) return res.status(403).json({ error: 'Not authorized for this child profile' });

  const { rows } = await db.query(
    `INSERT INTO consent_records (child_profile_id, caregiver_id, consent_given, scope)
     VALUES ($1, $2, $3, $4) RETURNING id, recorded_at`,
    [childProfileId, req.user.id, consentGiven, scope]
  );

  await logAction({
    userId: req.user.id,
    action: consentGiven ? 'consent_granted' : 'consent_revoked',
    detail: `child_profile_id=${childProfileId}, scope=${scope}`,
  });

  res.status(201).json({ id: rows[0].id, scope, consentGiven, recordedAt: rows[0].recorded_at });
}

module.exports = { getConsent, setConsent };
