// Consent ENFORCEMENT -- the "consent check" step of every child-data
// request (authentication -> role check -> consent check -> ML scoring ->
// response). consentController.js lets a caregiver grant/revoke; this is
// what makes that choice actually block access instead of just being
// recorded.
//
// Opt-in, per the Kenya Data Protection Act 2019: a scope with no consent
// row yet counts as NOT granted unless it is a required scope (profile
// identity is consented to by the act of registering the child, and can't
// be revoked while the profile exists).
const db = require('../config/db');

const SCOPES = {
  profile_identity: { label: 'Profile & Identity', required: true },
  developmental_records: { label: 'Developmental & Health Records', required: false },
};

// consent_records is append-only, so current status is the latest row.
// id breaks ties between rows written in the same transaction (same now()).
async function hasConsent(childProfileId, scope) {
  const { rows } = await db.query(
    `SELECT consent_given FROM consent_records
     WHERE child_profile_id = $1 AND scope = $2
     ORDER BY recorded_at DESC, id DESC LIMIT 1`,
    [childProfileId, scope]
  );
  return rows[0] ? rows[0].consent_given : SCOPES[scope].required;
}

module.exports = { SCOPES, hasConsent };
