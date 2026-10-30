// KDPA s.39 (limitation to retention): personal data is kept only as long
// as it is needed. Applied ONLY to archived child profiles -- an active
// child is never touched. Once a profile has been archived for longer than
// RETENTION_DAYS (backend/.env, default 365), its identity -- name, date of
// birth, family background, and the free-text archive reason -- is
// overwritten with a fixed placeholder. Developmental records, consent
// history and the audit trail stay, linked only to the profile id: the
// child can no longer be identified from them, but the security history
// remains intact (s.39(2) "anonymise or pseudonymise").
//
// Shared by Admin > Data Retention and `npm run retention:status|apply`.
// Runs as the explicit System identity: row-level security shows a SysAdmin
// no child data otherwise.
const db = require('../config/db');
const { encryptField } = require('../utils/encryption');

const ANONYMISED_NAME = 'Anonymised child';
const ANONYMISED_DOB = 'anonymised';

function retentionDays() {
  const days = Number(process.env.RETENTION_DAYS);
  return Number.isInteger(days) && days > 0 ? days : 365;
}

function getRetentionStatus() {
  return db.runAsSystem(async () => {
    const days = retentionDays();
    const { rows } = await db.query(
      `SELECT COUNT(*) FILTER (WHERE archived_at IS NOT NULL AND identity_anonymised_at IS NULL)::int AS archived,
              COUNT(*) FILTER (WHERE archived_at IS NOT NULL AND identity_anonymised_at IS NULL
                                 AND archived_at < now() - make_interval(days => $1))::int AS due,
              COUNT(*) FILTER (WHERE identity_anonymised_at IS NOT NULL)::int AS anonymised,
              MIN(archived_at) FILTER (WHERE archived_at IS NOT NULL AND identity_anonymised_at IS NULL) AS oldest_archived_at
       FROM child_profiles`,
      [days]
    );
    return { retentionDays: days, ...rows[0] };
  });
}

// Anonymises every archived profile past the retention period, all-or-
// nothing in one transaction. Returns the profile ids it anonymised.
function applyRetention() {
  return db.runAsSystem(() => db.transaction(async (client) => {
    const { rows } = await client.query(
      `SELECT id FROM child_profiles
       WHERE archived_at IS NOT NULL AND identity_anonymised_at IS NULL
         AND archived_at < now() - make_interval(days => $1)
       ORDER BY id FOR UPDATE`,
      [retentionDays()]
    );
    const ids = rows.map((r) => r.id);
    if (ids.length === 0) return [];

    // Encrypted like any other value, so the rest of the app (lists, key
    // rotation) needs no special case for anonymised profiles.
    for (const id of ids) {
      await client.query(
        `UPDATE child_identifiers
         SET full_name_enc = $1, date_of_birth_enc = $2, family_background_enc = NULL
         WHERE child_profile_id = $3`,
        [encryptField(ANONYMISED_NAME), encryptField(ANONYMISED_DOB), id]
      );
    }
    await client.query(
      'UPDATE child_profiles SET identity_anonymised_at = now(), archive_reason = NULL WHERE id = ANY($1)',
      [ids]
    );
    return ids;
  }));
}

module.exports = { getRetentionStatus, applyRetention, retentionDays };
