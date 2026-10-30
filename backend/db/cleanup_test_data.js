require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const db = require('../src/config/db');

// Runs as the explicit 'System' identity: with row-level security on, the
// child-data deletes below would otherwise match no rows.
const main = () => db.runAsSystem(clearAll);

async function clearAll() {
  await db.query('DELETE FROM risk_scores');
  await db.query('DELETE FROM access_requests');
  await db.query('DELETE FROM sessions');
  await db.query('DELETE FROM mfa_codes');
  await db.query('DELETE FROM developmental_records');
  await db.query('DELETE FROM child_identifiers');
  await db.query('DELETE FROM child_profiles');
  await db.query(
    "UPDATE users SET is_locked = FALSE, locked_reason = NULL WHERE email LIKE 'faith.chelulei+%'"
  );
  console.log('Test data cleared.');
  await db.pool.end();
}
main();
