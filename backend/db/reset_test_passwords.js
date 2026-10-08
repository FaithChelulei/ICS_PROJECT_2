// The Caregiver test account's password changed to a random temp password
// during the full-flow unlock demo -- reset all 3 test accounts back to
// the known DevTest123! so other test scripts can rely on it again.
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const bcrypt = require('bcryptjs');
const db = require('../src/config/db');

async function main() {
  const hash = await bcrypt.hash('DevTest123!', 10);
  const { rowCount } = await db.query(
    "UPDATE users SET password_hash = $1, must_change_password = FALSE WHERE email LIKE 'faith.chelulei+%'",
    [hash]
  );
  console.log(`Reset ${rowCount} test account password(s) to DevTest123!`);
  await db.pool.end();
}
main();
