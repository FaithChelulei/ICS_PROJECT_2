// One-off dev seed: creates one test login per role so the auth flow can
// be exercised end-to-end. Run with: node db/seed.js
// All three test accounts share the password 'DevTest123!' — change or
// delete them before this ever touches real data.
require('dotenv').config();
const bcrypt = require('bcryptjs');
const db = require('../src/config/db');

const TEST_PASSWORD = 'DevTest123!';

const USERS = [
  { email: 'caregiver.test@example.com', role: 'Caregiver', mfa: false },
  { email: 'auditor.test@example.com', role: 'SecurityAuditor', mfa: true },
  { email: 'admin.test@example.com', role: 'SysAdmin', mfa: true },
];

async function main() {
  const hash = await bcrypt.hash(TEST_PASSWORD, 10);

  for (const u of USERS) {
    const { rows } = await db.query('SELECT id FROM roles WHERE name = $1', [u.role]);
    const roleId = rows[0].id;

    await db.query(
      `INSERT INTO users (email, password_hash, role_id, mfa_required)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (email) DO NOTHING`,
      [u.email, hash, roleId, u.mfa]
    );
    console.log(`Seeded ${u.role}: ${u.email} / ${TEST_PASSWORD}`);
  }

  process.exit(0);
}

main().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});
