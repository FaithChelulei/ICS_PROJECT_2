// One-off dev seed: creates one demo login per role so the auth flow can
// be exercised end-to-end. Run with: node db/seed.js
// The password comes from DEMO_ACCOUNT_PASSWORD in backend/.env -- never
// from this file: the repository is public, so a password written here
// would let anyone sign in to a hosted copy.
require('dotenv').config();
const bcrypt = require('bcryptjs');
const db = require('../src/config/db');

const TEST_PASSWORD = process.env.DEMO_ACCOUNT_PASSWORD;
if (!TEST_PASSWORD || TEST_PASSWORD.length < 8) {
  console.error('Set DEMO_ACCOUNT_PASSWORD (8+ characters) in backend/.env first.');
  process.exit(1);
}

// All three roles require MFA now (updated: a compromised Caregiver
// account exposes that family's child data just as directly as a
// compromised staff account exposes system-wide data).
const USERS = [
  // Real email for all three, so the console-logged code (or a real email
  // now that SMTP is configured) is addressed to Faith's own inbox.
  // Plus-addressing keeps the logins distinct (DB requires unique emails)
  // while still delivering to the same real mailbox.
  { email: 'faith.chelulei+caregiver@strathmore.edu', role: 'Caregiver', mfa: true },
  { email: 'faith.chelulei+auditor@strathmore.edu', role: 'SecurityAuditor', mfa: true },
  { email: 'faith.chelulei+admin@strathmore.edu', role: 'SysAdmin', mfa: true },
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
    console.log(`Seeded ${u.role}: ${u.email} (password: DEMO_ACCOUNT_PASSWORD)`);
  }

  process.exit(0);
}

main().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});
