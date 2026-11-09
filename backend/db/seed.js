// Creates one demo login per role so the system can be tried end to end.
// Run from backend/ after node db/migrate.js:  node db/seed.js
//
// Nothing personal lives in this file (the repository is public):
//   DEMO_ACCOUNT_PASSWORD  the password for all three demo accounts
//   DEMO_EMAIL_BASE        an inbox you can read, e.g. you@example.com. The
//                          accounts become you+caregiver@..., you+auditor@...
//                          and you+admin@..., which most mail providers
//                          deliver to the same inbox, so the one-time
//                          sign-in codes reach you.
// An account whose email already exists is left unchanged.
require('dotenv').config();
const bcrypt = require('bcryptjs');
const db = require('../src/config/db');

const PASSWORD = process.env.DEMO_ACCOUNT_PASSWORD;
const BASE = process.env.DEMO_EMAIL_BASE;
if (!PASSWORD || PASSWORD.length < 8) {
  console.error('Set DEMO_ACCOUNT_PASSWORD (8+ characters) in backend/.env first.');
  process.exit(1);
}
if (!BASE || !/^[^@\s]+@[^@\s]+$/.test(BASE)) {
  console.error('Set DEMO_EMAIL_BASE in backend/.env to an inbox you can read (e.g. you@example.com) first.');
  process.exit(1);
}
const [local, domain] = BASE.split('@');

// All three roles require the emailed sign-in code.
const USERS = [
  { tag: 'caregiver', name: 'Demo Caregiver', username: 'demo.caregiver', role: 'Caregiver' },
  { tag: 'auditor', name: 'Demo Auditor', username: 'demo.auditor', role: 'SecurityAuditor' },
  { tag: 'admin', name: 'Demo Admin', username: 'demo.admin', role: 'SysAdmin' },
];

async function main() {
  const hash = await bcrypt.hash(PASSWORD, 10);
  for (const u of USERS) {
    const email = `${local}+${u.tag}@${domain}`;
    const { rowCount } = await db.query(
      `INSERT INTO users (email, full_name, username, password_hash, role_id, mfa_required)
       SELECT $1, $2, $3, $4, id, TRUE FROM roles WHERE name = $5
       ON CONFLICT DO NOTHING`,
      [email, u.name, u.username, hash, u.role]
    );
    console.log(`${rowCount ? 'Created' : 'Already there'}: ${u.role} ${email} (username ${u.username}, password DEMO_ACCOUNT_PASSWORD)`);
  }
  process.exit(0);
}

main().catch((err) => {
  console.error('Seed failed:', err.message);
  process.exit(1);
});
