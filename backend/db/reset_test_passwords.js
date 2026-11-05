// Resets the three demo accounts (faith.chelulei+...) to the password in
// DEMO_ACCOUNT_PASSWORD (backend/.env), e.g. after the full-flow unlock
// demo left one on a temporary password. The password is never written in
// this file -- the repository is public.
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const bcrypt = require('bcryptjs');
const db = require('../src/config/db');

async function main() {
  const password = process.env.DEMO_ACCOUNT_PASSWORD;
  if (!password || password.length < 8) {
    console.error('Set DEMO_ACCOUNT_PASSWORD (8+ characters) in backend/.env first.');
    process.exit(1);
  }
  const hash = await bcrypt.hash(password, 10);
  const { rowCount } = await db.query(
    "UPDATE users SET password_hash = $1, must_change_password = FALSE WHERE email LIKE 'faith.chelulei+%'",
    [hash]
  );
  console.log(`Reset ${rowCount} demo account password(s) to DEMO_ACCOUNT_PASSWORD.`);
  await db.pool.end();
}
main();
