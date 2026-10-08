// Login flow (MFA required for every role — see registrationController.js
// for why this now covers Caregiver too, not just SecurityAuditor/SysAdmin):
//   1. POST /auth/login          { email, password }
//        -> emails a 6-digit code, returns { mfaRequired: true, userId }
//           instead of a token
//   2. POST /auth/verify-mfa     { userId, code }
//        -> returns the token
//
// "Token" here means: a new row in `sessions`, and a JWT whose payload
// just points at that row's id. Revoking the row (sessions.revoked_at)
// is how the system logs someone out before their JWT would naturally
// expire — see src/middleware/auth.js.

const bcrypt = require('bcryptjs'); // pure-JS bcrypt — avoids native build tooling (node-gyp) on Windows and its tar/node-pre-gyp CVEs, same hash()/compare() API
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const { sendMfaCodeEmail } = require('../utils/mailer');
const { logAccessRequest } = require('../services/riskEngine');
const { getPcName, getIpAddress } = require('../utils/requestMeta');

const MFA_CODE_TTL_MINUTES = 10;

// Creates the session row and logs the login to access_requests -- but
// does NOT run it through ML scoring. The model was trained on COMPLETED
// sessions that already had real activity in them; scoring the bare
// moment of login (0 files accessed, ~0 session duration so far) compares
// against a baseline that can't possibly match yet, which flagged nearly
// every login in testing. Login is still logged, because it feeds the
// features computed for whatever the user does NEXT (events_prev_hour/day,
// unique_pcs_used_that_day, is_own_pc) -- see riskEngine.js and
// childRecordsController.js, where real scoring happens on actual data
// access, matching what this system is actually trying to catch.
async function issueSession({ userId, role, pcName, ipAddress }, res) {
  const { rows } = await db.query(
    'INSERT INTO sessions (user_id) VALUES ($1) RETURNING id',
    [userId]
  );
  const sessionId = rows[0].id;

  await logAccessRequest({ userId, actionType: 'login', pcName, ipAddress, sessionId });

  const token = jwt.sign(
    { userId, role, sessionId },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
  );

  return res.json({ token });
}

async function login(req, res) {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  const { rows } = await db.query(
    `SELECT u.id, u.password_hash, u.mfa_required, u.is_locked, r.name AS role
     FROM users u JOIN roles r ON r.id = u.role_id
     WHERE u.email = $1`,
    [email]
  );
  const user = rows[0];

  // Same generic error whether the email doesn't exist or the password is
  // wrong — never reveal which one, that itself leaks account existence.
  const genericError = () => res.status(401).json({ error: 'Invalid email or password' });

  if (!user) return genericError();
  if (user.is_locked) {
    return res.status(403).json({ error: 'Account is locked. Contact a System Administrator.' });
  }

  const passwordOk = await bcrypt.compare(password, user.password_hash);
  if (!passwordOk) return genericError();

  if (!user.mfa_required) {
    // No role currently skips MFA (Caregiver included, as of the MFA-for-
    // all-roles change) -- kept generic here in case that ever changes.
    return issueSession(
      { userId: user.id, role: user.role, pcName: getPcName(req), ipAddress: getIpAddress(req) },
      res
    );
  }

  // MFA required (now true for every role): generate, hash, store and email a 6-digit code
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const codeHash = await bcrypt.hash(code, 10);
  const expiresAt = new Date(Date.now() + MFA_CODE_TTL_MINUTES * 60 * 1000);

  await db.query(
    'INSERT INTO mfa_codes (user_id, code_hash, expires_at) VALUES ($1, $2, $3)',
    [user.id, codeHash, expiresAt]
  );
  await sendMfaCodeEmail(email, code);

  return res.json({ mfaRequired: true, userId: user.id });
}

async function verifyMfa(req, res) {
  const { userId, code } = req.body;
  if (!userId || !code) {
    return res.status(400).json({ error: 'userId and code are required' });
  }

  const { rows } = await db.query(
    `SELECT id, code_hash FROM mfa_codes
     WHERE user_id = $1 AND consumed = FALSE AND expires_at > now()
     ORDER BY created_at DESC LIMIT 1`,
    [userId]
  );
  const record = rows[0];
  if (!record) {
    return res.status(401).json({ error: 'No valid code found. Request a new login.' });
  }

  const ok = await bcrypt.compare(code, record.code_hash);
  if (!ok) return res.status(401).json({ error: 'Incorrect code' });

  await db.query('UPDATE mfa_codes SET consumed = TRUE WHERE id = $1', [record.id]);

  const { rows: userRows } = await db.query(
    `SELECT u.id, r.name AS role FROM users u
     JOIN roles r ON r.id = u.role_id WHERE u.id = $1`,
    [userId]
  );
  return issueSession(
    {
      userId: userRows[0].id,
      role: userRows[0].role,
      pcName: getPcName(req),
      ipAddress: getIpAddress(req),
    },
    res
  );
}

async function logout(req, res) {
  await db.query(
    "UPDATE sessions SET revoked_at = now(), revoked_reason = 'user_logout' WHERE id = $1",
    [req.user.sessionId]
  );
  return res.json({ message: 'Logged out' });
}

module.exports = { login, verifyMfa, logout };
