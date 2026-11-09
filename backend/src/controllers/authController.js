// Login flow (MFA required for every role — see registrationController.js
// for why this now covers Caregiver too, not just SecurityAuditor/SysAdmin):
//   1. POST /auth/login          { email, password }
//        -> emails a 6-digit code, returns { mfaRequired: true, challengeId }
//           instead of a token
//   2. POST /auth/verify-mfa     { challengeId, code }
//        -> returns the token
//
// The challengeId is a signed, short-lived reference to that one emailed
// code -- not the user's id, so nobody can send code guesses against
// another person's account. Each code allows MFA_MAX_ATTEMPTS wrong tries
// and is then cancelled; signing in again cancels any older code, so only
// one code per account is ever live.
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
const MFA_MAX_ATTEMPTS = 5;
const MFA_PURPOSE = 'mfa_challenge';

// Signed with a key derived from JWT_SECRET for this purpose only, so a
// challenge can never pass as a session token or the reverse.
const challengeSecret = () =>
  crypto.createHmac('sha256', process.env.JWT_SECRET).update('childguard mfa challenge').digest('hex');

function signChallenge(codeId, userId) {
  return jwt.sign({ purpose: MFA_PURPOSE, codeId, userId }, challengeSecret(), {
    algorithm: 'HS256',
    expiresIn: `${MFA_CODE_TTL_MINUTES}m`,
  });
}

function readChallenge(challengeId) {
  try {
    const p = jwt.verify(challengeId, challengeSecret(), { algorithms: ['HS256'] });
    return p.purpose === MFA_PURPOSE ? p : null;
  } catch {
    return null;
  }
}

// Wrong tries per code. Held in memory: a restart forgets the count, but a
// code that reached the limit is already cancelled in the database, and
// every code expires after MFA_CODE_TTL_MINUTES anyway.
const failedTries = new Map();

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
async function issueSession({ userId, role, email, fullName, mustChangePassword, pcName, ipAddress }, res) {
  const { rows } = await db.query(
    'INSERT INTO sessions (user_id) VALUES ($1) RETURNING id',
    [userId]
  );
  const sessionId = rows[0].id;

  await logAccessRequest({ userId, actionType: 'login', pcName, ipAddress, sessionId });

  const token = jwt.sign(
    { userId, role, sessionId },
    process.env.JWT_SECRET,
    { algorithm: 'HS256', expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
  );

  // role/email/fullName/mustChangePassword are returned alongside the
  // token so the frontend can route straight to the right dashboard (or
  // the forced change-password screen) and greet the person by name
  // without a second round trip.
  return res.json({ token, role, email, fullName, mustChangePassword });
}

async function login(req, res) {
  // Accepts either the account's email or its username in the same field
  // (kept named `identifier` so the client doesn't have to pre-detect
  // which one it is). The MFA code still only ever goes to the account's
  // real, registered email -- a username is just an alternate way to say
  // "which account", never an alternate delivery address.
  const identifier = req.body.identifier ?? req.body.email;
  const { password } = req.body;
  if (!identifier || !password) {
    return res.status(400).json({ error: 'identifier and password are required' });
  }

  const { rows } = await db.query(
    `SELECT u.id, u.email, u.full_name, u.password_hash, u.mfa_required, u.is_locked,
            u.must_change_password, r.name AS role
     FROM users u JOIN roles r ON r.id = u.role_id
     WHERE u.email = $1 OR u.username = $1`,
    [identifier]
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
      {
        userId: user.id,
        role: user.role,
        email: user.email,
        fullName: user.full_name,
        mustChangePassword: user.must_change_password,
        pcName: getPcName(req),
        ipAddress: getIpAddress(req),
      },
      res
    );
  }

  // MFA required (now true for every role): generate, hash, store and email a 6-digit code
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const codeHash = await bcrypt.hash(code, 10);
  const expiresAt = new Date(Date.now() + MFA_CODE_TTL_MINUTES * 60 * 1000);

  // Only one live code per account: a new sign-in cancels any older one.
  await db.query('UPDATE mfa_codes SET consumed = TRUE WHERE user_id = $1 AND consumed = FALSE', [user.id]);
  const { rows: codeRows } = await db.query(
    'INSERT INTO mfa_codes (user_id, code_hash, expires_at) VALUES ($1, $2, $3) RETURNING id',
    [user.id, codeHash, expiresAt]
  );
  // Always the account's real registered email -- never whatever
  // identifier (email or username) was typed to find this account.
  await sendMfaCodeEmail(user.email, code);

  // email included here too so the frontend can show "code sent to
  // ___" using the REAL destination, even when the person typed a
  // username (not an email) as their identifier to get this far.
  return res.json({ mfaRequired: true, challengeId: signChallenge(codeRows[0].id, user.id), email: user.email });
}

async function verifyMfa(req, res) {
  const { challengeId, code } = req.body;
  if (typeof challengeId !== 'string' || typeof code !== 'string' || !challengeId || !code) {
    return res.status(400).json({ error: 'challengeId and code are required' });
  }
  const challenge = readChallenge(challengeId);
  if (!challenge) {
    return res.status(401).json({ error: 'This sign-in has expired. Sign in again for a new code.' });
  }
  const { codeId, userId } = challenge;

  const { rows } = await db.query(
    `SELECT id, code_hash FROM mfa_codes
     WHERE id = $1 AND user_id = $2 AND consumed = FALSE AND expires_at > now()`,
    [codeId, userId]
  );
  const record = rows[0];
  if (!record) {
    failedTries.delete(codeId);
    return res.status(401).json({ error: 'No valid code found. Sign in again for a new code.' });
  }

  const ok = await bcrypt.compare(code, record.code_hash);
  if (!ok) {
    const tries = (failedTries.get(codeId) || 0) + 1;
    if (tries >= MFA_MAX_ATTEMPTS) {
      failedTries.delete(codeId);
      await db.query('UPDATE mfa_codes SET consumed = TRUE WHERE id = $1', [codeId]);
      return res.status(401).json({ error: 'Too many incorrect codes. Sign in again for a new code.', code: 'MFA_CODE_CANCELLED' });
    }
    failedTries.set(codeId, tries);
    return res.status(401).json({ error: `Incorrect code. ${MFA_MAX_ATTEMPTS - tries} tries left.` });
  }

  failedTries.delete(codeId);
  await db.query('UPDATE mfa_codes SET consumed = TRUE WHERE id = $1', [record.id]);

  const { rows: userRows } = await db.query(
    `SELECT u.id, u.email, u.full_name, u.must_change_password, r.name AS role FROM users u
     JOIN roles r ON r.id = u.role_id WHERE u.id = $1`,
    [userId]
  );
  return issueSession(
    {
      userId: userRows[0].id,
      role: userRows[0].role,
      email: userRows[0].email,
      fullName: userRows[0].full_name,
      mustChangePassword: userRows[0].must_change_password,
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

// GET /auth/me — lets the frontend re-hydrate who's logged in (role, email,
// whether a forced password change is still pending) after a page refresh,
// without having to decode the JWT itself.
async function me(req, res) {
  const { rows } = await db.query(
    'SELECT full_name, must_change_password FROM users WHERE id = $1',
    [req.user.id]
  );
  // The sign-in before this session, so people can spot one that wasn't them.
  const { rows: previous } = await db.query(
    'SELECT issued_at FROM sessions WHERE user_id = $1 AND id <> $2 ORDER BY issued_at DESC LIMIT 1',
    [req.user.id, req.user.sessionId]
  );
  return res.json({
    id: req.user.id,
    role: req.user.role,
    email: req.user.email,
    fullName: rows[0] ? rows[0].full_name : undefined,
    mustChangePassword: rows[0] ? rows[0].must_change_password : req.user.mustChangePassword,
    lastSignInAt: previous[0] ? previous[0].issued_at : null,
  });
}

// POST /auth/change-password — the only data-changing route reachable
// while mustChangePassword is still true (see middleware/auth.js). Requires
// the current (temp) password, not just a SysAdmin override, so a stolen
// temp-password email alone isn't enough without also knowing it already.
async function changePassword(req, res) {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'currentPassword and newPassword are required' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'newPassword must be at least 8 characters' });
  }

  const { rows } = await db.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
  const user = rows[0];
  if (!user) return res.status(404).json({ error: 'User not found' });

  const ok = await bcrypt.compare(currentPassword, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Current password is incorrect' });

  const newHash = await bcrypt.hash(newPassword, 10);
  await db.query(
    'UPDATE users SET password_hash = $1, must_change_password = FALSE WHERE id = $2',
    [newHash, req.user.id]
  );

  return res.json({ message: 'Password changed successfully.' });
}

module.exports = { login, verifyMfa, logout, me, changePassword };
