// Verifies the JWT on every request AND checks the server-side session
// table (schema: sessions). The second check is what actually makes the
// risk-tier "force logout" response work: revoking a session here takes
// effect immediately, instead of waiting for the JWT to expire on its own.
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const asyncHandler = require('../utils/asyncHandler');

async function authenticateHandler(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Missing bearer token' });
  }

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  const { rows } = await db.query(
    `SELECT s.revoked_at, s.revoked_reason, u.email, u.must_change_password
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.id = $1`,
    [payload.sessionId]
  );
  const session = rows[0];

  if (!session || session.revoked_at) {
    // Either the session never existed, or it was force-revoked by the
    // automatic risk response — in both cases the user must log in again.
    // The code lets the login screen say WHY (risk flag vs. normal logout).
    if (session && session.revoked_reason === 'risk_flagged') {
      return res.status(401).json({
        error: 'You were signed out because unusual activity was detected. Check your email to confirm whether it was you, then sign in again.',
        code: 'SESSION_REVOKED_RISK',
      });
    }
    return res.status(401).json({ error: 'Session has been revoked, please log in again', code: 'SESSION_REVOKED' });
  }

  req.user = {
    id: payload.userId,
    role: payload.role,
    sessionId: payload.sessionId,
    email: session.email,
    mustChangePassword: session.must_change_password,
  };
  // Everything downstream of this point (route handlers, services) runs as
  // this user, so the database's row-level security policies can see who
  // is asking -- see config/db.js.
  db.runAs({ userId: payload.userId, role: payload.role }, next);
}

// The DB query above has no try/catch of its own -- without this wrapper
// a Postgres hiccup here (this middleware runs in front of almost every
// route) would hang the request instead of failing cleanly.
const authenticate = asyncHandler(authenticateHandler);

// Blocks every data route until a temp password (set at registration
// approval or account unlock) has been changed. Deliberately NOT applied
// to /auth/me or /auth/change-password — those have to stay reachable
// while this flag is still true, or the user could never clear it.
function requirePasswordChanged(req, res, next) {
  if (req.user && req.user.mustChangePassword) {
    return res.status(403).json({
      error: 'You must change your temporary password before continuing.',
      code: 'MUST_CHANGE_PASSWORD',
    });
  }
  next();
}

module.exports = { authenticate, requirePasswordChanged };
