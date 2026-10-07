// Verifies the JWT on every request AND checks the server-side session
// table (schema: sessions). The second check is what actually makes the
// risk-tier "force logout" response work: revoking a session here takes
// effect immediately, instead of waiting for the JWT to expire on its own.
const jwt = require('jsonwebtoken');
const db = require('../config/db');

async function authenticate(req, res, next) {
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

  const { data: session } = await db.query(
    'SELECT revoked_at FROM sessions WHERE id = $1',
    [payload.sessionId]
  ).then((r) => ({ data: r.rows[0] }));

  if (!session || session.revoked_at) {
    // Either the session never existed, or it was force-revoked by the
    // automatic risk response — in both cases the user must log in again.
    return res.status(401).json({ error: 'Session has been revoked, please log in again' });
  }

  req.user = {
    id: payload.userId,
    role: payload.role,
    sessionId: payload.sessionId,
  };
  next();
}

module.exports = { authenticate };
