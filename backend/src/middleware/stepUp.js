// Step-up authentication for the most sensitive admin actions (re-encrypting
// all data, anonymising archived profiles): the admin re-enters their
// password in the request body. A session left open, or a stolen session
// token, is not enough to run them.
//
// Refusals are 403, never 401: the frontend treats 401 as "session ended"
// and signs the user out, which a mistyped password must not do. Wrong
// passwords are recorded in the audit log, and 5 failures in 15 minutes
// stops further tries for that account (held in memory: a backend restart
// clears it).
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const db = require('../config/db');
const { logAction } = require('../utils/auditLog');
const asyncHandler = require('../utils/asyncHandler');

const stepUpFailureLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  // Only a wrong password counts. Without this, any refusal after the
  // password check (a reason too short, a value out of range) would count
  // too, and five ordinary mistakes would lock the user out.
  skipSuccessfulRequests: true,
  requestWasSuccessful: (req, res) => !res.locals.stepUpFailed,
  keyGenerator: (req) => `step-up:${req.user.id}`,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  handler: (req, res) => res.status(429).json({
    error: 'Too many incorrect passwords. Try again in 15 minutes.',
    code: 'STEP_UP_LOCKED',
  }),
});

async function checkPassword(req, res, next) {
  const password = req.body && req.body.password;
  if (typeof password !== 'string' || !password) {
    return res.status(403).json({ error: 'Enter your password to confirm this action.', code: 'STEP_UP_REQUIRED' });
  }
  const { rows } = await db.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
  const ok = rows[0] && (await bcrypt.compare(password, rows[0].password_hash));
  if (!ok) {
    res.locals.stepUpFailed = true;
    await logAction({ userId: req.user.id, action: 'step_up_failed', detail: `${req.method} ${req.originalUrl}` });
    return res.status(403).json({ error: 'That password is not correct.', code: 'STEP_UP_FAILED' });
  }
  next();
}

const requireStepUp = [stepUpFailureLimit, asyncHandler(checkPassword)];

module.exports = { requireStepUp };
