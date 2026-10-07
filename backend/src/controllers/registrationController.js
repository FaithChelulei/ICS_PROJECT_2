// Registration request + admin approval. Nobody self-creates an account —
// anyone can submit a request (public route, no auth), but a `users` row
// only ever gets created when a SysAdmin approves one. This is the
// safeguarding control: unverified self-sign-up is a real risk on a
// child-data system, so a human reviews every request first.
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const db = require('../config/db');
const { logAction } = require('../utils/auditLog');
const { sendAccountApprovedEmail, sendAccountRejectedEmail } = require('../utils/mailer');

// Only these two roles can be self-requested. A SysAdmin account is
// created by another SysAdmin directly (out of scope for this public
// form) — letting anyone request SysAdmin access would defeat the point
// of reviewing requests at all.
const REQUESTABLE_ROLES = ['Caregiver', 'SecurityAuditor'];

function generateTempPassword() {
  // 16 random bytes, base64url-encoded — short enough to type from an
  // email, long enough to not be guessable before the forced change.
  return crypto.randomBytes(16).toString('base64url');
}

// POST /auth/register — public, no auth required.
async function submitRequest(req, res) {
  const { fullName, email, requestedRole, reason } = req.body;

  if (!fullName || !email || !requestedRole) {
    return res.status(400).json({ error: 'fullName, email and requestedRole are required' });
  }
  if (!REQUESTABLE_ROLES.includes(requestedRole)) {
    return res.status(400).json({ error: `requestedRole must be one of: ${REQUESTABLE_ROLES.join(', ')}` });
  }

  const { rows: existingUser } = await db.query('SELECT id FROM users WHERE email = $1', [email]);
  if (existingUser[0]) {
    // Same generic phrasing style as login — don't confirm/deny account
    // existence any more than necessary, even here.
    return res.status(409).json({ error: 'An account with this email already exists' });
  }

  const { rows: pending } = await db.query(
    "SELECT id FROM registration_requests WHERE email = $1 AND status = 'pending'",
    [email]
  );
  if (pending[0]) {
    return res.status(409).json({ error: 'A pending request for this email already exists' });
  }

  const { rows: roleRows } = await db.query('SELECT id FROM roles WHERE name = $1', [requestedRole]);
  const { rows } = await db.query(
    `INSERT INTO registration_requests (full_name, email, requested_role_id, reason)
     VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
    [fullName, email, roleRows[0].id, reason || null]
  );

  res.status(201).json({
    requestId: rows[0].id,
    status: 'pending',
    message: 'Your request has been submitted and will be reviewed by a System Administrator.',
  });
}

// GET /admin/registration-requests?status=pending — SysAdmin only.
async function listRequests(req, res) {
  const status = req.query.status || 'pending';
  const { rows } = await db.query(
    `SELECT rr.id, rr.full_name, rr.email, r.name AS requested_role, rr.reason,
            rr.status, rr.created_at, rr.reviewed_at, rr.rejection_reason
     FROM registration_requests rr
     JOIN roles r ON r.id = rr.requested_role_id
     WHERE rr.status = $1
     ORDER BY rr.created_at ASC`,
    [status]
  );
  res.json({ requests: rows });
}

// POST /admin/registration-requests/:id/approve — SysAdmin only. Creates
// the real users row and emails a one-time temp password. The plaintext
// password exists only in memory for the length of this function and in
// the email it's sent in — never written to a log, never put in the DB
// (only its bcrypt hash is), never returned in this response body.
async function approveRequest(req, res) {
  const requestId = Number(req.params.id);

  const { rows: reqRows } = await db.query(
    `SELECT rr.id, rr.full_name, rr.email, rr.requested_role_id, rr.status, r.name AS requested_role
     FROM registration_requests rr JOIN roles r ON r.id = rr.requested_role_id
     WHERE rr.id = $1`,
    [requestId]
  );
  const request = reqRows[0];
  if (!request) return res.status(404).json({ error: 'Request not found' });
  if (request.status !== 'pending') {
    return res.status(409).json({ error: `Request is already ${request.status}` });
  }

  const tempPassword = generateTempPassword();
  const passwordHash = await bcrypt.hash(tempPassword, 10);
  const mfaRequired = request.requested_role === 'SecurityAuditor';

  const client = await db.pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(
      `INSERT INTO users (email, password_hash, role_id, mfa_required, must_change_password)
       VALUES ($1, $2, $3, $4, TRUE)`,
      [request.email, passwordHash, request.requested_role_id, mfaRequired]
    );

    await client.query(
      `UPDATE registration_requests
       SET status = 'approved', reviewed_by = $1, reviewed_at = now()
       WHERE id = $2`,
      [req.user.id, requestId]
    );

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    return res.status(500).json({ error: 'Failed to approve request' });
  } finally {
    client.release();
  }

  await sendAccountApprovedEmail(request.email, {
    fullName: request.full_name,
    role: request.requested_role,
    tempPassword,
  });

  await logAction({
    userId: req.user.id,
    action: 'approve_registration_request',
    detail: `request_id=${requestId}, new user email=${request.email}, role=${request.requested_role}`,
  });

  res.json({ message: `Approved. Temporary password emailed to ${request.email}.` });
}

// POST /admin/registration-requests/:id/reject — SysAdmin only.
async function rejectRequest(req, res) {
  const requestId = Number(req.params.id);
  const { rejectionReason } = req.body;

  const { rows } = await db.query(
    `UPDATE registration_requests
     SET status = 'rejected', reviewed_by = $1, reviewed_at = now(), rejection_reason = $2
     WHERE id = $3 AND status = 'pending'
     RETURNING full_name, email`,
    [req.user.id, rejectionReason || null, requestId]
  );
  if (!rows[0]) {
    return res.status(404).json({ error: 'Pending request not found' });
  }

  await sendAccountRejectedEmail(rows[0].email, {
    fullName: rows[0].full_name,
    reason: rejectionReason,
  });

  await logAction({
    userId: req.user.id,
    action: 'reject_registration_request',
    detail: `request_id=${requestId}, email=${rows[0].email}`,
  });

  res.json({ message: 'Request rejected.' });
}

module.exports = { submitRequest, listRequests, approveRequest, rejectRequest };
