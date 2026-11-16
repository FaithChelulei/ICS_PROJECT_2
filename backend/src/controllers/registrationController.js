// Registration request + admin approval. Nobody self-creates an account —
// anyone can submit a request (public route, no auth), but a `users` row
// only ever gets created when a SysAdmin approves one. This is the
// safeguarding control: unverified self-sign-up is a real risk on a
// child-data system, so a human reviews every request first.
const bcrypt = require('bcryptjs');
const db = require('../config/db');
const { logAction } = require('../utils/auditLog');
const { sendAccountApprovedEmail, sendAccountRejectedEmail } = require('../utils/mailer');
const { generateTempPassword } = require('../utils/tempPassword');
const { scoreAction, logOnlyAction, riskFields } = require('../services/actionScoring');
const { checkPrivacyNotice } = require('../services/privacyNotice');

// Derives a login username from a person's full name (e.g. "Faith Chelulei"
// -> "faith.chelulei") and makes it unique against existing usernames by
// appending a number if needed. This only has to run once, at account
// creation, so a few extra queries here is fine.
async function generateUsername(client, fullName) {
  const base = fullName
    .toLowerCase()
    .replace(/[^a-z\s]/g, '')
    .trim()
    .split(/\s+/)
    .join('.') || 'user';

  let candidate = base;
  let suffix = 1;
  for (;;) {
    const { rows } = await client.query('SELECT 1 FROM users WHERE username = $1', [candidate]);
    if (!rows[0]) return candidate;
    suffix += 1;
    candidate = `${base}${suffix}`;
  }
}

// Only these roles can be self-requested. A SysAdmin account is
// created by another SysAdmin directly (out of scope for this public
// form) — letting anyone request SysAdmin access would defeat the point
// of reviewing requests at all.
const REQUESTABLE_ROLES = ['Caregiver', 'Educator', 'SecurityAuditor'];
// Kenyan numbers as people write them: 0712 345 678, +254 712 345 678, 020 123 4567.
const PHONE_RE = /^\+?[0-9][0-9 ()-]{6,18}[0-9]$/;
const MIN_VERIFICATION_NOTE = 15;

// POST /auth/register — public, no auth required.
async function submitRequest(req, res) {
  const { fullName, email, requestedRole, reason } = req.body;
  const ecdCentre = typeof req.body.ecdCentre === 'string' ? req.body.ecdCentre.trim() : '';
  const centrePhone = typeof req.body.centrePhone === 'string' ? req.body.centrePhone.trim() : '';

  if (!fullName || !email || !requestedRole) {
    return res.status(400).json({ error: 'fullName, email and requestedRole are required' });
  }
  if (!REQUESTABLE_ROLES.includes(requestedRole)) {
    return res.status(400).json({ error: `requestedRole must be one of: ${REQUESTABLE_ROLES.join(', ')}` });
  }
  // An educator is verified with their ECD centre before approval, so the
  // request must say which centre and how to reach it.
  if (requestedRole === 'Educator') {
    if (ecdCentre.length < 3 || ecdCentre.length > 200) {
      return res.status(400).json({ error: 'Enter the ECD centre where you work.', code: 'ECD_CENTRE_REQUIRED' });
    }
    if (!PHONE_RE.test(centrePhone)) {
      return res.status(400).json({ error: 'Enter the ECD centre’s phone number, e.g. 0712 345 678.', code: 'CENTRE_PHONE_REQUIRED' });
    }
  }
  const noticeError = checkPrivacyNotice(req.body);
  if (noticeError) {
    return res.status(400).json({ error: noticeError, code: 'PRIVACY_NOTICE_REQUIRED' });
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
    `INSERT INTO registration_requests
       (full_name, email, requested_role_id, reason, privacy_notice_version, privacy_notice_accepted_at, ecd_centre, centre_phone)
     VALUES ($1, $2, $3, $4, $5, now(), $6, $7) RETURNING id, created_at`,
    [fullName, email, roleRows[0].id, reason || null, req.body.privacyNoticeVersion,
      requestedRole === 'Educator' ? ecdCentre : null, requestedRole === 'Educator' ? centrePhone : null]
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
  if (!['pending', 'approved', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'status must be pending, approved or rejected' });
  }
  const { rows } = await db.query(
    `SELECT rr.id, rr.full_name, rr.email, r.name AS requested_role, rr.reason,
            rr.ecd_centre, rr.centre_phone, rr.verification_note,
            rr.status, rr.created_at, rr.reviewed_at, rr.rejection_reason
     FROM registration_requests rr
     JOIN roles r ON r.id = rr.requested_role_id
     WHERE rr.status = $1
     ORDER BY rr.created_at ASC`,
    [status]
  );
  // The SysAdmin's home screen -- loads on sign-in, so log-only.
  await logOnlyAction(req, 'view_registration_requests');
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
    `SELECT rr.id, rr.full_name, rr.email, rr.requested_role_id, rr.status, r.name AS requested_role,
            rr.ecd_centre, rr.centre_phone
     FROM registration_requests rr JOIN roles r ON r.id = rr.requested_role_id
     WHERE rr.id = $1`,
    [requestId]
  );
  const request = reqRows[0];
  if (!request) return res.status(404).json({ error: 'Request not found' });
  if (request.status !== 'pending') {
    return res.status(409).json({ error: `Request is already ${request.status}` });
  }
  // An educator is approved only after the admin has confirmed with the ECD
  // centre that this person works there, and has written down how.
  const verificationNote = typeof (req.body || {}).verificationNote === 'string' ? req.body.verificationNote.trim() : '';
  const isEducator = request.requested_role === 'Educator';
  if (isEducator && verificationNote.length < MIN_VERIFICATION_NOTE) {
    return res.status(400).json({
      error: `Confirm with the ECD centre that this person works there, then say how you checked (at least ${MIN_VERIFICATION_NOTE} characters).`,
      code: 'VERIFICATION_NOTE_REQUIRED',
    });
  }

  const tempPassword = generateTempPassword();
  const passwordHash = await bcrypt.hash(tempPassword, 10);
  // MFA is required for every role now, Caregiver included: a compromised
  // Caregiver account exposes that family's child data just as directly as
  // a compromised staff account exposes system-wide data, so the same
  // second factor applies across the board (updated from the original
  // proposal, which only required it for SecurityAuditor/SysAdmin).
  const mfaRequired = true;

  const client = await db.pool.connect();
  let username;
  try {
    await client.query('BEGIN');

    username = await generateUsername(client, request.full_name);

    await client.query(
      `INSERT INTO users (email, full_name, username, password_hash, role_id, mfa_required, must_change_password,
                          ecd_centre, centre_phone, verification_note, verified_by, verified_at)
       VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7, $8, $9, $10, $11)`,
      [request.email, request.full_name, username, passwordHash, request.requested_role_id, mfaRequired,
        isEducator ? request.ecd_centre : null, isEducator ? request.centre_phone : null,
        isEducator ? verificationNote : null, isEducator ? req.user.id : null, isEducator ? new Date() : null]
    );

    await client.query(
      `UPDATE registration_requests
       SET status = 'approved', reviewed_by = $1, reviewed_at = now(), verification_note = $3
       WHERE id = $2`,
      [req.user.id, requestId, isEducator ? verificationNote : null]
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
    username,
    tempPassword,
  });

  // Creating an account is a privileged change -- scored (first, so the
  // audit entry is linked to its risk score).
  const risk = await scoreAction(req, 'approve_registration');
  await logAction({
    userId: req.user.id,
    action: 'approve_registration_request',
    detail: `request_id=${requestId}, new user email=${request.email}, role=${request.requested_role}${isEducator ? ', verified with the ECD centre' : ''}`,
    accessRequestId: risk.accessRequestId,
  });
  res.json({
    message: `Approved. Username "${username}" created; temporary password emailed to ${request.email}.`,
    username,
    ...riskFields(risk),
  });
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

  // Scored first, so the audit entry below is linked to its risk score.
  const risk = await scoreAction(req, 'reject_registration');
  await logAction({
    userId: req.user.id,
    action: 'reject_registration_request',
    detail: `request_id=${requestId}, email=${rows[0].email}`,
    accessRequestId: risk.accessRequestId,
  });
  res.json({ message: 'Request rejected.', ...riskFields(risk) });
}

module.exports = { submitRequest, listRequests, approveRequest, rejectRequest };
