// Two-person approval (services/approvals.js): request, approve, reject.
// Requesting and deciding both need the person's password again (step-up)
// and a reason of at least 10 characters; the person who asked can never
// approve their own request.
const db = require('../config/db');
const { logAction } = require('../utils/auditLog');
const { logOnlyAction, scoreAction, riskFields } = require('../services/actionScoring');
const { ACTIONS, VALID_HOURS } = require('../services/approvals');
const { sendApprovalRequestEmail } = require('../utils/mailer');

const reasonOk = (r) => typeof r === 'string' && r.trim().length >= 10;

async function list(req, res) {
  const { rows } = await db.query(
    `SELECT pa.id, pa.action, pa.reason, pa.status, pa.requested_at, pa.decided_at, pa.used_at,
            pa.decision_reason, pa.requested_by, ru.full_name AS requested_by_name,
            du.full_name AS decided_by_name,
            (pa.status = 'pending' AND pa.requested_at < now() - make_interval(hours => $1)) AS expired,
            (pa.status = 'approved' AND pa.decided_at < now() - make_interval(hours => $1)) AS approval_expired
     FROM pending_approvals pa
     JOIN users ru ON ru.id = pa.requested_by
     LEFT JOIN users du ON du.id = pa.decided_by
     ORDER BY pa.requested_at DESC LIMIT 50`,
    [VALID_HOURS]
  );
  await logOnlyAction(req, 'view_approvals');
  res.json({
    approvals: rows.map((r) => ({ ...r, description: ACTIONS[r.action], mine: r.requested_by === req.user.id })),
    actions: ACTIONS,
  });
}

async function request(req, res) {
  const { action, reason } = req.body || {};
  if (!ACTIONS[action]) return res.status(400).json({ error: `action must be one of ${Object.keys(ACTIONS).join(', ')}` });
  if (!reasonOk(reason)) return res.status(400).json({ error: 'A reason of at least 10 characters is required.' });
  const { rows } = await db.query(
    `INSERT INTO pending_approvals (action, reason, requested_by) VALUES ($1, $2, $3) RETURNING id, requested_at`,
    [action, reason.trim().slice(0, 1000), req.user.id]
  );
  const risk = await scoreAction(req, 'request_approval');
  await logAction({
    userId: req.user.id, action: 'approval_requested',
    detail: `approval_id=${rows[0].id}, action=${action}`, accessRequestId: risk.accessRequestId,
  });
  const { rows: admins } = await db.query(
    `SELECT u.email FROM users u JOIN roles r ON r.id = u.role_id
     WHERE r.name = 'SysAdmin' AND u.id <> $1 AND NOT u.is_locked`,
    [req.user.id]
  );
  const requestedBy = req.user.fullName || req.user.email || `user ${req.user.id}`;
  await Promise.allSettled(admins.map((a) => sendApprovalRequestEmail(a.email, { action: ACTIONS[action], reason: reason.trim(), requestedBy })));
  res.status(201).json({ id: rows[0].id, status: 'pending', otherAdmins: admins.length, ...riskFields(risk) });
}

async function decide(req, res, decision) {
  const { reason } = req.body || {};
  if (!reasonOk(reason)) return res.status(400).json({ error: 'A reason of at least 10 characters is required.' });
  const id = Number(req.params.id);
  const { rows: found } = await db.query('SELECT * FROM pending_approvals WHERE id = $1', [id]);
  const row = found[0];
  if (!row) return res.status(404).json({ error: 'Approval request not found' });
  if (row.requested_by === req.user.id) {
    await logAction({ userId: req.user.id, action: 'approval_own_request_refused', detail: `approval_id=${id}` });
    return res.status(403).json({ error: 'A second System Administrator must decide on this request, not the person who asked.', code: 'OWN_REQUEST' });
  }
  const risk = await scoreAction(req, 'decide_approval');
  const { rows } = await db.query(
    `UPDATE pending_approvals SET status = $1, decided_by = $2, decision_reason = $3, decided_at = now()
     WHERE id = $4 AND status = 'pending' AND requested_at > now() - make_interval(hours => $5)
     RETURNING id`,
    [decision, req.user.id, reason.trim().slice(0, 1000), id, VALID_HOURS]
  );
  if (!rows[0]) return res.status(409).json({ error: 'This request has already been decided or has expired (24 hours).' });
  await logAction({
    userId: req.user.id, action: `approval_${decision}`,
    detail: `approval_id=${id}, action=${row.action}, requested_by=${row.requested_by}`, accessRequestId: risk.accessRequestId,
  });
  res.json({ id, status: decision, ...riskFields(risk) });
}

module.exports = {
  list,
  request,
  approve: (req, res) => decide(req, res, 'approved'),
  reject: (req, res) => decide(req, res, 'rejected'),
};
