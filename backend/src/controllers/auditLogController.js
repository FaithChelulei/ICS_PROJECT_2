// Read side of the audit trail. The WRITE side (utils/auditLog.js's
// logAction, called from every controller that touches child data or
// account state) has existed since an earlier day -- this is just the
// first route that reads audit_log back out, for the Security Auditor's
// "Audit Log" screen. Permission: 'view_audit_log' (see middleware/rbac.js).
const db = require('../config/db');
const { scoreAction, riskFields } = require('../services/actionScoring');

async function listAuditLog(req, res) {
  const limit = Math.min(Number(req.query.limit) || 100, 200);
  const params = [];
  const clauses = [];

  if (req.query.action) {
    params.push(req.query.action);
    clauses.push(`al.action = $${params.length}`);
  }
  if (req.query.from) {
    params.push(req.query.from);
    clauses.push(`al.created_at >= $${params.length}`);
  }
  if (req.query.to) {
    params.push(req.query.to);
    clauses.push(`al.created_at <= $${params.length}`);
  }
  if (req.query.q) {
    params.push(`%${req.query.q}%`);
    clauses.push(`(u.email ILIKE $${params.length} OR al.action ILIKE $${params.length} OR al.detail ILIKE $${params.length})`);
  }

  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  params.push(limit);

  const { rows } = await db.query(
    `SELECT al.id, al.created_at, al.action, al.detail,
            u.email, r.name AS role,
            rs.combined_score, rs.is_flagged
     FROM audit_log al
     LEFT JOIN users u ON u.id = al.user_id
     LEFT JOIN roles r ON r.id = u.role_id
     LEFT JOIN access_requests ar ON ar.id = al.access_request_id
     LEFT JOIN risk_scores rs ON rs.access_request_id = ar.id
     ${where}
     ORDER BY al.created_at DESC
     LIMIT $${params.length}`,
    params
  );

  const { rows: countRows } = await db.query('SELECT count(*)::int AS total FROM audit_log');

  // Reading the audit trail is the sensitive data read for this role --
  // scored, so mass scraping of the log stands out.
  const risk = await scoreAction(req, 'view_audit_log');
  res.json({ entries: rows, totalEvents: countRows[0].total, ...riskFields(risk) });
}

module.exports = { listAuditLog };
