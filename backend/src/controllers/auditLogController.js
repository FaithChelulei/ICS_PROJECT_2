// Read side of the audit trail. The WRITE side (utils/auditLog.js's
// logAction, called from every controller that touches child data or
// account state) has existed since an earlier day -- this is just the
// first route that reads audit_log back out, for the Security Auditor's
// "Audit Log" screen. Permission: 'view_audit_log' (see middleware/rbac.js).
const db = require('../config/db');
const { scoreAction, RISK_NOTICE } = require('../services/actionScoring');

// A date (2026-11-09) or a date and time (2026-11-09T14:30, optionally with
// seconds and a time zone). Anything else would fail inside PostgreSQL.
const DATE_TIME_RE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:\d{2})?)?$/;
const validDateTime = (v) => DATE_TIME_RE.test(v) && !Number.isNaN(new Date(v).getTime());

async function listAuditLog(req, res) {
  for (const name of ['from', 'to']) {
    if (req.query[name] && !validDateTime(req.query[name])) {
      return res.status(400).json({ error: `${name} must be a date (YYYY-MM-DD) or a date and time (YYYY-MM-DDTHH:MM)` });
    }
  }
  if (req.query.limit !== undefined && !/^\d{1,4}$/.test(req.query.limit)) {
    return res.status(400).json({ error: 'limit must be a whole number from 1 to 200' });
  }

  // Reading the audit trail is the sensitive data read for this role, so it
  // is scored -- BEFORE anything is read, like report downloads: if this is
  // the read that crosses the limit (mass scraping), nothing is sent.
  const risk = await scoreAction(req, 'view_audit_log');
  if (risk.flagged) {
    return res.status(401).json({ error: RISK_NOTICE, code: 'SESSION_REVOKED_RISK' });
  }

  const limit = Math.max(1, Math.min(Number(req.query.limit) || 100, 200));
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

  res.json({ entries: rows, totalEvents: countRows[0].total });
}

module.exports = { listAuditLog };
