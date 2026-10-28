// Security Auditor review queue for ML-flagged sessions. Runs in PARALLEL
// with the owner's own "This was me / NOT me" email response, independent
// of it -- risk_tiers.json's at_or_above_review_threshold_human: a
// compromised account's owner (i.e. an attacker) could also click
// "This was me", so this human review is the backstop that doesn't rely
// on the account owner's own honesty.
const db = require('../config/db');
const { logAction } = require('../utils/auditLog');
const { scoreAction, logOnlyAction, riskFields } = require('../services/actionScoring');

async function listFlagged(req, res) {
  // This queue is scoped to FLAGGED sessions only (is_flagged = true) --
  // every scored session gets an auditor_status of 'pending' by default,
  // flagged or not, so without this filter an ordinary below-threshold
  // login would clutter the review queue right alongside real alerts.
  const status = req.query.status || 'pending';
  const params = [];
  let where = 'WHERE rs.is_flagged = TRUE';
  if (status !== 'all') {
    params.push(status);
    where += ` AND rs.auditor_status = $${params.length}`;
  }

  const { rows } = await db.query(
    `SELECT rs.id AS risk_score_id, rs.combined_score, rs.role_threshold, rs.is_flagged,
            rs.owner_response, rs.auditor_status, rs.created_at,
            ar.action_type, ar.pc_name, ar.ip_address,
            u.id AS user_id, u.email, r.name AS role
     FROM risk_scores rs
     JOIN access_requests ar ON ar.id = rs.access_request_id
     JOIN users u ON u.id = ar.user_id
     JOIN roles r ON r.id = u.role_id
     ${where}
     ORDER BY rs.created_at DESC`,
    params
  );

  // The auditor's home screen -- loads on sign-in and after every review.
  await logOnlyAction(req, 'view_flagged_sessions');
  res.json({ flaggedSessions: rows });
}

async function reviewFlagged(req, res) {
  const riskScoreId = Number(req.params.riskScoreId);
  const { status } = req.body;
  const allowed = ['reviewing', 'confirmed', 'escalated'];
  if (!allowed.includes(status)) {
    return res.status(400).json({ error: `status must be one of ${allowed.join(', ')}` });
  }

  const { rows } = await db.query(
    'UPDATE risk_scores SET auditor_status = $1 WHERE id = $2 RETURNING id',
    [status, riskScoreId]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Risk score not found' });

  await logAction({
    userId: req.user.id,
    action: 'auditor_reviewed_flagged_session',
    detail: `risk_score_id=${riskScoreId}, new_status=${status}`,
  });

  // Scored: an insider auditor quietly closing out many alerts is exactly
  // the kind of behaviour this role's model should see.
  const risk = await scoreAction(req, 'review_flagged_session');
  res.json({ riskScoreId, auditorStatus: status, ...riskFields(risk) });
}

module.exports = { listFlagged, reviewFlagged };
