// Public endpoints behind the "This was me" / "This was NOT me" links in
// the risk-alert email (riskEngine.js -> mailer.js sendRiskAlertEmail).
// Deliberately NOT behind the authenticate middleware: reaching this link
// means the user's session was already force-revoked, so they have no
// valid bearer token to present. The signed token in the URL
// (riskResponseToken.js) proves intent instead.
const db = require('../config/db');
const { verifyRiskResponseToken } = require('../utils/riskResponseToken');
const { logAction } = require('../utils/auditLog');

async function loadRiskScore(riskScoreId) {
  const { rows } = await db.query(
    `SELECT rs.id, rs.owner_response, rs.auditor_status, ar.user_id
     FROM risk_scores rs
     JOIN access_requests ar ON ar.id = rs.access_request_id
     WHERE rs.id = $1`,
    [riskScoreId]
  );
  return rows[0] || null;
}

function htmlPage(message) {
  return `<!doctype html><html><body style="font-family: sans-serif; max-width: 480px; margin: 60px auto; text-align: center;"><p>${message}</p></body></html>`;
}

async function confirm(req, res) {
  const riskScoreId = Number(req.params.riskScoreId);
  const { token } = req.query;

  if (!verifyRiskResponseToken(token, riskScoreId, 'confirm')) {
    return res.status(403).send(htmlPage('This link is invalid or has expired.'));
  }

  const risk = await loadRiskScore(riskScoreId);
  if (!risk) return res.status(404).send(htmlPage('This alert could not be found.'));

  if (risk.owner_response !== 'pending') {
    return res.send(htmlPage('You already responded to this alert. No further action needed.'));
  }

  await db.query("UPDATE risk_scores SET owner_response = 'confirmed_benign' WHERE id = $1", [riskScoreId]);
  await logAction({
    userId: risk.user_id,
    action: 'risk_response_confirmed_benign',
    detail: `risk_score_id=${riskScoreId}`,
  });

  return res.send(htmlPage(
    'Thanks for confirming. You can log in again normally. This activity has still been logged for routine security review.'
  ));
}

async function deny(req, res) {
  const riskScoreId = Number(req.params.riskScoreId);
  const { token } = req.query;

  if (!verifyRiskResponseToken(token, riskScoreId, 'deny')) {
    return res.status(403).send(htmlPage('This link is invalid or has expired.'));
  }

  const risk = await loadRiskScore(riskScoreId);
  if (!risk) return res.status(404).send(htmlPage('This alert could not be found.'));

  if (risk.owner_response !== 'pending') {
    return res.send(htmlPage('You already responded to this alert. No further action needed.'));
  }

  await db.query(
    "UPDATE risk_scores SET owner_response = 'not_me', auditor_status = 'escalated' WHERE id = $1",
    [riskScoreId]
  );
  await db.query(
    "UPDATE users SET is_locked = TRUE, locked_reason = 'Owner reported unrecognized activity -- pending password reset' WHERE id = $1",
    [risk.user_id]
  );
  await logAction({
    userId: risk.user_id,
    action: 'risk_response_not_me_account_locked',
    detail: `risk_score_id=${riskScoreId}`,
  });

  return res.send(htmlPage(
    'Your account has been locked for safety. Contact a System Administrator to reset your password.'
  ));
}

module.exports = { confirm, deny };
