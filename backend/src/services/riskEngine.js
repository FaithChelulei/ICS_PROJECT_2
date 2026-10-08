// Orchestrates one full risk-scoring cycle for a session-relevant action:
// log it to access_requests, compute the 7 live features, call the Flask
// ML service, store the result in risk_scores, and -- if it crosses this
// role's review_threshold -- apply ml/models/risk_tiers.json's documented
// response policy: revoke the session, email the owner a "This was me /
// This was NOT me" link, and queue the session for Security Auditor review
// in parallel (auditor_status stays 'pending', its default -- no extra
// write needed to put it in the queue).
const db = require('../config/db');
const { computeFeatures } = require('./featureComputation');
const { scoreSession } = require('../utils/mlClient');
const { sendRiskAlertEmail } = require('../utils/mailer');
const { logAction } = require('../utils/auditLog');
const { signRiskResponseToken } = require('../utils/riskResponseToken');

async function insertAccessRequest({ userId, childProfileId, actionType, pcName, ipAddress, sessionId, now }) {
  const { rows } = await db.query(
    `INSERT INTO access_requests (user_id, child_profile_id, action_type, pc_name, ip_address, session_id, requested_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
    [userId, childProfileId, actionType, pcName, ipAddress, sessionId, now]
  );
  return rows[0].id;
}

// Logs an action to access_requests WITHOUT scoring it. Used for login:
// the ML model was trained on COMPLETED sessions that already had real
// activity in them, so scoring at the bare moment of login -- 0 files
// accessed, ~0 session duration -- compares a session against a baseline
// it cannot possibly match yet, which flagged nearly every login in
// testing regardless of role. Login is still logged (it feeds
// events_prev_hour/day, unique_pcs_used_that_day and is_own_pc for
// whatever gets scored next), just not scored on its own. See
// recordAndScore for where real scoring happens: the first actual
// data-touching action, which is also a closer match to what this system
// is actually trying to catch -- unauthorized ACCESS to child data, not
// the act of logging in by itself.
async function logAccessRequest({ userId, actionType, childProfileId = null, pcName, ipAddress, sessionId }) {
  const now = new Date();
  const accessRequestId = await insertAccessRequest({ userId, childProfileId, actionType, pcName, ipAddress, sessionId, now });
  return { accessRequestId, scored: false, flagged: false };
}

async function recordAndScore({ userId, role, actionType, childProfileId = null, pcName, ipAddress, sessionId }) {
  const now = new Date();

  const accessRequestId = await insertAccessRequest({ userId, childProfileId, actionType, pcName, ipAddress, sessionId, now });

  const features = await computeFeatures({ userId, sessionId, pcName, now, role });
  const result = await scoreSession(role, features);

  if (!result) {
    // ML service unreachable or errored -- the action itself already
    // succeeded; don't block it over a missing risk score. Visible in
    // server logs via mlClient.js.
    return { accessRequestId, scored: false, flagged: false };
  }

  const { rows: riskRows } = await db.query(
    `INSERT INTO risk_scores
       (access_request_id, isoforest_score, autoencoder_score, combined_score, role_threshold, is_flagged)
     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
    [accessRequestId, result.iso_score, result.ae_score, result.risk_score, result.threshold, result.flagged]
  );
  const riskScoreId = riskRows[0].id;

  if (result.flagged) {
    await handleFlagged({ riskScoreId, sessionId, userId, role, pcName, actionType, now });
  }

  return { accessRequestId, riskScoreId, scored: true, flagged: result.flagged, riskScore: result.risk_score };
}

// Applies the automatic half of risk_tiers.json's response_policy. The
// parallel human-review half needs no code here -- auditor_status already
// defaults to 'pending' on insert, which is what puts it in the auditor's
// queue (see auditorController.js listFlagged).
async function handleFlagged({ riskScoreId, sessionId, userId, role, pcName, actionType, now }) {
  await db.query(
    "UPDATE sessions SET revoked_at = now(), revoked_reason = 'risk_flagged' WHERE id = $1",
    [sessionId]
  );

  await logAction({
    userId,
    action: 'risk_flagged_session_revoked',
    detail: `risk_score_id=${riskScoreId}, action_type=${actionType}, pc=${pcName || 'unknown'}`,
  });

  const { rows } = await db.query('SELECT email FROM users WHERE id = $1', [userId]);
  const email = rows[0] && rows[0].email;
  if (!email) return; // shouldn't happen, but a missing email must not crash the request

  const confirmToken = signRiskResponseToken(riskScoreId, 'confirm');
  const denyToken = signRiskResponseToken(riskScoreId, 'deny');
  const base = process.env.APP_BASE_URL || 'http://localhost:4000';

  await sendRiskAlertEmail(email, {
    timestamp: now.toISOString(),
    pcName: pcName || 'unknown device',
    actionType,
    role,
    confirmUrl: `${base}/risk-response/${riskScoreId}/confirm?token=${confirmToken}`,
    denyUrl: `${base}/risk-response/${riskScoreId}/deny?token=${denyToken}`,
  });
}

module.exports = { logAccessRequest, recordAndScore };
