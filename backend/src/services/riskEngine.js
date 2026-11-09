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
const { thresholdFor } = require('./riskThresholds');
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
// `now` defaults to the real time. Only the anomaly-injection test passes
// one (to replay night-time activity); no request can set it.
async function logAccessRequest({ userId, actionType, childProfileId = null, pcName, ipAddress, sessionId, now = new Date() }) {
  const accessRequestId = await insertAccessRequest({ userId, childProfileId, actionType, pcName, ipAddress, sessionId, now });
  return { accessRequestId, scored: false, flagged: false };
}

// The evidence columns come from db/008_score_evidence.sql. Until that has
// been applied, scores are still stored, just without the evidence, so an
// install that has not migrated yet keeps working. Checked once.
let evidenceColumns = null;
function hasEvidenceColumns() {
  if (!evidenceColumns) {
    evidenceColumns = db.query(
      `SELECT count(*)::int AS n FROM information_schema.columns
       WHERE table_name = 'risk_scores' AND column_name IN ('features', 'drivers', 'model_version')`
    ).then(({ rows }) => {
      if (rows[0].n !== 3) console.warn('[risk-engine] run node db/migrate.js to store the evidence with each score (008_score_evidence.sql)');
      return rows[0].n === 3;
    }).catch(() => false);
  }
  return evidenceColumns;
}

async function recordAndScore({ userId, role, actionType, childProfileId = null, pcName, ipAddress, sessionId, now = new Date() }) {

  const accessRequestId = await insertAccessRequest({ userId, childProfileId, actionType, pcName, ipAddress, sessionId, now });

  const features = await computeFeatures({ userId, sessionId, pcName, now, role });
  const result = await scoreSession(role, features);

  if (!result) {
    // ML service unreachable or errored -- the action itself already
    // succeeded; don't block it over a missing risk score. Visible in
    // server logs via mlClient.js.
    return { accessRequestId, scored: false, flagged: false };
  }

  // The model gives the score; the limit in force may be one the Security
  // Auditor has set on screen (FR-21), so the decision is made here.
  const threshold = await thresholdFor(role, result.threshold);
  const flagged = Number(result.risk_score) >= threshold;

  const values = [accessRequestId, result.iso_score, result.ae_score, result.risk_score, threshold, flagged];
  const { rows: riskRows } = (await hasEvidenceColumns())
    ? await db.query(
      `INSERT INTO risk_scores
         (access_request_id, isoforest_score, autoencoder_score, combined_score, role_threshold, is_flagged,
          features, drivers, model_version)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
      [...values, JSON.stringify(features), JSON.stringify(result.drivers || []), result.model_version || null]
    )
    : await db.query(
      `INSERT INTO risk_scores
         (access_request_id, isoforest_score, autoencoder_score, combined_score, role_threshold, is_flagged)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      values
    );
  const riskScoreId = riskRows[0].id;

  if (flagged) {
    await handleFlagged({ riskScoreId, accessRequestId, sessionId, userId, role, pcName, actionType, now });
  }

  return { accessRequestId, riskScoreId, scored: true, flagged, riskScore: result.risk_score };
}

// Applies the automatic half of risk_tiers.json's response_policy. The
// parallel human-review half needs no code here -- auditor_status already
// defaults to 'pending' on insert, which is what puts it in the auditor's
// queue (see auditorController.js listFlagged).
async function handleFlagged({ riskScoreId, accessRequestId, sessionId, userId, role, pcName, actionType, now }) {
  await db.query(
    "UPDATE sessions SET revoked_at = now(), revoked_reason = 'risk_flagged' WHERE id = $1",
    [sessionId]
  );

  await logAction({
    userId,
    action: 'risk_flagged_session_revoked',
    detail: `risk_score_id=${riskScoreId}, action_type=${actionType}, pc=${pcName || 'unknown'}`,
    // Links this audit entry back to its risk_scores row (via
    // access_requests) so the Audit Log's Risk/Outcome columns can show
    // the real score instead of "unscored" for the one action type that
    // is actually risk-tied.
    accessRequestId,
  });

  const { rows } = await db.query('SELECT email FROM users WHERE id = $1', [userId]);
  const email = rows[0] && rows[0].email;
  if (!email) return; // shouldn't happen, but a missing email must not crash the request

  const confirmToken = signRiskResponseToken(riskScoreId, 'confirm');
  const denyToken = signRiskResponseToken(riskScoreId, 'deny');
  const base = process.env.APP_BASE_URL || 'https://localhost:4000';

  // The session is already revoked and the auditor queue item already
  // exists at this point -- an email outage must not turn the user's
  // (already completed) action into a 500. Log it and move on.
  try {
    await sendRiskAlertEmail(email, {
      timestamp: now.toISOString(),
      pcName: pcName || 'unknown device',
      actionType,
      role,
      confirmUrl: `${base}/risk-response/${riskScoreId}/confirm?token=${confirmToken}`,
      denyUrl: `${base}/risk-response/${riskScoreId}/deny?token=${denyToken}`,
    });
  } catch (err) {
    console.error(`[risk-engine] risk alert email to user ${userId} failed:`, err.message);
  }
}

module.exports = { logAccessRequest, recordAndScore };
