// Shared request -> risk-engine glue for controllers outside
// childRecordsController.js (which has its own copy of the same two
// helpers). Two kinds of action:
//
//   scoreAction    -- a real data read or privileged change (reading the
//                     audit log, reviewing a flag, approving an account,
//                     unlocking an account). Logged AND scored; crossing the
//                     role's threshold revokes the session, emails the
//                     owner and queues the session for auditor review.
//   logOnlyAction  -- passive navigation (the list a dashboard loads the
//                     moment someone signs in). Logged so it still feeds
//                     events_prev_hour/day, but not scored on its own --
//                     same reasoning as the Caregiver dashboard list.
const { recordAndScore, logAccessRequest } = require('./riskEngine');
const { getPcName, getIpAddress } = require('../utils/requestMeta');

const RISK_NOTICE =
  'Unusual activity detected during this action. You have been logged out as a precaution — check your email to confirm or report it.';

// Roles whose actions are actually sent to the model in the live app -- all
// three. Each needs a deployment_threshold in ml/models/risk_tiers.json:
// at its research threshold (0.31) a normal auditor triage session of 2-3
// actions already scored above the line, so SecurityAuditor was held at
// log-only until it was calibrated at 0.65 (see docs/RISK_THRESHOLDS.md).
// A role can be taken back to log-only by removing it from this list.
const ROLES_SCORED_LIVE = ['Caregiver', 'SysAdmin', 'SecurityAuditor'];

function scoreAction(req, actionType, childProfileId = null) {
  if (!ROLES_SCORED_LIVE.includes(req.user.role)) {
    return logOnlyAction(req, actionType, childProfileId);
  }
  return recordAndScore({
    userId: req.user.id,
    role: req.user.role,
    actionType,
    childProfileId,
    pcName: getPcName(req),
    ipAddress: getIpAddress(req),
    sessionId: req.user.sessionId,
  });
}

function logOnlyAction(req, actionType, childProfileId = null) {
  return logAccessRequest({
    userId: req.user.id,
    actionType,
    childProfileId,
    pcName: getPcName(req),
    ipAddress: getIpAddress(req),
    sessionId: req.user.sessionId,
  });
}

// Spread into a JSON response: { ...riskFields(risk) }
function riskFields(risk) {
  return risk && risk.flagged ? { riskNotice: RISK_NOTICE } : {};
}

module.exports = { scoreAction, logOnlyAction, riskFields, RISK_NOTICE };
