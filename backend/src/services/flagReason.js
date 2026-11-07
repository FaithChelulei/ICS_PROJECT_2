// A plain-language LIKELY reason for a risk flag, for the auditor's screens.
// The model returns a score, not an explanation, and the features it saw are
// not stored, so this is an estimate from the flagged action itself: night
// hours (same rule as the live feature), else a device the account hadn't
// used in an earlier session (same rule as isOwnDevice), else high activity.
// `ar` must be the access_requests alias in the query.
const { isAfterHours } = require('./featureComputation');

const KNOWN_DEVICE_SQL = `(
  ar.pc_name IS NULL
  OR NOT EXISTS (SELECT 1 FROM access_requests p
                 WHERE p.user_id = ar.user_id AND p.pc_name IS NOT NULL
                   AND p.requested_at < ar.requested_at AND p.session_id IS DISTINCT FROM ar.session_id)
  OR EXISTS (SELECT 1 FROM access_requests p
             WHERE p.user_id = ar.user_id AND p.pc_name = ar.pc_name
               AND p.requested_at < ar.requested_at AND p.session_id IS DISTINCT FROM ar.session_id)
)`;

function likelyReason({ requested_at: requestedAt, known_device: knownDevice }) {
  if (isAfterHours(new Date(requestedAt))) return 'Activity at night';
  if (!knownDevice) return 'Unknown device';
  return 'Unusually high activity';
}

module.exports = { KNOWN_DEVICE_SQL, likelyReason };
