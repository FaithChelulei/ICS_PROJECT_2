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

// The model's own answer, when the score was stored with it
// (db/008_score_evidence.sql): the features that raised the score, found by
// resetting each one to a normal session and re-scoring (ml/service/app.py).
// `drivers` is [{ feature, value, raised_by }], largest first.
const CATEGORY = {
  is_after_hours: 'Activity at night',
  is_own_pc: 'Unknown device',
  unique_pcs_used_that_day: 'Unknown device',
};

const describe = ({ feature, value }) => {
  const v = Math.round(Number(value) * 10) / 10;
  switch (feature) {
    case 'is_after_hours': return 'Activity after hours (20:00 to 06:00)';
    case 'is_own_pc': return 'A device this account had not used before';
    case 'unique_pcs_used_that_day': return `${v} devices used today`;
    case 'files_accessed_per_session': return `${v} records opened in this session`;
    case 'events_prev_hour': return `${v} actions in the last hour`;
    case 'events_prev_day': return `${v} actions in the last 24 hours`;
    case 'session_duration_minutes': return `Session length ${v} min`;
    default: return feature;
  }
};

const driversOf = (row) => (Array.isArray(row.drivers) ? row.drivers.filter((d) => d && d.feature) : []);

// For the queue: what raised this score, in words, largest first, e.g.
// [{ text: '35 actions in the last hour', raisedBy: 0.057 }]. Empty for
// scores stored before the evidence existed.
function mainFactors(row) {
  return driversOf(row).map((d) => ({ text: describe(d), raisedBy: Number(d.raised_by) }));
}

// One short category per flag, for the queue and the "likely reasons" chart.
// From the model's top factor when it was stored; otherwise estimated from
// the flagged action (night hours, else a device not seen in an earlier
// session, else high activity) as before.
function likelyReason(row) {
  const top = driversOf(row)[0];
  if (top) return CATEGORY[top.feature] || 'Unusually high activity';
  if (isAfterHours(new Date(row.requested_at))) return 'Activity at night';
  if (!row.known_device) return 'Unknown device';
  return 'Unusually high activity';
}

module.exports = { KNOWN_DEVICE_SQL, likelyReason, mainFactors };
