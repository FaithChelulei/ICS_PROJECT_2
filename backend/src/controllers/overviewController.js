// Summary figures for the SysAdmin and Security Auditor home pages. Counts
// only: no child data, and nothing is decrypted. These reads are deliberately
// not logged as access events or scored: a home page refreshing should not
// raise anyone's activity counts, which feed the risk model.
const db = require('../config/db');
const { getRetentionStatus } = require('../services/retention');
const { wrappedKeyEntries } = require('../utils/keyVault');
const { KNOWN_DEVICE_SQL, likelyReason } = require('../services/flagReason');
const { TEST_ACCOUNT_LOCK_REASON } = require('./userManagementController');

const BREACH_WINDOW_HOURS = 72;

// Admin actions worth showing on the home page, in everyday words.
const ADMIN_ACTIVITY = {
  approve_registration_request: 'Approved an account request',
  reject_registration_request: 'Rejected an account request',
  admin_unlocked_account: 'Unlocked an account',
  reencrypt_child_data: 'Ran re-encryption',
  apply_retention: 'Applied data retention',
};

// GET /admin/overview
async function adminOverview(req, res) {
  const [pending, locked, users, activity, retention] = await Promise.all([
    db.query("SELECT COUNT(*)::int AS n FROM registration_requests WHERE status = 'pending'"),
    db.query(
      "SELECT COUNT(*)::int AS n FROM users WHERE is_locked = TRUE AND COALESCE(locked_reason, '') NOT LIKE $1",
      [`${TEST_ACCOUNT_LOCK_REASON}%`]
    ),
    db.query(
      `SELECT r.name AS role, COUNT(*)::int AS n FROM users u JOIN roles r ON r.id = u.role_id
       WHERE u.is_locked = FALSE GROUP BY r.name ORDER BY r.name`
    ),
    db.query(
      'SELECT action, created_at FROM audit_log WHERE action = ANY($1) ORDER BY created_at DESC, id DESC LIMIT 5',
      [Object.keys(ADMIN_ACTIVITY)]
    ),
    getRetentionStatus(),
  ]);

  res.json({
    pendingRequests: pending.rows[0].n,
    lockedAccounts: locked.rows[0].n,
    activeUsers: users.rows,
    retentionDue: retention.due,
    retentionDays: retention.retentionDays,
    keysInVault: wrappedKeyEntries().length > 0,
    recentActivity: activity.rows.map((a) => ({ label: ADMIN_ACTIVITY[a.action], at: a.created_at })),
  });
}

// GET /auditor/overview
async function auditorOverview(req, res) {
  const [summary, perDay, recent] = await Promise.all([
    db.query(
      `SELECT COUNT(*) FILTER (WHERE created_at >= now() - interval '7 days')::int AS this_week,
              COUNT(*) FILTER (WHERE created_at >= now() - interval '14 days' AND created_at < now() - interval '7 days')::int AS last_week,
              COUNT(*) FILTER (WHERE auditor_status = 'pending')::int AS waiting,
              MIN(created_at) FILTER (WHERE auditor_status = 'pending') AS oldest_waiting,
              COUNT(*) FILTER (WHERE auditor_status <> 'pending' AND created_at >= date_trunc('month', now()))::int AS reviewed_this_month,
              COUNT(*) FILTER (WHERE (auditor_status = 'escalated' OR owner_response = 'not_me') AND breach_decision IS NULL)::int AS breach_open,
              COUNT(*) FILTER (WHERE (auditor_status = 'escalated' OR owner_response = 'not_me') AND breach_decision IS NULL
                                 AND created_at < now() - make_interval(hours => $1))::int AS breach_overdue,
              MIN(created_at) FILTER (WHERE (auditor_status = 'escalated' OR owner_response = 'not_me') AND breach_decision IS NULL
                                        AND created_at >= now() - make_interval(hours => $1)) AS breach_soonest
       FROM risk_scores WHERE is_flagged`,
      [BREACH_WINDOW_HOURS]
    ),
    db.query(
      `SELECT d::date AS day, COUNT(rs.id)::int AS flags
       FROM generate_series(current_date - 13, current_date, interval '1 day') d
       LEFT JOIN risk_scores rs ON rs.is_flagged AND rs.created_at::date = d::date
       GROUP BY d ORDER BY d`
    ),
    db.query(
      `SELECT ar.requested_at, ${KNOWN_DEVICE_SQL} AS known_device
       FROM risk_scores rs JOIN access_requests ar ON ar.id = rs.access_request_id
       WHERE rs.is_flagged AND rs.created_at >= now() - interval '7 days'`
    ),
  ]);

  const s = summary.rows[0];
  const reasons = {};
  for (const row of recent.rows) {
    const reason = likelyReason(row);
    reasons[reason] = (reasons[reason] || 0) + 1;
  }
  const hoursLeft = s.breach_soonest
    ? Math.max(0, Math.floor(BREACH_WINDOW_HOURS - (Date.now() - new Date(s.breach_soonest)) / 3600000))
    : null;

  res.json({
    flagsThisWeek: s.this_week,
    flagsLastWeek: s.last_week,
    waitingForReview: s.waiting,
    oldestWaiting: s.oldest_waiting,
    reviewedThisMonth: s.reviewed_this_month,
    breachOpen: s.breach_open,
    breachOverdue: s.breach_overdue,
    breachHoursLeft: hoursLeft,
    flagsPerDay: perDay.rows,
    reasons: Object.entries(reasons).map(([reason, count]) => ({ reason, count })).sort((a, b) => b.count - a.count),
  });
}

module.exports = { adminOverview, auditorOverview };
