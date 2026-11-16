// "People to review this week" (layer 2, services/weeklyReview.js).
//
// Who sees what:
//   * A Security Auditor sees every person's week EXCEPT their own.
//   * A System Administrator sees the weeks of Security Auditors only, so
//     an auditor is reviewed even when the centre has a single auditor.
//   * Nobody can open or decide on their own week (also a database CHECK).
// A decision needs a note of at least 10 characters and is written to the
// audit log, which the application cannot change.
const db = require('../config/db');
const { logAction } = require('../utils/auditLog');
const { scoreAction, logOnlyAction, riskFields } = require('../services/actionScoring');
const { refreshWeek, weekStartOf, localDate, getLastRun } = require('../services/weeklyReview');
const { FILE_ACTION_TYPES } = require('../services/featureComputation');
const { sendWeeklyActionEmail } = require('../utils/mailer');
const { openCaseFromReview } = require('./accountCaseController');

const STATUSES = ['no_concern', 'escalated'];
const ROLES = ['Caregiver', 'Educator', 'SecurityAuditor', 'SysAdmin'];
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

// Which roles' weeks the signed-in user may review.
function visibleRoles(user) {
  if (user.role === 'SecurityAuditor') return ROLES;
  if (user.role === 'SysAdmin') return ['SecurityAuditor'];
  return [];
}

function parseWeek(q) {
  if (q === undefined || q === '') return weekStartOf(new Date());
  if (typeof q !== 'string' || !DATE_RE.test(q) || Number.isNaN(new Date(`${q}T00:00:00`).getTime())) return null;
  return weekStartOf(new Date(`${q}T12:00:00`));
}

async function list(req, res) {
  const weekStart = parseWeek(req.query.week);
  if (!weekStart) return res.status(400).json({ error: 'week must be a date, YYYY-MM-DD' });
  let roles = visibleRoles(req.user);
  if (req.query.role !== undefined) {
    if (!roles.includes(req.query.role)) return res.status(400).json({ error: `role must be one of ${roles.join(', ')}` });
    roles = [req.query.role];
  }
  const { rows } = await db.query(
    `SELECT wr.id, wr.user_id, u.full_name, u.email, wr.role_name AS role, wr.week_label, wr.week_start,
            wr.score, wr.score_limit, wr.above_limit, wr.reasons, wr.parts, wr.rule_flags, wr.sessions,
            wr.model_version, wr.status, wr.review_note, wr.reviewed_at, ru.full_name AS reviewed_by_name,
            wr.computed_at,
            -- The case opened by "Take action", if any (db/013).
            (SELECT c.status FROM account_cases c WHERE c.weekly_review_id = wr.id ORDER BY c.id DESC LIMIT 1) AS case_status,
            -- Sessions the instant check (layer 1) already stopped this week,
            -- so the auditor sees both layers in one place.
            (SELECT COUNT(DISTINCT COALESCE(ar.session_id::text, ar.id::text))::int
             FROM risk_scores rs JOIN access_requests ar ON ar.id = rs.access_request_id
             WHERE ar.user_id = wr.user_id AND rs.is_flagged
               AND ar.requested_at >= $4 AND ar.requested_at < $5) AS stopped_sessions
     FROM weekly_reviews wr
     JOIN users u ON u.id = wr.user_id
     LEFT JOIN users ru ON ru.id = wr.reviewed_by
     WHERE wr.week_start = $1 AND wr.role_name = ANY($2) AND wr.user_id <> $3
     -- People above the review line first, then by how closely the week
     -- matches known insider behaviour (the learned part), then the score.
     ORDER BY (wr.above_limit OR jsonb_array_length(wr.rule_flags) > 0) DESC,
              COALESCE((wr.parts->>'learned')::numeric / NULLIF((wr.parts->>'learned_limit')::numeric, 0), 0) DESC,
              wr.score DESC`,
    [localDate(weekStart), roles, req.user.id, weekStart, new Date(weekStart.getTime() + 7 * 24 * 60 * 60 * 1000)]
  );
  await logOnlyAction(req, 'view_weekly_review');
  const toReview = rows.filter((r) => r.above_limit || r.rule_flags.length > 0);
  res.json({
    week: localDate(weekStart),
    people: rows.map((r) => ({ ...r, needs_review: r.above_limit || r.rule_flags.length > 0 })),
    summary: {
      people: rows.length,
      toReview: toReview.length,
      notYetReviewed: toReview.filter((r) => r.status === 'not_reviewed').length,
      escalated: rows.filter((r) => r.status === 'escalated').length,
      stoppedSessions: rows.reduce((n, r) => n + r.stopped_sessions, 0),
    },
    lastRefresh: getLastRun(),
  });
}

async function findVisible(req, res) {
  const { rows } = await db.query(
    `SELECT wr.*, u.full_name, u.email FROM weekly_reviews wr JOIN users u ON u.id = wr.user_id WHERE wr.id = $1`,
    [Number(req.params.id)]
  );
  const row = rows[0];
  if (!row || !visibleRoles(req.user).includes(row.role_name)) {
    res.status(404).json({ error: 'Weekly review not found' });
    return null;
  }
  if (row.user_id === req.user.id) {
    await logAction({ userId: req.user.id, action: 'weekly_review_own_week_refused', detail: `weekly_review_id=${row.id}` });
    res.status(403).json({ error: 'You cannot review your own week.', code: 'OWN_WEEK' });
    return null;
  }
  return row;
}

async function detail(req, res) {
  const row = await findVisible(req, res);
  if (!row) return;
  const start = new Date(`${localDate(new Date(row.week_start))}T00:00:00`);
  const end = new Date(start.getTime() + 7 * 24 * 60 * 60 * 1000);
  // Grouped by day here, in the server's local time -- the same clock the
  // risk features use -- not by the database's own time zone.
  const { rows: acts } = await db.query(
    `SELECT requested_at, action_type, pc_name FROM access_requests
     WHERE user_id = $1 AND requested_at >= $2 AND requested_at < $3 ORDER BY requested_at`,
    [row.user_id, start, end]
  );
  const hhmm = (d) => `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  const byDay = new Map();
  for (const a of acts) {
    const at = new Date(a.requested_at);
    const day = localDate(at);
    const d = byDay.get(day) || { day, actions: 0, data_actions: 0, devices: new Set(), first_at: hhmm(at), last_at: hhmm(at) };
    d.actions += 1;
    if (FILE_ACTION_TYPES.includes(a.action_type)) d.data_actions += 1;
    if (a.pc_name) d.devices.add(a.pc_name);
    d.last_at = hhmm(at);
    byDay.set(day, d);
  }
  const days = [...byDay.values()].map((d) => ({ ...d, devices: d.devices.size }));
  // The person's own usual, from the 30 days before the week: what the
  // "rise above their own usual" half compares the week with.
  const { rows: past } = await db.query(
    `SELECT requested_at, action_type FROM access_requests
     WHERE user_id = $1 AND requested_at >= $2 AND requested_at < $3`,
    [row.user_id, new Date(start.getTime() - 30 * 24 * 60 * 60 * 1000), start]
  );
  const pastDays = new Map();
  for (const a of past) {
    const day = localDate(new Date(a.requested_at));
    pastDays.set(day, (pastDays.get(day) || 0) + (FILE_ACTION_TYPES.includes(a.action_type) ? 1 : 0));
  }
  const usual = pastDays.size
    ? { active_days: pastDays.size, data_actions_per_day: Math.round(([...pastDays.values()].reduce((s, n) => s + n, 0) / pastDays.size) * 10) / 10 }
    : null;
  const { rows: caseRows } = await db.query(
    `SELECT c.status, c.report_note, c.pause_note, c.explanation, c.explained_at, c.decision_note, c.decided_at,
            pb.full_name AS paused_by, dbu.full_name AS decided_by
     FROM account_cases c LEFT JOIN users pb ON pb.id = c.paused_by LEFT JOIN users dbu ON dbu.id = c.decided_by
     WHERE c.weekly_review_id = $1 ORDER BY c.id DESC LIMIT 1`, [row.id]);
  const c = caseRows[0];
  // How long the person has been on ChildGuard (grows every week; the
  // demo history's accounts are older than their account row, so the
  // earlier of the two), and their last four weeks on this list.
  const { rows: since } = await db.query(
    `SELECT LEAST(u.created_at, (SELECT MIN(requested_at) FROM access_requests WHERE user_id = u.id)) AS first_seen
     FROM users u WHERE u.id = $1`, [row.user_id]);
  const { rows: hist } = await db.query(
    `SELECT week_label, week_start, (above_limit OR jsonb_array_length(rule_flags) > 0) AS listed, status
     FROM weekly_reviews WHERE user_id = $1 AND week_start <= $2 ORDER BY week_start DESC LIMIT 4`,
    [row.user_id, row.week_start]);
  const firstSeen = since[0] && since[0].first_seen;
  await logOnlyAction(req, 'view_weekly_review_detail');
  res.json({
    person: firstSeen ? { firstSeen, daysOnChildGuard: Math.max(0, Math.floor((Date.now() - new Date(firstSeen).getTime()) / 86400000)) } : null,
    history: hist.reverse().map((h) => ({ week: h.week_label, listed: h.listed, status: h.status })),
    case: c ? { status: c.status, pausedBy: c.paused_by, pauseNote: c.pause_note, explanation: c.explanation,
      explainedAt: c.explained_at, decidedBy: c.decided_by, decisionNote: c.decision_note, decidedAt: c.decided_at } : null,
    review: {
      id: row.id, user_id: row.user_id, full_name: row.full_name, email: row.email, role: row.role_name,
      week_label: row.week_label, score: row.score, score_limit: row.score_limit, above_limit: row.above_limit,
      reasons: row.reasons, parts: row.parts, rule_flags: row.rule_flags, sessions: row.sessions, model_version: row.model_version,
      status: row.status, review_note: row.review_note, reviewed_at: row.reviewed_at,
    },
    days,
    usual,
  });
}

async function decide(req, res) {
  const { status, note } = req.body || {};
  if (!STATUSES.includes(status)) return res.status(400).json({ error: `status must be one of ${STATUSES.join(', ')}` });
  if (typeof note !== 'string' || note.trim().length < 10) {
    return res.status(400).json({ error: 'A note of at least 10 characters is required.' });
  }
  const row = await findVisible(req, res);
  if (!row) return;
  // Scored before anything changes, like every other privileged action.
  const risk = await scoreAction(req, 'review_weekly_person');
  await db.query(
    `UPDATE weekly_reviews SET status = $1, review_note = $2, reviewed_by = $3, reviewed_at = now() WHERE id = $4`,
    [status, note.trim().slice(0, 2000), req.user.id, row.id]
  );
  await logAction({
    userId: req.user.id,
    action: 'weekly_review_decision',
    detail: `weekly_review_id=${row.id}, person=${row.user_id}, week=${row.week_label}, status=${status}`,
    accessRequestId: risk.accessRequestId,
  });
  // "Action needed" goes to the System Administrators, who can act on the
  // account (lock it, change the role); "No concern" only teaches the line.
  let caseId = null;
  if (status === 'escalated') {
    caseId = await openCaseFromReview({ userId: row.user_id, weeklyReviewId: row.id, reportedBy: req.user.id, note: note.trim().slice(0, 2000) });
    const { rows: admins } = await db.query(
      `SELECT u.email FROM users u JOIN roles r ON r.id = u.role_id
       WHERE r.name = 'SysAdmin' AND NOT u.is_locked AND u.id <> $1`, [req.user.id]);
    const { rows: me } = await db.query('SELECT COALESCE(full_name, email) AS name FROM users WHERE id = $1', [req.user.id]);
    for (const a of admins) {
      sendWeeklyActionEmail(a.email, { person: row.full_name || row.email, role: row.role_name, week: row.week_label,
        note: note.trim().slice(0, 500), decidedBy: me[0] ? me[0].name : 'A reviewer' })
        .catch((err) => console.error('[weekly-review] action e-mail failed:', err.message));
    }
  }
  res.json({ id: row.id, status, ...(status === 'escalated' ? { adminsTold: true, caseId } : {}), ...riskFields(risk) });
}

async function refresh(req, res) {
  const run = await refreshWeek(new Date());
  await logOnlyAction(req, 'refresh_weekly_review');
  if (!run.ok) return res.status(503).json({ error: 'The weekly review could not be refreshed: the scoring service is unavailable.', lastRefresh: run });
  res.json({ lastRefresh: run });
}

module.exports = { list, detail, decide, refresh, visibleRoles };
