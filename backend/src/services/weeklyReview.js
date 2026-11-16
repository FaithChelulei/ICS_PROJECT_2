// Layer 2: the weekly review ("People to review this week").
//
// Layer 1 (riskEngine.js) scores every action the moment it happens and
// signs out a session that crosses its role's limit. Layer 2 looks at each
// person's whole WEEK: it catches the slow, quiet misuse that never trips
// layer 1 on any single day, and ranks people for a Security Auditor to
// review. It never signs anyone out or locks anyone; a person decides.
//
// How a refresh works:
//   1. Collect every scored action of the week being reviewed and of the 30
//      days before it (the history the "unusual for this person" features
//      need). Each risk_scores row already holds the 7 features layer 1
//      computed (db/008_score_evidence.sql).
//   2. Group them into the same units layer 1 and the training data use: a
//      calendar day for a Caregiver or Security Auditor, one sign-in session
//      for a System Administrator (see featureComputation.js). A group's
//      values are the most extreme of the day or session: the most data
//      actions, the busiest hour, an unknown device if one was used.
//   3. Send them to the scoring service's /score_week (ml/service/weekly.py),
//      which computes the per-person features and a review score (1.00 is
//      the review line): the larger of a learned score (like known insider
//      weeks) and a sustained rise above the person's own usual, each
//      divided by its limit, with the reasons.
//   4. Store one weekly_reviews row per person, keeping any review already
//      recorded for that week.
//   5. Always-review rules for the powerful roles: any System Administrator
//      or Security Auditor action at night or from a device the person had
//      not used before puts that person's week on the list, whatever the
//      model says (a model cannot be trusted alone for a handful of people).
const db = require('../config/db');
const { scoreWeek } = require('../utils/mlClient');

const HISTORY_DAYS = 30;
const SESSION_BASED_ROLES = ['SysAdmin'];
const ALWAYS_REVIEW_ROLES = ['SysAdmin', 'SecurityAuditor'];
const FEATURES = [
  'files_accessed_per_session', 'events_prev_day', 'events_prev_hour',
  'unique_pcs_used_that_day', 'session_duration_minutes', 'is_after_hours', 'is_own_pc',
];

const pad = (n) => String(n).padStart(2, '0');
// Local time, as the features use local time (isAfterHours, usual hours).
const localDate = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
const localIso = (d) => `${localDate(d)}T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;

// Monday 00:00 (local) of the week that contains `date`.
function weekStartOf(date) {
  const d = new Date(date);
  d.setHours(0, 0, 0, 0);
  d.setDate(d.getDate() - ((d.getDay() + 6) % 7));
  return d;
}

async function collectSessions(weekStart, weekEnd) {
  const since = new Date(weekStart.getTime() - HISTORY_DAYS * 24 * 60 * 60 * 1000);
  const { rows } = await db.query(
    `SELECT ar.user_id, r.name AS role, ar.requested_at, ar.pc_name, ar.session_id, rs.features
     FROM risk_scores rs
     JOIN access_requests ar ON ar.id = rs.access_request_id
     JOIN users u ON u.id = ar.user_id
     JOIN roles r ON r.id = u.role_id
     WHERE ar.requested_at >= $1 AND ar.requested_at < $2 AND rs.features IS NOT NULL
     ORDER BY ar.requested_at`,
    [since, weekEnd]
  );
  return groupIntoSessions(rows);
}

// Rows: { user_id, role, requested_at, pc_name, session_id, features }, in
// time order. Also used by scripts/simulate-traffic.js, so the simulation
// measures exactly what the live weekly review does.
function groupIntoSessions(rows) {
  const groups = new Map();
  for (const row of rows) {
    const at = new Date(row.requested_at);
    const unit = SESSION_BASED_ROLES.includes(row.role) ? `s:${row.session_id}` : `d:${localDate(at)}`;
    const key = `${row.user_id}|${unit}`;
    const f = row.features;
    const g = groups.get(key);
    if (!g) {
      groups.set(key, {
        user: String(row.user_id), role: row.role, start: localIso(at), pc: row.pc_name || 'unknown',
        ...Object.fromEntries(FEATURES.map((k) => [k, Number(f[k]) || 0])),
      });
      continue;
    }
    for (const k of FEATURES) {
      if (k === 'is_own_pc') {
        if (Number(f[k]) < g[k]) { g[k] = Number(f[k]); g.pc = row.pc_name || g.pc; }
      } else {
        g[k] = Math.max(g[k], Number(f[k]) || 0);
      }
    }
  }
  return [...groups.values()];
}

function ruleFlags(role, sessions) {
  if (!ALWAYS_REVIEW_ROLES.includes(role)) return [];
  const flags = [];
  if (sessions.some((s) => s.is_after_hours >= 1)) {
    flags.push({ code: 'privileged_night', text: 'Privileged work at night (always reviewed)' });
  }
  if (sessions.some((s) => s.is_own_pc === 0)) {
    flags.push({ code: 'privileged_new_device', text: 'Privileged work from a new device (always reviewed)' });
  }
  return flags;
}

let lastRun = { at: null, ok: null, people: 0, error: null };

// ---- Deployment calibration of the review line
// The lines were set on CERT office workers. ChildGuard's own users behave
// differently (in a 5-week simulation of the app about 12% of ordinary
// caregivers crossed the CERT line every week), so once this system has
// enough of its own history, each role's line is raised to where 99% of its
// own ordinary past weeks fall below it.
//   - "Ordinary" means a week that was below the line, or one an auditor
//     reviewed and marked "No concern". Unreviewed weeks on the list and
//     weeks marked "Take action" are never used: an insider must not be able
//     to raise the line that is meant to catch them. In effect the line
//     learns from the auditors' "No concern" decisions.
//   - It is never LOWERED below the CERT line.
//   - A group needs at least 50 such past person-weeks; until then the CERT
//     line applies.
//   - Groups follow the models: Educators share the general-staff
//     (Caregiver) models, so their weeks are pooled with caregivers'.
const CALIBRATION = { quantile: 0.99, minWeeks: 50, lookbackWeeks: 12 };

function calibrationGroup(role) {
  return role === 'Educator' ? 'Caregiver' : role;
}

async function localLines(weekStart) {
  const since = new Date(weekStart.getTime() - CALIBRATION.lookbackWeeks * 7 * 24 * 60 * 60 * 1000);
  const { rows } = await db.query(
    `SELECT CASE WHEN role_name = 'Educator' THEN 'Caregiver' ELSE role_name END AS role, COUNT(*)::int AS n,
            percentile_cont($3) WITHIN GROUP (ORDER BY (parts->>'learned')::float) AS learned,
            percentile_cont($3) WITHIN GROUP (ORDER BY (parts->>'change')::float) AS change
     FROM weekly_reviews
     WHERE week_start < $1 AND week_start >= $2 AND parts IS NOT NULL
       AND (status = 'no_concern' OR (status = 'not_reviewed' AND NOT above_limit))
     GROUP BY 1`,
    [localDate(weekStart), localDate(since), CALIBRATION.quantile]
  );
  return linesFrom(rows);
}

// rows: one per calibration group -- { role, n, learned, change }, where
// learned/change are the 99th percentiles of that group's ordinary past
// weeks. Also used by scripts/simulate-traffic.js.
function linesFrom(rows) {
  const lines = {};
  const basis = {};
  for (const r of rows) {
    const g = calibrationGroup(r.role);
    const n = Number(r.n);
    basis[g] = { pastWeeks: n, calibrated: n >= CALIBRATION.minWeeks };
    if (n >= CALIBRATION.minWeeks) lines[g] = { learned: Number(r.learned) || 0, change: Number(r.change) || 0 };
  }
  return { lines, basis };
}

async function refreshWeek(date = new Date()) {
  const weekStart = weekStartOf(date);
  const weekEnd = new Date(weekStart.getTime() + 7 * 24 * 60 * 60 * 1000);
  const sessions = await collectSessions(weekStart, weekEnd);
  const calibration = await localLines(weekStart);
  const result = await scoreWeek(localDate(weekStart), sessions, Object.keys(calibration.lines).length ? calibration.lines : null);
  if (!result) {
    lastRun = { at: new Date(), ok: false, people: 0, error: 'scoring service unavailable' };
    return lastRun;
  }
  const inWeek = sessions.filter((s) => s.start >= localIso(weekStart));
  for (const p of result.people) {
    const flags = ruleFlags(p.role, inWeek.filter((s) => s.user === p.user));
    await db.query(
      `INSERT INTO weekly_reviews (user_id, role_name, week_label, week_start, score, score_limit, above_limit,
                                   reasons, parts, rule_flags, sessions, model_version, computed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now())
       ON CONFLICT (user_id, week_label) DO UPDATE SET
         role_name = EXCLUDED.role_name, score = EXCLUDED.score, score_limit = EXCLUDED.score_limit,
         above_limit = EXCLUDED.above_limit, reasons = EXCLUDED.reasons, parts = EXCLUDED.parts,
         rule_flags = EXCLUDED.rule_flags, sessions = EXCLUDED.sessions, model_version = EXCLUDED.model_version,
         computed_at = now()`,
      [Number(p.user), p.role, result.week, localDate(weekStart), p.score, p.limit, p.above_limit,
        JSON.stringify(p.reasons || []), JSON.stringify(p.parts || null), JSON.stringify(flags), p.sessions,
        p.model_version]
    );
  }
  lastRun = { at: new Date(), ok: true, people: result.people.length, error: null, week: result.week, calibration: calibration.basis };
  return lastRun;
}

// Hourly in the background (WEEKLY_REVIEW_EVERY_MINUTES, 0 turns it off;
// the automated tests refresh on demand instead).
function startWeeklySchedule() {
  const minutes = Number(process.env.WEEKLY_REVIEW_EVERY_MINUTES ?? 60);
  if (!minutes) return null;
  const run = () => refreshWeek().catch((err) => {
    lastRun = { at: new Date(), ok: false, people: 0, error: err.message };
    console.error('[weekly-review] refresh failed:', err.message);
  });
  setTimeout(run, 15 * 1000).unref();
  return setInterval(run, minutes * 60 * 1000).unref();
}

module.exports = { linesFrom, calibrationGroup, CALIBRATION, refreshWeek, startWeeklySchedule, weekStartOf, localDate, localIso, collectSessions, groupIntoSessions, ruleFlags,
  getLastRun: () => lastRun };
