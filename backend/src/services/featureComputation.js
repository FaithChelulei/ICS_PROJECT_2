// Live replication of the 7 features ml/scripts/01_preprocess.py computed
// from the CERT dataset, using this system's own access_requests/sessions
// history instead of logon.csv/file.csv/device.csv.
//
// is_after_hours, is_own_pc and unique_pcs_used_that_day are straightforward
// live analogs. events_prev_hour/_day needed one correction: 01_preprocess.py's
// rolling_counts() uses np.searchsorted(..., side="right"), which is INCLUSIVE
// of the event timestamped exactly at session_start -- and that event is the
// session's own triggering logon, since all_events concatenates logon+files+
// device together. So training data NEVER has events_prev_hour/_day == 0 (real
// percentiles confirm a floor of exactly 1). The live queries below originally
// used a strict "<" upper bound specifically to exclude the current action
// (whose access_requests row is inserted before computeFeatures runs), which
// meant a user's first action in a given window scored live 0 -- a value the
// Autoencoder never saw in training and reconstructed as pure noise (ae_score
// pinned at the 1.0 clip ceiling, confirmed by direct feature/score
// inspection). Fixed by switching to "<=" so the current action counts toward
// its own window, exactly matching training semantics and guaranteeing the
// same floor of 1 live.
//
// The two features that needed real investigation on their own were
// files_accessed_per_session and session_duration_minutes -- a CERT "session"
// is a full logon-to-logoff
// span, not one web-app visit, and checking the actual training data
// (ml/data/processed/sessions_features.csv) confirmed this matters:
//   - Caregiver and SecurityAuditor average ~1.3 sessions/user/day (70% of
//     days have exactly 1) with a MEDIAN session duration of 8+ hours. A
//     live per-login JWT session (capped at 1 hour, usually minutes) can
//     never resemble that, so scoring it per-login flagged nearly every
//     action regardless of role threshold -- not a real signal, a unit
//     mismatch. Fix: for these two roles, compute both features over the
//     user's whole CALENDAR DAY so far (since their first access_request
//     today), not since this particular login.
//   - SysAdmin is different: ~4.3 sessions/user/day, median duration only
//     ~13 minutes -- their real CERT sessions already ARE short and
//     discrete, so a live per-login window is already a reasonable match.
//     Left as session-scoped, unchanged.
//   - Confirmed malicious sessions are NOT shorter than normal ones for any
//     role (duration doesn't discriminate) -- files_accessed_per_session is
//     the real signal (malicious sessions touch ~2x-4.5x more files), so
//     this fix changes WHEN that count resets, never whether it's tracked.
//   - Known remaining edge case: a user's very first action on a brand-new
//     calendar day still measures ~0 minutes elapsed, because there's no
//     prior login today to measure from. Accepted as a narrower, rarer case
//     than "every session" -- revisit only if it proves to matter in
//     practice.
const db = require('../config/db');

const FILE_ACTION_TYPES = ['create_child_profile', 'view_own_child_records', 'submit_developmental_record'];

// Roles whose CERT "session" is really a whole workday (see rationale
// above). SysAdmin is deliberately excluded.
const DAY_BASED_SHAPE_ROLES = ['Caregiver', 'SecurityAuditor'];

function isAfterHours(date) {
  const hour = date.getHours();
  return hour < 6 || hour >= 20 ? 1 : 0;
}

async function mostFrequentPc(userId) {
  const { rows } = await db.query(
    `SELECT pc_name, COUNT(*) AS cnt FROM access_requests
     WHERE user_id = $1 AND pc_name IS NOT NULL
     GROUP BY pc_name ORDER BY cnt DESC LIMIT 1`,
    [userId]
  );
  return rows[0] ? rows[0].pc_name : null;
}

// Caregiver / SecurityAuditor: "session" = this user's whole calendar day
// so far. Files counted and duration measured from their first
// access_request of the day (any action type -- a login counts as
// "clocking in" even though it isn't itself a file-access action).
async function computeDayBasedShape(userId, dayStart, now) {
  const [filesToday, firstToday] = await Promise.all([
    db.query(
      `SELECT COUNT(*) FROM access_requests
       WHERE user_id = $1 AND action_type = ANY($2) AND requested_at >= $3 AND requested_at <= $4`,
      [userId, FILE_ACTION_TYPES, dayStart, now]
    ),
    db.query(
      `SELECT MIN(requested_at) AS first_at FROM access_requests
       WHERE user_id = $1 AND requested_at >= $2 AND requested_at <= $3`,
      [userId, dayStart, now]
    ),
  ]);
  const firstAt = firstToday.rows[0].first_at ? new Date(firstToday.rows[0].first_at) : now;
  return {
    filesAccessed: Number(filesToday.rows[0].count),
    durationMinutes: Math.max(0, (now - firstAt) / 60000),
  };
}

// SysAdmin: left as the original per-login-session window -- their real
// CERT sessions are themselves short and discrete, so this already fits.
async function computeSessionBasedShape(sessionId, now) {
  const [filesThisSession, sessionRow] = await Promise.all([
    db.query(
      `SELECT COUNT(*) FROM access_requests WHERE session_id = $1 AND action_type = ANY($2)`,
      [sessionId, FILE_ACTION_TYPES]
    ),
    db.query('SELECT issued_at FROM sessions WHERE id = $1', [sessionId]),
  ]);
  const issuedAt = sessionRow.rows[0] ? new Date(sessionRow.rows[0].issued_at) : now;
  return {
    filesAccessed: Number(filesThisSession.rows[0].count),
    durationMinutes: Math.max(0, (now - issuedAt) / 60000),
  };
}

async function computeFeatures({ userId, sessionId, pcName, now, role }) {
  const nowDate = now || new Date();
  const oneHourAgo = new Date(nowDate.getTime() - 60 * 60 * 1000);
  const oneDayAgo = new Date(nowDate.getTime() - 24 * 60 * 60 * 1000);
  const dayStart = new Date(nowDate);
  dayStart.setHours(0, 0, 0, 0);
  const dayEnd = new Date(nowDate);
  dayEnd.setHours(23, 59, 59, 999);

  const useDayBasedShape = DAY_BASED_SHAPE_ROLES.includes(role);

  const [prevHour, prevDay, pcsToday, shape, topPc] = await Promise.all([
    db.query(
      `SELECT COUNT(*) FROM access_requests WHERE user_id = $1 AND requested_at >= $2 AND requested_at <= $3`,
      [userId, oneHourAgo, nowDate]
    ),
    db.query(
      `SELECT COUNT(*) FROM access_requests WHERE user_id = $1 AND requested_at >= $2 AND requested_at <= $3`,
      [userId, oneDayAgo, nowDate]
    ),
    db.query(
      `SELECT COUNT(DISTINCT pc_name) FROM access_requests
       WHERE user_id = $1 AND requested_at >= $2 AND requested_at <= $3 AND pc_name IS NOT NULL`,
      [userId, dayStart, dayEnd]
    ),
    useDayBasedShape
      ? computeDayBasedShape(userId, dayStart, nowDate)
      : computeSessionBasedShape(sessionId, nowDate),
    mostFrequentPc(userId),
  ]);

  const isOwnPc = topPc === null ? 1 : (pcName === topPc ? 1 : 0);

  return {
    files_accessed_per_session: shape.filesAccessed,
    events_prev_day: Number(prevDay.rows[0].count),
    events_prev_hour: Number(prevHour.rows[0].count),
    unique_pcs_used_that_day: Number(pcsToday.rows[0].count),
    session_duration_minutes: shape.durationMinutes,
    is_after_hours: isAfterHours(nowDate),
    is_own_pc: isOwnPc,
  };
}

module.exports = { computeFeatures, FILE_ACTION_TYPES };
