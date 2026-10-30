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

// "File accessed" = an action that reads or changes protected data, per
// role. Passive list loads (dashboards) are logged as events but are not
// files -- the Caregiver children list is logged as 'list_own_children' for
// exactly that reason (it used to reuse 'view_own_child_records', which
// counted every page visit as a record read).
const FILE_ACTION_TYPES = [
  // Caregiver
  'create_child_profile', 'view_own_child_records', 'submit_developmental_record',
  // Security Auditor
  'view_audit_log', 'review_flagged_session', 'export_report',
  // SysAdmin
  'approve_registration', 'reject_registration', 'unlock_account', 'reencrypt_data',
];

// Roles whose CERT "session" is really a whole workday (see rationale
// above). SysAdmin is deliberately excluded.
const DAY_BASED_SHAPE_ROLES = ['Caregiver', 'SecurityAuditor'];

function isAfterHours(date) {
  const hour = date.getHours();
  return hour < 6 || hour >= 20 ? 1 : 0;
}

// is_own_pc, live version. CERT's "own PC" is the machine a user normally
// works on; the web-app equivalent is "a device this user has signed in
// from before". Only rows from OTHER sessions count as history -- the
// current session's own login row is always present by the time a scored
// action runs, so counting it would make every new device look familiar.
//   - request carries no device name (old clients, curl)  -> 1
//   - user has no named-device history at all (first ever) -> 1
//   - device seen in an earlier session                     -> 1
//   - user has history, but never this device               -> 0
async function isOwnDevice(userId, pcName, sessionId) {
  if (!pcName) return 1;
  const { rows } = await db.query(
    `SELECT COUNT(*) FILTER (WHERE pc_name IS NOT NULL) AS any_named,
            COUNT(*) FILTER (WHERE pc_name = $2)         AS this_device
     FROM access_requests
     WHERE user_id = $1 AND session_id IS DISTINCT FROM $3`,
    [userId, pcName, sessionId]
  );
  const anyNamed = Number(rows[0].any_named);
  const thisDevice = Number(rows[0].this_device);
  if (anyNamed === 0) return 1;
  return thisDevice > 0 ? 1 : 0;
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

  const [prevHour, prevDay, pcsToday, shape, isOwnPc] = await Promise.all([
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
    // History-based, not "most frequent PC": the old most-frequent rule
    // let a couple of stale test rows (2 tagged "FAITH-TEST-PC") pin
    // is_own_pc at 0 forever. See isOwnDevice above.
    isOwnDevice(userId, pcName, sessionId),
  ]);

  // Every tracked session genuinely runs on exactly one physical device,
  // even when a request carries no NAME for it (non-browser clients like
  // curl/PowerShell don't send X-Device-Name -- see getPcName; the React
  // frontend does, via api/client.js). Reporting that as "0 distinct PCs
  // today" is a live-vs-training mismatch, not a faithful "no device"
  // signal: in the CERT training data a normal session is NEVER attributed
  // to 0 PCs (every real session used at least the one it ran on -- scaler
  // mean ~1.09, std ~0.29, so training data sits in an extremely tight
  // band around 1). A live 0 is therefore a ~-3.7 std-dev outlier the
  // Autoencoder never saw in training, and on its own was enough to pin
  // the reconstruction error at the 1.0 clip ceiling regardless of every
  // other feature -- confirmed directly against the trained model:
  // identical feature vectors score ae_raw ~1.8-1.9 (clipped to 1.0) with
  // this at 0, vs ~0.0001-0.0000019 (far below ae_train_max) with it at 1.
  // Same "degrade to the realistic default, not to a value training never
  // saw" reasoning already applied to is_own_pc just above. Approved by
  // Faith after reviewing the diagnosis (2026-10-16).
  const pcsCounted = Number(pcsToday.rows[0].count);
  const uniquePcsUsedToday = pcsCounted === 0 ? 1 : pcsCounted;

  return {
    files_accessed_per_session: shape.filesAccessed,
    events_prev_day: Number(prevDay.rows[0].count),
    events_prev_hour: Number(prevHour.rows[0].count),
    unique_pcs_used_that_day: uniquePcsUsedToday,
    session_duration_minutes: shape.durationMinutes,
    is_after_hours: isAfterHours(nowDate),
    is_own_pc: isOwnPc,
  };
}

module.exports = { computeFeatures, FILE_ACTION_TYPES };
