// Live replication of the 7 features ml/scripts/01_preprocess.py computed
// from the CERT dataset, using this system's own access_requests/sessions
// history instead of logon.csv/file.csv/device.csv. Exact definitions
// (matched to 01_preprocess.py):
//   is_after_hours             = hour < 6 or hour >= 20
//   is_own_pc                  = pc used now == this user's all-time most
//                                 frequently used pc (no history yet: 1 --
//                                 a brand-new user's first device can't be
//                                 "unusual" relative to a history of zero)
//   unique_pcs_used_that_day   = distinct pc_name for this user, same
//                                 calendar date, including this action
//   files_accessed_per_session = count of data-access actions logged
//                                 against THIS session so far
//   events_prev_hour/_day      = count of this user's actions strictly
//                                 BEFORE `now`, within the trailing 1hr/1day
//   session_duration_minutes   = minutes since this session's sessions.issued_at.
//                                 CERT's sessions were already complete when
//                                 this was computed; a live session is still
//                                 open, so this is "elapsed so far", not a
//                                 final duration -- the closest live analog.
const db = require('../config/db');

const FILE_ACTION_TYPES = ['create_child_profile', 'view_own_child_records', 'submit_developmental_record'];

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

async function computeFeatures({ userId, sessionId, pcName, now }) {
  const nowDate = now || new Date();
  const oneHourAgo = new Date(nowDate.getTime() - 60 * 60 * 1000);
  const oneDayAgo = new Date(nowDate.getTime() - 24 * 60 * 60 * 1000);
  const dayStart = new Date(nowDate);
  dayStart.setHours(0, 0, 0, 0);
  const dayEnd = new Date(nowDate);
  dayEnd.setHours(23, 59, 59, 999);

  const [prevHour, prevDay, pcsToday, filesThisSession, sessionRow, topPc] = await Promise.all([
    db.query(
      `SELECT COUNT(*) FROM access_requests WHERE user_id = $1 AND requested_at >= $2 AND requested_at < $3`,
      [userId, oneHourAgo, nowDate]
    ),
    db.query(
      `SELECT COUNT(*) FROM access_requests WHERE user_id = $1 AND requested_at >= $2 AND requested_at < $3`,
      [userId, oneDayAgo, nowDate]
    ),
    db.query(
      `SELECT COUNT(DISTINCT pc_name) FROM access_requests
       WHERE user_id = $1 AND requested_at >= $2 AND requested_at <= $3 AND pc_name IS NOT NULL`,
      [userId, dayStart, dayEnd]
    ),
    db.query(
      `SELECT COUNT(*) FROM access_requests WHERE session_id = $1 AND action_type = ANY($2)`,
      [sessionId, FILE_ACTION_TYPES]
    ),
    db.query('SELECT issued_at FROM sessions WHERE id = $1', [sessionId]),
    mostFrequentPc(userId),
  ]);

  const issuedAt = sessionRow.rows[0] ? new Date(sessionRow.rows[0].issued_at) : nowDate;
  const sessionDurationMinutes = Math.max(0, (nowDate - issuedAt) / 60000);
  const isOwnPc = topPc === null ? 1 : (pcName === topPc ? 1 : 0);

  return {
    files_accessed_per_session: Number(filesThisSession.rows[0].count),
    events_prev_day: Number(prevDay.rows[0].count),
    events_prev_hour: Number(prevHour.rows[0].count),
    unique_pcs_used_that_day: Number(pcsToday.rows[0].count),
    session_duration_minutes: sessionDurationMinutes,
    is_after_hours: isAfterHours(nowDate),
    is_own_pc: isOwnPc,
  };
}

module.exports = { computeFeatures, FILE_ACTION_TYPES };
