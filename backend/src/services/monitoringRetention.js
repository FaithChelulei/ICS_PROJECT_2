// Monitoring data retention (DPIA gap G1).
//
// Every recorded action keeps, for the risk model and the auditor, the
// device name and network address it came from (access_requests) and the
// model's evidence (risk_scores.features / drivers); each week's layer-2
// result is kept in weekly_reviews. Until now none of it had a time limit.
// After the period set on System Settings (default 730 days) these personal
// details are cleared every night: the action, its time, its risk score and
// the audit log entry stay, so accountability is not lost, but where it was
// done from and the behavioural detail are not kept for ever (KDPA s.39).
const db = require('../config/db');
const { logAction } = require('../utils/auditLog');
const { getSetting } = require('./systemSettings');

let lastRun = null;

async function getMonitoringStatus() {
  const days = await getSetting('monitoring_retention_days');
  const { rows } = await db.query(
    `SELECT
       (SELECT COUNT(*) FROM access_requests
         WHERE requested_at < now() - make_interval(days => $1) AND (pc_name IS NOT NULL OR ip_address IS NOT NULL))::int AS actions,
       (SELECT COUNT(*) FROM risk_scores
         WHERE created_at < now() - make_interval(days => $1) AND (features IS NOT NULL OR drivers IS NOT NULL))::int AS scores,
       (SELECT COUNT(*) FROM weekly_reviews WHERE week_start < (now() - make_interval(days => $1))::date)::int AS weeks`,
    [days]
  );
  return { days, due: rows[0], lastRun };
}

async function clearOldMonitoringData({ userId = null } = {}) {
  const days = await getSetting('monitoring_retention_days');
  const a = await db.query(
    `UPDATE access_requests SET pc_name = NULL, ip_address = NULL
     WHERE requested_at < now() - make_interval(days => $1) AND (pc_name IS NOT NULL OR ip_address IS NOT NULL)`, [days]);
  const r = await db.query(
    `UPDATE risk_scores SET features = NULL, drivers = NULL
     WHERE created_at < now() - make_interval(days => $1) AND (features IS NOT NULL OR drivers IS NOT NULL)`, [days]);
  const w = await db.query(`DELETE FROM weekly_reviews WHERE week_start < (now() - make_interval(days => $1))::date`, [days]);
  lastRun = { at: new Date(), days, actions: a.rowCount, scores: r.rowCount, weeks: w.rowCount };
  if (a.rowCount || r.rowCount || w.rowCount || userId) {
    await logAction({
      userId,
      action: 'monitoring_data_cleared',
      detail: `older_than_days=${days}, actions=${a.rowCount}, scores=${r.rowCount}, weekly_reviews=${w.rowCount}`,
    });
  }
  return lastRun;
}

// Nightly (MONITORING_PURGE_EVERY_HOURS, 0 turns it off).
function startMonitoringRetention() {
  const hours = Number(process.env.MONITORING_PURGE_EVERY_HOURS ?? 24);
  if (!hours) return null;
  const run = () => clearOldMonitoringData().catch((err) => console.error('[monitoring-retention] failed:', err.message));
  setTimeout(run, 60 * 1000).unref();
  return setInterval(run, hours * 60 * 60 * 1000).unref();
}

module.exports = { getMonitoringStatus, clearOldMonitoringData, startMonitoringRetention };
