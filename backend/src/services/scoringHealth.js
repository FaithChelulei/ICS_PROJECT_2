// Is the risk scoring service answering? (DPIA gap G5)
//
// Scoring fails open on purpose: if the ML service is down, a parent can
// still see their child's records, and the action is still logged -- it is
// just not scored. Before this, nobody was told. Now the first failure
// starts an "offline" period: it is written to the audit log, every System
// Administrator is emailed once, and both home pages show a red banner
// until scoring answers again (which is logged too).
const db = require('../config/db');
const { logAction } = require('../utils/auditLog');
const { sendScoringOfflineEmail } = require('../utils/mailer');

const state = { online: true, since: null, lastOk: null, lastError: null };

async function notifyAdmins(since) {
  const { rows } = await db.query(
    "SELECT u.email FROM users u JOIN roles r ON r.id = u.role_id WHERE r.name = 'SysAdmin' AND NOT u.is_locked"
  );
  await Promise.allSettled(rows.map((r) => sendScoringOfflineEmail(r.email, { since: since.toISOString() })));
}

function markUp() {
  state.lastOk = new Date();
  if (state.online) return;
  const was = state.since;
  state.online = true;
  state.since = null;
  logAction({ userId: null, action: 'risk_scoring_back_online', detail: `offline_since=${was && was.toISOString()}` })
    .catch(() => {});
}

function markDown(error) {
  state.lastError = String(error || 'no answer').slice(0, 200);
  if (!state.online) return;
  state.online = false;
  state.since = new Date();
  logAction({ userId: null, action: 'risk_scoring_offline', detail: state.lastError }).catch(() => {});
  notifyAdmins(state.since).catch((err) => console.error('[scoring-health] email failed:', err.message));
}

function getScoringHealth() {
  return { online: state.online, offlineSince: state.since, lastOk: state.lastOk };
}

// A light check every minute, so an outage is noticed even when nobody is
// doing anything that would be scored.
function startHealthChecks(url = process.env.ML_SERVICE_URL || 'http://127.0.0.1:5001') {
  const minutes = Number(process.env.SCORING_HEALTH_EVERY_MINUTES ?? 1);
  if (!minutes) return null;
  const check = () => fetch(`${url}/health`, { signal: AbortSignal.timeout(5000) })
    .then((r) => (r.ok ? markUp() : markDown(`health ${r.status}`)))
    .catch((err) => markDown(err.message));
  setTimeout(check, 5000).unref();
  return setInterval(check, minutes * 60 * 1000).unref();
}

module.exports = { markUp, markDown, getScoringHealth, startHealthChecks };
