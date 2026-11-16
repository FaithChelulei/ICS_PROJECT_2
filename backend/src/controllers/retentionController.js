// SysAdmin: data retention (Admin > Data Retention). See services/retention.js.
const { getRetentionStatus, applyRetention } = require('../services/retention');
const { logAction } = require('../utils/auditLog');
const { scoreAction, logOnlyAction, riskFields } = require('../services/actionScoring');
const { claimApproval, approvalRequired } = require('../services/approvals');
const { getMonitoringStatus, clearOldMonitoringData } = require('../services/monitoringRetention');

async function status(req, res) {
  const result = await getRetentionStatus();
  await logOnlyAction(req, 'view_retention_status');
  res.json({ ...result, monitoring: await getMonitoringStatus() });
}

async function apply(req, res) {
  // Two-person approval (services/approvals.js).
  const approval = await claimApproval(Number(req.body && req.body.approvalId), 'apply_retention');
  if (!approval) return approvalRequired(req, res, 'apply_retention');
  const ids = await applyRetention();
  const risk = await scoreAction(req, 'apply_retention');
  await logAction({
    userId: req.user.id,
    action: 'apply_retention',
    detail: `anonymised=${ids.length}${ids.length ? `, child_profile_ids=${ids.join(',')}` : ''}, approval_id=${approval.id}`,
    accessRequestId: risk.accessRequestId,
  });
  res.json({ anonymised: ids.length, childProfileIds: ids, status: await getRetentionStatus(), ...riskFields(risk) });
}

// Clears monitoring details past their period now, instead of waiting for
// the nightly run (needs the password again). Only device names, network
// addresses and model evidence are cleared; no child data is touched.
async function clearMonitoring(req, res) {
  const risk = await scoreAction(req, 'clear_monitoring_data');
  const run = await clearOldMonitoringData({ userId: req.user.id });
  res.json({ cleared: run, monitoring: await getMonitoringStatus(), ...riskFields(risk) });
}

module.exports = { status, apply, clearMonitoring };
