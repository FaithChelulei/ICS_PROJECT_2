// SysAdmin: data retention (Admin > Data Retention). See services/retention.js.
const { getRetentionStatus, applyRetention } = require('../services/retention');
const { logAction } = require('../utils/auditLog');
const { scoreAction, logOnlyAction, riskFields } = require('../services/actionScoring');

async function status(req, res) {
  const result = await getRetentionStatus();
  await logOnlyAction(req, 'view_retention_status');
  res.json(result);
}

async function apply(req, res) {
  const ids = await applyRetention();
  await logAction({
    userId: req.user.id,
    action: 'apply_retention',
    detail: `anonymised=${ids.length}${ids.length ? `, child_profile_ids=${ids.join(',')}` : ''}`,
  });
  const risk = await scoreAction(req, 'apply_retention');
  res.json({ anonymised: ids.length, childProfileIds: ids, status: await getRetentionStatus(), ...riskFields(risk) });
}

module.exports = { status, apply };
