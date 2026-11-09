// Security Auditor: view and change a role's risk threshold (FR-21).
// The route requires the password again; see routes/auditorRoutes.js.
const { logAction } = require('../utils/auditLog');
const { scoreAction, logOnlyAction, riskFields } = require('../services/actionScoring');
const { THRESHOLD_LIMITS, listThresholds, saveThreshold, notifyAdmins } = require('../services/riskThresholds');
const { cleanReason } = require('../utils/changeReason');

async function list(req, res) {
  const thresholds = await listThresholds(req.user.role);
  await logOnlyAction(req, 'view_risk_thresholds');
  res.json({ thresholds });
}

async function update(req, res) {
  const { role } = req.params;
  if (!Object.hasOwn(THRESHOLD_LIMITS, role)) return res.status(404).json({ error: 'Unknown role' });
  if (role === req.user.role) {
    return res.status(403).json({ error: 'You cannot change the limit that applies to your own role.', code: 'OWN_ROLE_THRESHOLD' });
  }

  const { threshold } = req.body || {};
  const { min, max } = THRESHOLD_LIMITS[role];
  if (typeof threshold !== 'number' || !Number.isFinite(threshold) || threshold < min || threshold > max) {
    return res.status(400).json({ error: `The limit for this role must be between ${min.toFixed(2)} and ${max.toFixed(2)}.` });
  }
  const reason = cleanReason(req.body.reason);
  if (!reason) return res.status(400).json({ error: 'Give a reason of 10 to 500 characters.' });

  const current = (await listThresholds(req.user.role)).find((t) => t.role === role);
  if (current.threshold === threshold) return res.status(409).json({ error: 'That is already the current limit.' });

  await saveThreshold({ role, threshold, reason, userId: req.user.id });
  await logAction({
    userId: req.user.id,
    action: 'risk_threshold_changed',
    detail: `role=${role}, from=${current.threshold}, to=${threshold}, reason=${reason}`,
  });
  await notifyAdmins({ role, from: current.threshold, to: threshold, reason, changedBy: req.user.email });

  const risk = await scoreAction(req, 'change_risk_threshold');
  res.json({
    message: `The ${role} limit is now ${threshold.toFixed(2)}. It applies from the next action.`,
    ...riskFields(risk),
  });
}

module.exports = { list, update };
