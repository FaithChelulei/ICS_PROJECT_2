// SysAdmin: view and change system settings (FR-25). The route requires the
// password again; see routes/systemSettingsRoutes.js.
const { logAction } = require('../utils/auditLog');
const { scoreAction, logOnlyAction, riskFields } = require('../services/actionScoring');
const { SETTINGS, listSettings, saveSetting } = require('../services/systemSettings');
const { cleanReason } = require('../utils/changeReason');

async function list(req, res) {
  const settings = await listSettings();
  await logOnlyAction(req, 'view_system_settings');
  res.json({ settings });
}

async function update(req, res) {
  const { key } = req.params;
  if (!Object.hasOwn(SETTINGS, key)) return res.status(404).json({ error: 'Unknown setting' });

  const { value } = req.body || {};
  const { label, unit, min, max } = SETTINGS[key];
  if (!Number.isInteger(value) || value < min || value > max) {
    return res.status(400).json({ error: `${label} must be a whole number from ${min} to ${max}.` });
  }
  const reason = cleanReason(req.body.reason);
  if (!reason) return res.status(400).json({ error: 'Give a reason of 10 to 500 characters.' });

  const current = (await listSettings()).find((s) => s.key === key);
  if (current.value === value) return res.status(409).json({ error: 'That is already the current value.' });

  await saveSetting({ key, value, reason, userId: req.user.id });
  await logAction({
    userId: req.user.id,
    action: 'system_setting_changed',
    detail: `setting=${key}, from=${current.value}, to=${value}, reason=${reason}`,
  });

  const risk = await scoreAction(req, 'change_system_setting');
  res.json({ message: `${label} is now ${value} ${unit}.`, ...riskFields(risk) });
}

module.exports = { list, update };
