// Risk thresholds a Security Auditor can change on screen (FR-21). The model
// keeps scoring as before: the backend decides whether a score crosses the
// line, so a change applies to the very next action with no restart.
//
// Each role has hard limits. The low end keeps ordinary work from being
// signed out; the high end still catches mass access (0.82 to 1.00 in the
// calibration table, docs/RISK_THRESHOLDS.md). The same limits are CHECK
// constraints in db/migration_admin_controls.sql.
const db = require('../config/db');
const { sendThresholdChangedEmail } = require('../utils/mailer');
const tiers = require('../../../ml/models/risk_tiers.json');

const THRESHOLD_LIMITS = {
  Caregiver: { min: 0.35, max: 0.5 },
  SecurityAuditor: { min: 0.55, max: 0.75 },
  SysAdmin: { min: 0.5, max: 0.7 },
};

const defaultThreshold = (role) => tiers[role].deployment_threshold;

// The threshold in force for one role. If the lookup fails (for example the
// migration has not been run) the model's own threshold still applies, so
// detection never stops because of this feature.
async function thresholdFor(role, modelThreshold) {
  try {
    const { rows } = await db.query('SELECT threshold FROM risk_threshold_settings WHERE role_name = $1', [role]);
    return rows[0] ? Number(rows[0].threshold) : modelThreshold;
  } catch (err) {
    console.error('[risk-thresholds] lookup failed, using the model threshold:', err.message);
    return modelThreshold;
  }
}

async function listThresholds(viewerRole) {
  const { rows } = await db.query(
    `SELECT s.role_name, s.threshold, s.reason, s.updated_at, u.email AS updated_by
     FROM risk_threshold_settings s JOIN users u ON u.id = s.updated_by`
  );
  const saved = new Map(rows.map((r) => [r.role_name, r]));
  return Object.entries(THRESHOLD_LIMITS).map(([role, limits]) => {
    const row = saved.get(role);
    return {
      role,
      threshold: row ? Number(row.threshold) : defaultThreshold(role),
      defaultThreshold: defaultThreshold(role),
      ...limits,
      // Nobody loosens the rule that watches their own role.
      editable: role !== viewerRole,
      reason: row ? row.reason : null,
      updatedAt: row ? row.updated_at : null,
      updatedBy: row ? row.updated_by : null,
    };
  });
}

async function saveThreshold({ role, threshold, reason, userId }) {
  await db.query(
    `INSERT INTO risk_threshold_settings (role_name, threshold, reason, updated_by)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (role_name) DO UPDATE
     SET threshold = EXCLUDED.threshold, reason = EXCLUDED.reason,
         updated_by = EXCLUDED.updated_by, updated_at = now()`,
    [role, threshold, reason, userId]
  );
}

// The change is made by an auditor, so an admin hears about it too. A mail
// outage must not undo a change that is already saved and logged.
async function notifyAdmins(change) {
  try {
    const { rows } = await db.query(
      `SELECT u.email FROM users u JOIN roles r ON r.id = u.role_id
       WHERE r.name = 'SysAdmin' AND u.is_locked = FALSE`
    );
    await Promise.all(rows.map((r) => sendThresholdChangedEmail(r.email, change)));
  } catch (err) {
    console.error('[risk-thresholds] admin notification failed:', err.message);
  }
}

module.exports = { THRESHOLD_LIMITS, thresholdFor, listThresholds, saveThreshold, notifyAdmins };
