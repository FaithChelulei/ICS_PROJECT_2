// System settings a SysAdmin can change on screen (FR-25). Only these two:
// keys, passwords and connection details stay in backend/.env and are never
// editable or shown here. The default for each is its value in backend/.env.
// The limits are repeated as CHECK constraints in
// db/006_admin_controls.sql.
const db = require('../config/db');

const SETTINGS = {
  retention_days: {
    label: 'Retention period',
    unit: 'days',
    description: 'How long an archived child profile is kept before its identity can be anonymised.',
    min: 30,
    max: 3650,
    envName: 'RETENTION_DAYS',
    fallback: 365,
  },
  report_exports_per_hour: {
    label: 'Report download limit',
    unit: 'per hour',
    description: 'How many reports one Security Auditor can download in an hour.',
    min: 1,
    max: 50,
    envName: 'REPORT_EXPORTS_PER_HOUR',
    fallback: 10,
  },
};

function defaultValue(key) {
  const { envName, fallback } = SETTINGS[key];
  const value = Number(process.env[envName]);
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

// The value in force. If the lookup fails, the .env value still applies.
async function getSetting(key) {
  try {
    const { rows } = await db.query('SELECT setting_value FROM system_settings WHERE setting_key = $1', [key]);
    return rows[0] ? rows[0].setting_value : defaultValue(key);
  } catch (err) {
    console.error(`[system-settings] lookup of ${key} failed, using the default:`, err.message);
    return defaultValue(key);
  }
}

async function listSettings() {
  const { rows } = await db.query(
    `SELECT s.setting_key, s.setting_value, s.reason, s.updated_at, u.email AS updated_by
     FROM system_settings s JOIN users u ON u.id = s.updated_by`
  );
  const saved = new Map(rows.map((r) => [r.setting_key, r]));
  return Object.entries(SETTINGS).map(([key, { label, unit, description, min, max }]) => {
    const row = saved.get(key);
    return {
      key,
      label,
      unit,
      description,
      min,
      max,
      value: row ? row.setting_value : defaultValue(key),
      defaultValue: defaultValue(key),
      reason: row ? row.reason : null,
      updatedAt: row ? row.updated_at : null,
      updatedBy: row ? row.updated_by : null,
    };
  });
}

async function saveSetting({ key, value, reason, userId }) {
  await db.query(
    `INSERT INTO system_settings (setting_key, setting_value, reason, updated_by)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (setting_key) DO UPDATE
     SET setting_value = EXCLUDED.setting_value, reason = EXCLUDED.reason,
         updated_by = EXCLUDED.updated_by, updated_at = now()`,
    [key, value, reason, userId]
  );
}

module.exports = { SETTINGS, getSetting, listSettings, saveSetting };
