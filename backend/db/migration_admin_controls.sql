-- Migration: on-screen risk thresholds (FR-21) and system settings (FR-25).
-- Additive, safe to re-run. Run as the table owner (postgres), then restart
-- the backend.
--
-- No row in a table means "use the default": ml/models/risk_tiers.json for a
-- threshold, backend/.env for a setting. The CHECK constraints repeat the
-- limits in services/riskThresholds.js and services/systemSettings.js, so a
-- bug in the application still cannot store a value that turns detection
-- off. Every change is also written to the audit log, which app_user cannot
-- edit, so these tables only need to hold the current value.

CREATE TABLE IF NOT EXISTS risk_threshold_settings (
    role_name   VARCHAR(32) PRIMARY KEY REFERENCES roles(name),
    threshold   NUMERIC(6,4) NOT NULL,
    reason      TEXT NOT NULL,
    updated_by  INTEGER NOT NULL REFERENCES users(id),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT risk_threshold_within_limits CHECK (
        (role_name = 'Caregiver'       AND threshold BETWEEN 0.35 AND 0.50) OR
        (role_name = 'SecurityAuditor' AND threshold BETWEEN 0.55 AND 0.75) OR
        (role_name = 'SysAdmin'        AND threshold BETWEEN 0.50 AND 0.70)
    )
);

CREATE TABLE IF NOT EXISTS system_settings (
    setting_key    VARCHAR(50) PRIMARY KEY,
    setting_value  INTEGER NOT NULL,
    reason         TEXT NOT NULL,
    updated_by     INTEGER NOT NULL REFERENCES users(id),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT system_setting_within_limits CHECK (
        (setting_key = 'retention_days'          AND setting_value BETWEEN 30 AND 3650) OR
        (setting_key = 'report_exports_per_hour' AND setting_value BETWEEN 1 AND 50)
    )
);

-- DELETE puts a value back to its default (the automated tests use it).
GRANT SELECT, INSERT, UPDATE, DELETE ON risk_threshold_settings TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON system_settings TO app_user;

-- Sanity check -- run after. Expect 2 rows, each with 4 privileges:
-- SELECT table_name, COUNT(*) FROM information_schema.role_table_grants
-- WHERE grantee = 'app_user' AND table_name IN ('risk_threshold_settings', 'system_settings')
-- GROUP BY table_name;
