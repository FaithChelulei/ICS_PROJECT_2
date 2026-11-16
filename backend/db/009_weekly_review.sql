-- Layer 2 (the weekly review) and two-person approval for powerful actions.
-- Additive and safe to re-run; applied by db/migrate.js as the table owner.

-- One row per person per week, written by services/weeklyReview.js from
-- the scoring service's /score_week answer. The model ranks; a Security
-- Auditor decides. Nothing here signs anyone out.
CREATE TABLE IF NOT EXISTS weekly_reviews (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_name       VARCHAR(32) NOT NULL REFERENCES roles(name),
    week_label      VARCHAR(30) NOT NULL,             -- e.g. 2026-11-09/2026-11-15 (Monday to Sunday)
    week_start      DATE NOT NULL,
    score           NUMERIC(7,6) NOT NULL,
    score_limit     NUMERIC(7,6) NOT NULL,
    above_limit     BOOLEAN NOT NULL,
    reasons         JSONB NOT NULL DEFAULT '[]',      -- [{code, text, raised_by}]
    parts           JSONB,                            -- learned score and change, each with its limit
    rule_flags      JSONB NOT NULL DEFAULT '[]',      -- always-review rules for powerful roles
    sessions        INTEGER NOT NULL,
    model_version   VARCHAR(60),
    status          VARCHAR(20) NOT NULL DEFAULT 'not_reviewed',
    reviewed_by     INTEGER REFERENCES users(id),
    review_note     TEXT,
    reviewed_at     TIMESTAMPTZ,
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT weekly_review_status CHECK (status IN ('not_reviewed', 'no_concern', 'escalated')),
    -- Nobody reviews their own week, enforced by the database as well.
    CONSTRAINT weekly_review_not_self CHECK (reviewed_by IS NULL OR reviewed_by <> user_id),
    CONSTRAINT weekly_review_note CHECK (status = 'not_reviewed' OR length(trim(review_note)) >= 10),
    UNIQUE (user_id, week_label)
);
CREATE INDEX IF NOT EXISTS idx_weekly_reviews_week ON weekly_reviews (week_start, above_limit, score DESC);

-- Two-person approval: re-encrypting all child data and anonymising
-- profiles need a request by one System Administrator and the approval of
-- a DIFFERENT one before they can run. A request expires after 24 hours
-- and an approval can be used once.
CREATE TABLE IF NOT EXISTS pending_approvals (
    id               SERIAL PRIMARY KEY,
    action           VARCHAR(40) NOT NULL,
    reason           TEXT NOT NULL,
    requested_by     INTEGER NOT NULL REFERENCES users(id),
    requested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    status           VARCHAR(20) NOT NULL DEFAULT 'pending',
    decided_by       INTEGER REFERENCES users(id),
    decision_reason  TEXT,
    decided_at       TIMESTAMPTZ,
    used_at          TIMESTAMPTZ,
    CONSTRAINT approval_action CHECK (action IN ('reencrypt_data', 'apply_retention')),
    CONSTRAINT approval_status CHECK (status IN ('pending', 'approved', 'rejected', 'used')),
    CONSTRAINT approval_reason CHECK (length(trim(reason)) >= 10),
    CONSTRAINT approval_two_people CHECK (decided_by IS NULL OR decided_by <> requested_by)
);

-- DPIA gap G1: a time limit for monitoring data (services/monitoringRetention.js).
-- The settings table's limits are widened to the new setting.
ALTER TABLE system_settings DROP CONSTRAINT IF EXISTS system_setting_within_limits;
ALTER TABLE system_settings ADD CONSTRAINT system_setting_within_limits CHECK (
    (setting_key = 'retention_days'            AND setting_value BETWEEN 30 AND 3650) OR
    (setting_key = 'report_exports_per_hour'   AND setting_value BETWEEN 1 AND 50) OR
    (setting_key = 'monitoring_retention_days' AND setting_value BETWEEN 90 AND 3650)
);

GRANT SELECT, INSERT, UPDATE ON weekly_reviews TO app_user;
-- Old weekly reviews are deleted by the monitoring retention job.
GRANT DELETE ON weekly_reviews TO app_user;
GRANT SELECT, INSERT, UPDATE ON pending_approvals TO app_user;
GRANT USAGE, SELECT ON SEQUENCE weekly_reviews_id_seq, pending_approvals_id_seq TO app_user;

-- Breach decisions (KDPA s.43): the "report" choice now goes to the System
-- Administrators, who are e-mailed and see it on their home page. Existing
-- decisions keep their meaning under the new name.
ALTER TABLE risk_scores DROP CONSTRAINT IF EXISTS risk_scores_breach_decision_check;
UPDATE risk_scores SET breach_decision = 'reported_to_admin' WHERE breach_decision = 'notified_commissioner';
ALTER TABLE risk_scores ADD CONSTRAINT risk_scores_breach_decision_check
    CHECK (breach_decision IS NULL OR breach_decision IN ('reported_to_admin', 'no_real_risk'));
