-- Migration: Kenya Data Protection Act 2019 features. Additive, safe to
-- re-run. Run AFTER migration_rls.sql, as the table owner (postgres), then
-- restart the backend.
--
--   s.40(3)  archive (restrict processing) a child profile instead of
--            erasing it -- the data stays as evidence but is frozen
--   s.39     retention: an archived profile past the retention period has
--            its identity anonymised; records and the audit trail remain,
--            linked only to the profile id
--   s.29     record which privacy notice version was shown and accepted
--   s.43     the Security Auditor's breach decision on a flagged session
--            (notified the Data Commissioner / no real risk of harm)

-- 1. Archive + retention state on the child profile.
ALTER TABLE child_profiles ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;
ALTER TABLE child_profiles ADD COLUMN IF NOT EXISTS archive_reason TEXT;
ALTER TABLE child_profiles ADD COLUMN IF NOT EXISTS identity_anonymised_at TIMESTAMPTZ;

-- 2. Privacy notice acceptance (s.29): the version the person saw and agreed to.
ALTER TABLE child_profiles ADD COLUMN IF NOT EXISTS privacy_notice_version VARCHAR(20);
ALTER TABLE registration_requests ADD COLUMN IF NOT EXISTS privacy_notice_version VARCHAR(20);
ALTER TABLE registration_requests ADD COLUMN IF NOT EXISTS privacy_notice_accepted_at TIMESTAMPTZ;

-- 3. Breach decision on a flagged session (s.43).
ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS breach_decision VARCHAR(30);
ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS breach_decision_reason TEXT;
ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS breach_decided_at TIMESTAMPTZ;
ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS breach_decided_by INTEGER REFERENCES users(id);
ALTER TABLE risk_scores DROP CONSTRAINT IF EXISTS risk_scores_breach_decision_check;
ALTER TABLE risk_scores ADD CONSTRAINT risk_scores_breach_decision_check
    CHECK (breach_decision IS NULL OR breach_decision IN ('notified_commissioner', 'no_real_risk'));

-- 4. Row-level security: an archived child is frozen at the database level
--    too, not just in the application. A caregiver can no longer add
--    records or consent changes, or correct the identity, of an archived
--    profile; and nobody but System can touch an anonymised one.
CREATE OR REPLACE FUNCTION child_is_active(profile_id integer) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$ SELECT EXISTS (SELECT 1 FROM child_profiles WHERE id = profile_id AND archived_at IS NULL) $$;

DROP POLICY IF EXISTS caregiver_update ON child_profiles;
CREATE POLICY caregiver_update ON child_profiles FOR UPDATE
    USING (app_role() = 'Caregiver' AND caregiver_id = app_user_id() AND identity_anonymised_at IS NULL)
    WITH CHECK (app_role() = 'Caregiver' AND caregiver_id = app_user_id() AND identity_anonymised_at IS NULL);

DROP POLICY IF EXISTS caregiver_update ON child_identifiers;
CREATE POLICY caregiver_update ON child_identifiers FOR UPDATE
    USING (app_role() = 'Caregiver' AND owns_child(child_profile_id) AND child_is_active(child_profile_id))
    WITH CHECK (app_role() = 'Caregiver' AND owns_child(child_profile_id) AND child_is_active(child_profile_id));

DROP POLICY IF EXISTS caregiver_insert ON developmental_records;
CREATE POLICY caregiver_insert ON developmental_records FOR INSERT
    WITH CHECK (app_role() = 'Caregiver' AND owns_child(child_profile_id)
                AND child_is_active(child_profile_id) AND created_by = app_user_id());

DROP POLICY IF EXISTS caregiver_insert ON consent_records;
CREATE POLICY caregiver_insert ON consent_records FOR INSERT
    WITH CHECK (app_role() = 'Caregiver' AND caregiver_id = app_user_id()
                AND owns_child(child_profile_id) AND child_is_active(child_profile_id));

-- Sanity check -- run after:
-- SELECT column_name FROM information_schema.columns
-- WHERE table_name IN ('child_profiles','registration_requests','risk_scores')
--   AND column_name LIKE ANY (ARRAY['archive%','identity_%','privacy_%','breach_%']);
