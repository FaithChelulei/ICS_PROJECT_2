-- 010: the Educator role and caregiver-approved access to a child's records.
--
-- SOFIA defines an optional, READ-ONLY Educator who has "no authority ...
-- without caregiver approval" (Technical SRS 3.1). Until now nobody except
-- the child's own caregiver ever asked for a child's records, so consent had
-- no counterpart. From here:
--   1. the caregiver gives the teacher the child's sharing code (in person);
--   2. the teacher asks for access with that code and a reason;
--      (steps 1-2 were replaced by 011: the teacher asks by the parent's
--      email, and the parent picks the child)
--   3. the caregiver grants it for a fixed period, refuses it, or later
--      revokes it;
--   4. while it is granted (and records consent is on, and the profile is not
--      archived) the teacher can READ that child's name and developmental
--      records -- nothing else, and nothing about any other child.
-- The same rule is enforced twice: in the application, and here in
-- row-level security, so an application bug still cannot show a teacher a
-- child they were not granted.

INSERT INTO roles (name) VALUES ('Educator') ON CONFLICT (name) DO NOTHING;

-- 1. The sharing code: random, not guessable from the profile number.
ALTER TABLE child_profiles ADD COLUMN IF NOT EXISTS share_code VARCHAR(12) UNIQUE;

-- 2. Requests and decisions. One row per request; history is kept.
CREATE TABLE IF NOT EXISTS educator_access (
    id                SERIAL PRIMARY KEY,
    child_profile_id  INTEGER NOT NULL REFERENCES child_profiles(id) ON DELETE CASCADE,
    educator_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reason            TEXT NOT NULL CHECK (char_length(btrim(reason)) >= 10),
    status            VARCHAR(12) NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'granted', 'refused', 'revoked')),
    requested_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at        TIMESTAMPTZ,
    decided_by        INTEGER REFERENCES users(id),
    expires_at        TIMESTAMPTZ,
    ended_at          TIMESTAMPTZ,
    -- Access is never open-ended, and a decision always names who made it.
    CONSTRAINT granted_has_expiry CHECK (status <> 'granted' OR expires_at IS NOT NULL),
    CONSTRAINT decided_has_decider CHECK (status = 'pending' OR decided_by IS NOT NULL),
    -- A teacher cannot approve their own request.
    CONSTRAINT not_self_decided CHECK (decided_by IS NULL OR decided_by <> educator_id)
);
-- At most one open (pending or granted) request per teacher and child.
CREATE UNIQUE INDEX IF NOT EXISTS educator_access_one_open
    ON educator_access (child_profile_id, educator_id) WHERE status IN ('pending', 'granted');
CREATE INDEX IF NOT EXISTS educator_access_by_educator ON educator_access (educator_id, status);

GRANT SELECT, INSERT, UPDATE ON educator_access TO app_user;
GRANT USAGE, SELECT ON SEQUENCE educator_access_id_seq TO app_user;

-- 3. Row-level security: what "granted" means, in one place.
CREATE OR REPLACE FUNCTION has_child_access(profile_id integer) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$ SELECT EXISTS (
            SELECT 1 FROM educator_access
            WHERE child_profile_id = profile_id AND educator_id = app_user_id()
              AND status = 'granted' AND expires_at > now()) $$;

DROP POLICY IF EXISTS educator_select ON child_profiles;
CREATE POLICY educator_select ON child_profiles FOR SELECT
    USING (app_role() = 'Educator' AND archived_at IS NULL AND has_child_access(id));

DROP POLICY IF EXISTS educator_select ON child_identifiers;
CREATE POLICY educator_select ON child_identifiers FOR SELECT
    USING (app_role() = 'Educator' AND has_child_access(child_profile_id) AND child_is_active(child_profile_id));

DROP POLICY IF EXISTS educator_select ON developmental_records;
CREATE POLICY educator_select ON developmental_records FOR SELECT
    USING (app_role() = 'Educator' AND has_child_access(child_profile_id) AND child_is_active(child_profile_id));

-- Consent state only (to honour a withdrawn consent), never to change it.
DROP POLICY IF EXISTS educator_select ON consent_records;
CREATE POLICY educator_select ON consent_records FOR SELECT
    USING (app_role() = 'Educator' AND has_child_access(child_profile_id));

-- 4. The teacher's own risk limit (Risk Thresholds page). Teachers are
-- scored with the general-staff models (the ones labelled Caregiver: in CERT
-- that group is every employee who is not an IT administrator or in the
-- security department). They start at the caregivers' limit (0.40), which
-- stops a stolen teacher login from a new browser on its first read; an
-- auditor can raise it to 0.60 for teachers who read a whole class at once.
ALTER TABLE risk_threshold_settings DROP CONSTRAINT IF EXISTS risk_threshold_within_limits;
ALTER TABLE risk_threshold_settings ADD CONSTRAINT risk_threshold_within_limits CHECK (
    (role_name = 'Caregiver'       AND threshold BETWEEN 0.35 AND 0.50) OR
    (role_name = 'Educator'        AND threshold BETWEEN 0.40 AND 0.60) OR
    (role_name = 'SecurityAuditor' AND threshold BETWEEN 0.55 AND 0.75) OR
    (role_name = 'SysAdmin'        AND threshold BETWEEN 0.50 AND 0.70)
);
