-- Migration: PostgreSQL row-level security on the four child-data tables
-- (child_profiles, child_identifiers, developmental_records,
-- consent_records). Safe to re-run.
--
-- Must be run by the table owner (postgres) -- app_user deliberately can't
-- create policies. Run it in pgAdmin connected as the owner, then restart
-- the backend.
--
-- How it works: for every query made during an authenticated request, the
-- backend sets two transaction-local settings (src/config/db.js):
--     app.user_id   the signed-in user's id
--     app.role      Caregiver | SecurityAuditor | SysAdmin | System
-- The policies below read them. With no settings at all -- a bug, a script
-- that forgot, an unauthenticated route -- the child tables return NO rows
-- (deny by default). 'System' is only ever set explicitly by code that
-- needs every row (key rotation, CLI maintenance), via db.runAsSystem().
--
-- What this adds: the database itself enforces "a caregiver only sees their
-- own children", on top of the same check in the application code, so a
-- query that forgets its WHERE clause still can't leak another family's
-- data. It does not protect against someone who controls the application
-- server itself (they could set any role) -- that is what the anomaly
-- detection and audit log are for.

-- 1. Helpers reading the per-request identity. missing_ok = true so an
--    unset value is NULL rather than an error; NULLIF covers a connection
--    whose previous transaction left the setting as ''.
CREATE OR REPLACE FUNCTION app_user_id() RETURNS integer
    LANGUAGE sql STABLE
    AS $$ SELECT NULLIF(current_setting('app.user_id', true), '')::integer $$;

CREATE OR REPLACE FUNCTION app_role() RETURNS text
    LANGUAGE sql STABLE
    AS $$ SELECT NULLIF(current_setting('app.role', true), '') $$;

-- True if this child profile belongs to the requesting caregiver. Runs with
-- the caller's rights, so it is itself filtered by child_profiles' policy.
CREATE OR REPLACE FUNCTION owns_child(profile_id integer) RETURNS boolean
    LANGUAGE sql STABLE
    AS $$ SELECT EXISTS (SELECT 1 FROM child_profiles WHERE id = profile_id AND caregiver_id = app_user_id()) $$;

-- 2. Turn RLS on. app_user is not the owner, so it is always subject to
--    the policies; the owner (postgres, a superuser) is not.
ALTER TABLE child_profiles        ENABLE ROW LEVEL SECURITY;
ALTER TABLE child_identifiers     ENABLE ROW LEVEL SECURITY;
ALTER TABLE developmental_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE consent_records       ENABLE ROW LEVEL SECURITY;

-- 3. Policies. Least privilege per role: caregivers can read and add their
--    own children's data and update a profile/identity (correction), but
--    never delete; records and consent are add-only. No policy = no access,
--    so anything not granted below is refused.

-- child_profiles
DROP POLICY IF EXISTS caregiver_select ON child_profiles;
DROP POLICY IF EXISTS caregiver_insert ON child_profiles;
DROP POLICY IF EXISTS caregiver_update ON child_profiles;
DROP POLICY IF EXISTS system_all       ON child_profiles;
CREATE POLICY caregiver_select ON child_profiles FOR SELECT
    USING (app_role() = 'Caregiver' AND caregiver_id = app_user_id());
CREATE POLICY caregiver_insert ON child_profiles FOR INSERT
    WITH CHECK (app_role() = 'Caregiver' AND caregiver_id = app_user_id());
CREATE POLICY caregiver_update ON child_profiles FOR UPDATE
    USING (app_role() = 'Caregiver' AND caregiver_id = app_user_id())
    WITH CHECK (app_role() = 'Caregiver' AND caregiver_id = app_user_id());
CREATE POLICY system_all ON child_profiles FOR ALL
    USING (app_role() = 'System') WITH CHECK (app_role() = 'System');

-- child_identifiers (name, date of birth, family background)
DROP POLICY IF EXISTS caregiver_select ON child_identifiers;
DROP POLICY IF EXISTS caregiver_insert ON child_identifiers;
DROP POLICY IF EXISTS caregiver_update ON child_identifiers;
DROP POLICY IF EXISTS system_all       ON child_identifiers;
CREATE POLICY caregiver_select ON child_identifiers FOR SELECT
    USING (app_role() = 'Caregiver' AND owns_child(child_profile_id));
CREATE POLICY caregiver_insert ON child_identifiers FOR INSERT
    WITH CHECK (app_role() = 'Caregiver' AND owns_child(child_profile_id));
CREATE POLICY caregiver_update ON child_identifiers FOR UPDATE
    USING (app_role() = 'Caregiver' AND owns_child(child_profile_id))
    WITH CHECK (app_role() = 'Caregiver' AND owns_child(child_profile_id));
CREATE POLICY system_all ON child_identifiers FOR ALL
    USING (app_role() = 'System') WITH CHECK (app_role() = 'System');

-- developmental_records (add-only for caregivers)
DROP POLICY IF EXISTS caregiver_select ON developmental_records;
DROP POLICY IF EXISTS caregiver_insert ON developmental_records;
DROP POLICY IF EXISTS system_all       ON developmental_records;
CREATE POLICY caregiver_select ON developmental_records FOR SELECT
    USING (app_role() = 'Caregiver' AND owns_child(child_profile_id));
CREATE POLICY caregiver_insert ON developmental_records FOR INSERT
    WITH CHECK (app_role() = 'Caregiver' AND owns_child(child_profile_id) AND created_by = app_user_id());
CREATE POLICY system_all ON developmental_records FOR ALL
    USING (app_role() = 'System') WITH CHECK (app_role() = 'System');

-- consent_records (append-only; the auditor may read it -- it holds no
-- names, only profile ids -- for the Consent Activity report)
DROP POLICY IF EXISTS caregiver_select ON consent_records;
DROP POLICY IF EXISTS caregiver_insert ON consent_records;
DROP POLICY IF EXISTS auditor_select   ON consent_records;
DROP POLICY IF EXISTS system_all       ON consent_records;
CREATE POLICY caregiver_select ON consent_records FOR SELECT
    USING (app_role() = 'Caregiver' AND owns_child(child_profile_id));
CREATE POLICY caregiver_insert ON consent_records FOR INSERT
    WITH CHECK (app_role() = 'Caregiver' AND caregiver_id = app_user_id() AND owns_child(child_profile_id));
CREATE POLICY auditor_select ON consent_records FOR SELECT
    USING (app_role() = 'SecurityAuditor');
CREATE POLICY system_all ON consent_records FOR ALL
    USING (app_role() = 'System') WITH CHECK (app_role() = 'System');

-- Sanity check -- run after; all four should show rls = true:
-- SELECT relname, relrowsecurity AS rls FROM pg_class
-- WHERE relname IN ('child_profiles','child_identifiers','developmental_records','consent_records');
