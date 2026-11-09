-- Rights for app_user, the restricted account the backend connects as.
-- Run as the table owner (postgres) after every other migration; safe to
-- re-run. app_user must already exist:
--   CREATE ROLE app_user LOGIN PASSWORD '...';
--
-- It may read and write the application tables, but on audit_log only add
-- and read entries: it can never change or delete one. It is not a
-- superuser and cannot bypass row-level security (004_rls.sql).

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;
REVOKE UPDATE, DELETE ON audit_log FROM app_user;
-- The migration log (db/migrate.js) is for the owner only.
DO $$
BEGIN
  IF to_regclass('public.schema_migrations') IS NOT NULL THEN
    REVOKE ALL ON schema_migrations FROM app_user;
  END IF;
END $$;
