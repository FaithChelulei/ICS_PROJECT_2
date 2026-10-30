-- Migration: adds full_name + username to users, so the app can greet
-- people by their first name and let them log in with either their email
-- or a generated username. Additive + backfilling, safe to re-run.
--
-- This must be run by the table owner (the app's runtime DB role,
-- app_user, deliberately has no ALTER privileges -- see schema.sql /
-- least-privilege notes). Run this in pgAdmin connected as the owner
-- BEFORE testing login again -- authController.js already queries
-- u.full_name and u.username, so login/me/approveRequest will fail with
-- "column does not exist" until this has been applied.

-- 1. Add the columns.
ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(255);

-- 2. Backfill full_name for existing users from registration_requests
--    (the public request form already captured this; it was just never
--    copied onto the users row when a request got approved -- the gap
--    this migration and the updated approveRequest() code both close).
--    DISTINCT ON picks each email's most recent request if there's more
--    than one.
UPDATE users u
SET full_name = rr.full_name
FROM (
    SELECT DISTINCT ON (email) email, full_name
    FROM registration_requests
    ORDER BY email, created_at DESC, id DESC
) rr
WHERE u.full_name IS NULL AND u.email = rr.email;

-- 3. Fallback for any account with no matching registration_request at
--    all (e.g. a row inserted directly by db/seed.js) -- derive something
--    readable from the email's local part rather than leaving it blank.
UPDATE users
SET full_name = INITCAP(REPLACE(SPLIT_PART(email, '@', 1), '.', ' '))
WHERE full_name IS NULL;

-- 4. Generate a unique username per existing user, using the same scheme
--    registrationController.js's generateUsername() uses for new accounts:
--    lowercase full name, letters only, joined with dots, numeric suffix
--    on collision. Done in id order so it's deterministic.
DO $$
DECLARE
    r RECORD;
    base_username VARCHAR;
    candidate VARCHAR;
    suffix INT;
BEGIN
    FOR r IN SELECT id, full_name FROM users WHERE username IS NULL ORDER BY id LOOP
        base_username := regexp_replace(lower(r.full_name), '[^a-z\s]', '', 'g');
        base_username := trim(base_username);
        base_username := regexp_replace(base_username, '\s+', '.', 'g');
        IF base_username = '' THEN
            base_username := 'user';
        END IF;

        candidate := base_username;
        suffix := 1;
        WHILE EXISTS (SELECT 1 FROM users WHERE username = candidate) LOOP
            suffix := suffix + 1;
            candidate := base_username || suffix::text;
        END LOOP;

        UPDATE users SET username = candidate WHERE id = r.id;
    END LOOP;
END $$;

-- 5. Now that every row has a value, enforce the same guarantees the app
--    relies on (authController.js looks up by username, so it must be
--    unique; registrationController.js never leaves it blank for a new
--    account either).
ALTER TABLE users ALTER COLUMN username SET NOT NULL;
ALTER TABLE users ADD CONSTRAINT users_username_unique UNIQUE (username);

-- Sanity check -- run this after and confirm every row has both columns
-- filled in:
-- SELECT id, email, full_name, username FROM users ORDER BY id;
