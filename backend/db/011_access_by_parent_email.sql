-- 011: a teacher asks the PARENT (by the parent's email), not the child.
--
-- 010 had the parent hand the teacher a sharing code in person. Most
-- parents never meet the teacher (children travel by school transport), so
-- that step did not happen in practice. What the school does have is each
-- parent's email, from the admission form. So now:
--   1. the teacher enters the parent's email and a reason;
--   2. if that email belongs to a parent on ChildGuard, the parent is
--      emailed and sees the request (the teacher gets the same answer either
--      way, so a teacher cannot find out who uses ChildGuard);
--   3. the parent chooses WHICH of their children to share, and for how
--      long, or refuses. The teacher never learns about any other child.
-- Row-level security (has_child_access) is unchanged: access still means a
-- granted, unexpired row for that teacher and that child.

-- The parent asked, and the email the teacher typed. A pending request has
-- no child yet; the parent picks one when granting.
ALTER TABLE educator_access ADD COLUMN IF NOT EXISTS caregiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE educator_access ADD COLUMN IF NOT EXISTS requested_email VARCHAR(255);
ALTER TABLE educator_access ALTER COLUMN child_profile_id DROP NOT NULL;

-- Requests made under 010 belong to the child's parent.
UPDATE educator_access ea SET caregiver_id = cp.caregiver_id
FROM child_profiles cp WHERE cp.id = ea.child_profile_id AND ea.caregiver_id IS NULL;

-- Access that was granted (or later revoked) always names a child.
ALTER TABLE educator_access DROP CONSTRAINT IF EXISTS granted_names_child;
ALTER TABLE educator_access ADD CONSTRAINT granted_names_child
    CHECK (status IN ('pending', 'refused') OR child_profile_id IS NOT NULL);

-- One waiting request per teacher and email address.
CREATE UNIQUE INDEX IF NOT EXISTS educator_access_one_pending_per_email
    ON educator_access (educator_id, lower(requested_email)) WHERE status = 'pending' AND requested_email IS NOT NULL;
CREATE INDEX IF NOT EXISTS educator_access_by_caregiver ON educator_access (caregiver_id, status);

-- The sharing code is no longer used.
ALTER TABLE child_profiles DROP COLUMN IF EXISTS share_code;
