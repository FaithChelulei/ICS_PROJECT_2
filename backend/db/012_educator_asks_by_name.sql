-- 012: the EDUCATOR asks, by the child's name; the PARENT decides.
--
-- Replaces how access starts (010 used a sharing code, 011 the parent's
-- email). Now:
--   1. An educator's account is verified once: the request names the ECD
--      centre and its phone number, and the System Administrator must
--      record how they confirmed it with the centre before approving.
--   2. The educator types a child's full name and a reason. ChildGuard looks
--      for active children with that name, aged 3 to 6 (ECD age), and puts
--      the request on each matching child's parent's page. The educator
--      gets the same reply whether or not anything matched, so the form
--      cannot be used to find out which children are registered.
--   3. The parent grants (until the chosen date, and never past the child's
--      7th birthday) or refuses. Row-level security is unchanged
--      (has_child_access in 010).
--
-- Names are encrypted with a fresh random IV each time, so the database
-- cannot search them. Each child therefore also gets a BLIND INDEX: a
-- keyed one-way fingerprint (HMAC-SHA256) of the normalised name, made
-- with a key derived from the data key (services/nameIndex.js). It allows
-- an exact-match lookup without decrypting anything, and cannot be turned
-- back into the name without the key.

-- 1. Educator verification.
ALTER TABLE registration_requests ADD COLUMN IF NOT EXISTS ecd_centre VARCHAR(200);
ALTER TABLE registration_requests ADD COLUMN IF NOT EXISTS centre_phone VARCHAR(40);
ALTER TABLE registration_requests ADD COLUMN IF NOT EXISTS verification_note TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS ecd_centre VARCHAR(200);
ALTER TABLE users ADD COLUMN IF NOT EXISTS centre_phone VARCHAR(40);
ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_note TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS verified_by INTEGER REFERENCES users(id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ;

-- 2. The blind index of each child's name.
ALTER TABLE child_identifiers ADD COLUMN IF NOT EXISTS name_index CHAR(64);
ALTER TABLE child_identifiers ADD COLUMN IF NOT EXISTS name_index_key_id SMALLINT;
CREATE INDEX IF NOT EXISTS child_identifiers_name_index ON child_identifiers (name_index);

-- 3. What the educator asked (what they typed), kept apart from the
-- per-child requests the parents see. The educator sees only this table,
-- never how many children (if any) matched.
CREATE TABLE IF NOT EXISTS educator_asks (
    id           SERIAL PRIMARY KEY,
    educator_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    child_name   VARCHAR(200) NOT NULL CHECK (char_length(btrim(child_name)) >= 3),
    reason       TEXT NOT NULL CHECK (char_length(btrim(reason)) >= 10),
    asked_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS educator_asks_by_educator ON educator_asks (educator_id, asked_at);
ALTER TABLE educator_access ADD COLUMN IF NOT EXISTS ask_id INTEGER REFERENCES educator_asks(id) ON DELETE SET NULL;

-- New columns on existing tables inherit app_user's table rights (007).
GRANT SELECT, INSERT ON educator_asks TO app_user;
GRANT USAGE, SELECT ON SEQUENCE educator_asks_id_seq TO app_user;
