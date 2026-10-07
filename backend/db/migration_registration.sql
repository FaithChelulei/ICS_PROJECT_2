-- Migration: registration request/approval flow. Additive only, safe to
-- run against the live dev database.
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TYPE registration_status_t AS ENUM ('pending', 'approved', 'rejected');

CREATE TABLE registration_requests (
    id                  SERIAL PRIMARY KEY,
    full_name           VARCHAR(255) NOT NULL,
    email               VARCHAR(255) NOT NULL,
    requested_role_id   INTEGER NOT NULL REFERENCES roles(id),
    reason              TEXT,
    status              registration_status_t NOT NULL DEFAULT 'pending',
    reviewed_by         INTEGER REFERENCES users(id),
    reviewed_at         TIMESTAMPTZ,
    rejection_reason    TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_registration_requests_status ON registration_requests(status);
