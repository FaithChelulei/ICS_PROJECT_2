-- Child Data Security System — PostgreSQL schema
-- Implements the ERD from Chapter 3.4.3/3.4.4 of the proposal.
--
-- Key design decision (data separation requirement): a child's identifying
-- information (name, DOB, family background) lives in child_identifiers,
-- completely separate from developmental_records. The two are linked only
-- through child_profiles.id, which carries no personal information. A user
-- whose role permits developmental records does NOT automatically see the
-- child's identity — that is a separate permission, enforced in the RBAC
-- middleware, not just in this schema.

-- ============================================================
-- ROLES & USERS
-- ============================================================

CREATE TABLE roles (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(32) UNIQUE NOT NULL      -- 'Caregiver' | 'SecurityAuditor' | 'SysAdmin'
);

INSERT INTO roles (name) VALUES ('Caregiver'), ('SecurityAuditor'), ('SysAdmin');

CREATE TABLE users (
    id              SERIAL PRIMARY KEY,
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,        -- bcrypt hash, never plaintext
    role_id         INTEGER NOT NULL REFERENCES roles(id),
    mfa_required    BOOLEAN NOT NULL DEFAULT FALSE, -- true for SecurityAuditor & SysAdmin
    is_locked       BOOLEAN NOT NULL DEFAULT FALSE,
    locked_reason   VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One-time codes for the MFA step (Security Auditor / SysAdmin logins)
CREATE TABLE mfa_codes (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   VARCHAR(255) NOT NULL,            -- hashed, same reason as passwords
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Server-side session registry so a session can actually be force-logged-out
-- (a bare JWT can't be revoked before it expires — this table is what makes
-- the automatic "invalidate this session" risk response enforceable).
CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    revoked_reason  VARCHAR(255)
);

-- ============================================================
-- CHILD DATA — identity and developmental records kept apart
-- ============================================================

CREATE TABLE child_profiles (
    id              SERIAL PRIMARY KEY,
    caregiver_id    INTEGER NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE child_identifiers (
    id                  SERIAL PRIMARY KEY,
    child_profile_id    INTEGER UNIQUE NOT NULL REFERENCES child_profiles(id) ON DELETE CASCADE,
    full_name_enc       BYTEA NOT NULL,   -- AES-256-GCM: iv || ciphertext || authTag, self-contained
    date_of_birth_enc   BYTEA NOT NULL,
    family_background_enc BYTEA
);

CREATE TABLE developmental_records (
    id                  SERIAL PRIMARY KEY,
    child_profile_id    INTEGER NOT NULL REFERENCES child_profiles(id) ON DELETE CASCADE,
    milestone_enc       BYTEA NOT NULL,   -- AES-256-GCM: iv || ciphertext || authTag, self-contained
    health_indicator_enc BYTEA NOT NULL,
    assessment_score_enc BYTEA NOT NULL,
    progress_notes_enc  BYTEA,
    created_by          INTEGER NOT NULL REFERENCES users(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE consent_records (
    id                  SERIAL PRIMARY KEY,
    child_profile_id    INTEGER NOT NULL REFERENCES child_profiles(id) ON DELETE CASCADE,
    caregiver_id        INTEGER NOT NULL REFERENCES users(id),
    consent_given       BOOLEAN NOT NULL,
    scope               VARCHAR(100) NOT NULL DEFAULT 'full_record_access',
    recorded_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- ACCESS SESSIONS, ML RISK SCORES, RESPONSE STATE
-- ============================================================

CREATE TABLE access_requests (
    id                  SERIAL PRIMARY KEY,
    user_id             INTEGER NOT NULL REFERENCES users(id),
    child_profile_id    INTEGER REFERENCES child_profiles(id),
    action_type         VARCHAR(64) NOT NULL,     -- 'view_record' | 'submit_record' | 'login' ...
    pc_name             VARCHAR(100),
    ip_address          VARCHAR(64),
    requested_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TYPE owner_response_t AS ENUM ('pending', 'confirmed_benign', 'not_me');
CREATE TYPE auditor_status_t AS ENUM ('pending', 'reviewing', 'confirmed', 'escalated');

CREATE TABLE risk_scores (
    id                  SERIAL PRIMARY KEY,
    access_request_id   INTEGER UNIQUE NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
    isoforest_score     NUMERIC(6,4) NOT NULL,
    autoencoder_score   NUMERIC(6,4) NOT NULL,
    combined_score      NUMERIC(6,4) NOT NULL,
    role_threshold      NUMERIC(6,4) NOT NULL,
    is_flagged          BOOLEAN NOT NULL,
    owner_response       owner_response_t NOT NULL DEFAULT 'pending',
    auditor_status        auditor_status_t NOT NULL DEFAULT 'pending',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- AUDIT LOG — append-only
-- ============================================================

CREATE TABLE audit_log (
    id                  BIGSERIAL PRIMARY KEY,
    access_request_id   INTEGER REFERENCES access_requests(id),
    user_id             INTEGER REFERENCES users(id),
    action              VARCHAR(100) NOT NULL,
    detail              TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Make the audit log genuinely immutable at the database level: the
-- application's own DB login role is never granted UPDATE/DELETE on this
-- table, only INSERT + SELECT. Run after creating that role, e.g.:
--   REVOKE UPDATE, DELETE ON audit_log FROM app_user;
--   GRANT INSERT, SELECT ON audit_log TO app_user;

CREATE INDEX idx_access_requests_user ON access_requests(user_id);
CREATE INDEX idx_risk_scores_flagged ON risk_scores(is_flagged);
CREATE INDEX idx_audit_log_user ON audit_log(user_id);
