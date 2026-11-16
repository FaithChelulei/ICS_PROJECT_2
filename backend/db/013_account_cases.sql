-- 013: "Take action" leads to a case, handled entirely on the website.
--
--   1. A Security Auditor marks a person's week "Take action" with a reason
--      (an administrator does the same for an auditor's week). A case opens.
--   2. A System Administrator may PAUSE the account until it is verified:
--      every session ends; the person can still sign in, but sees only a
--      page asking them to explain; every data request is refused.
--   3. The person sends an explanation from that page.
--   4. An administrator decides: VERIFIED (access restored, the person goes
--      on with their own password) or REMOVED (the account is locked and,
--      for an educator, every child's access ends at once).
-- The auditor sees the outcome on People to Review. Every step names who
-- took it and is also in the audit log; nobody can act on their own case.

CREATE TABLE IF NOT EXISTS account_cases (
    id                SERIAL PRIMARY KEY,
    user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    weekly_review_id  INTEGER REFERENCES weekly_reviews(id) ON DELETE SET NULL,
    status            VARCHAR(12) NOT NULL DEFAULT 'reported'
                      CHECK (status IN ('reported', 'paused', 'explained', 'verified', 'removed')),
    reported_by       INTEGER NOT NULL REFERENCES users(id),
    report_note       TEXT NOT NULL CHECK (char_length(btrim(report_note)) >= 10),
    reported_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    paused_by         INTEGER REFERENCES users(id),
    paused_at         TIMESTAMPTZ,
    pause_note        TEXT,
    explanation       TEXT,
    explained_at      TIMESTAMPTZ,
    decided_by        INTEGER REFERENCES users(id),
    decided_at        TIMESTAMPTZ,
    decision_note     TEXT,
    -- Nobody reports, pauses or decides their own case.
    CONSTRAINT case_not_own CHECK (reported_by <> user_id
        AND (paused_by IS NULL OR paused_by <> user_id)
        AND (decided_by IS NULL OR decided_by <> user_id)),
    -- A paused case names who paused it; a closed one who decided it.
    CONSTRAINT case_paused_has_pauser CHECK (status NOT IN ('paused', 'explained') OR paused_by IS NOT NULL),
    CONSTRAINT case_decided_has_decider CHECK (status NOT IN ('verified', 'removed') OR (decided_by IS NOT NULL AND decision_note IS NOT NULL))
);
-- At most one open case per person.
CREATE UNIQUE INDEX IF NOT EXISTS account_cases_one_open
    ON account_cases (user_id) WHERE status IN ('reported', 'paused', 'explained');
CREATE INDEX IF NOT EXISTS account_cases_by_review ON account_cases (weekly_review_id);

GRANT SELECT, INSERT, UPDATE ON account_cases TO app_user;
GRANT USAGE, SELECT ON SEQUENCE account_cases_id_seq TO app_user;
