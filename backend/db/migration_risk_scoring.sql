-- Day 2: ML risk-scoring integration.
--
-- Adds session grouping to access_requests so the live feature computation
-- (backend/src/services/featureComputation.js) can compute "events in THIS
-- session" (files_accessed_per_session) the same way the CERT training data
-- grouped events into sessions -- not just "events by this user ever".
-- Everything else needed for Day 2 (access_requests, risk_scores, sessions,
-- the owner_response_t / auditor_status_t enums) already existed from the
-- Day 1 schema -- this is the one genuinely new column.

ALTER TABLE access_requests
  ADD COLUMN IF NOT EXISTS session_id UUID REFERENCES sessions(id);

CREATE INDEX IF NOT EXISTS idx_access_requests_session ON access_requests(session_id);
