-- Keep the evidence with every risk score (9 November review): the 7
-- feature values the model was given, the features that raised the score
-- (ml/service/app.py "drivers"), and the exact model that scored it.
-- Additive and safe to re-run. Rows scored before this have NULLs, and the
-- auditor's queue then falls back to the older "likely reason".
ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS features      JSONB;
ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS drivers       JSONB;
ALTER TABLE risk_scores ADD COLUMN IF NOT EXISTS model_version VARCHAR(60);
