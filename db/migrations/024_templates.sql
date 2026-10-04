-- Per-franchise overrides for every staff message type (follow-up, weather,
-- small-craft notices, quick replies). Confirmation stays in
-- message_template for compatibility. Keys absent = built-in default.
ALTER TABLE franchises ADD COLUMN IF NOT EXISTS templates JSONB NOT NULL DEFAULT '{}';
