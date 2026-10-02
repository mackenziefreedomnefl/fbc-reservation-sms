-- When a reservation was cancelled (member NO reply stamps NOW(); Salesforce
-- cancels carry the exact status-flip time from field history), and a flag
-- for rows where the member said something the bot couldn't handle — dock
-- staff need to follow up personally.
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS cancelled_at TIMESTAMPTZ;
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS needs_attention BOOLEAN NOT NULL DEFAULT FALSE;
