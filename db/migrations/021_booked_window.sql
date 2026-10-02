-- The booked TIMEFRAME (B25 slot, often a whole-day block) kept alongside
-- the member's planned arrival/return. Used as the auto-apply bounds for
-- texted time changes and shown subtly in the UI.
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS sf_window_start TIMESTAMPTZ;
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS sf_window_end TIMESTAMPTZ;
