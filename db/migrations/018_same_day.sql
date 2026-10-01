-- Same-day call-ins: reservations that appeared mid-day for that same day.
-- They auto-confirm on import (the member just booked — no confirm text
-- needed) and the UI tags them so the dock knows why they're confirmed.
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS same_day BOOLEAN NOT NULL DEFAULT FALSE;

-- Backfill the two call-ins that landed on 2026-10-01 before the flag existed.
UPDATE reservations SET same_day = TRUE WHERE id IN ('F1-JAX-B11-015', 'F1-CAM-B9-015');
