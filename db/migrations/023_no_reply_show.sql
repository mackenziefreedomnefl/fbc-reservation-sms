-- Member never answered the confirmation text but checked out anyway —
-- auto-confirmed by the sync, with this flag so staff can see who ignores
-- the texts but still shows up.
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS no_reply_show BOOLEAN NOT NULL DEFAULT FALSE;
