-- Human-readable timeframe (PDTF) name from Salesforce, e.g.
-- "Fall Weekend - Morning" — shown under the planned arrival/return.
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS sf_timeframe TEXT;
