-- Salesforce trip status (Scheduled / On The Water / Completed / Canceled)
-- carried alongside the app's own confirmation status, refreshed by the
-- same-day sync so the dock can see who's out, back in, or running late.
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS sf_status TEXT;
