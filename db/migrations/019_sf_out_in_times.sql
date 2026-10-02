-- Exact check-out / back-in times, sourced from Salesforce status field
-- history (every B25__Status__c flip is timestamped there).
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS sf_out_at TIMESTAMPTZ;
ALTER TABLE reservations ADD COLUMN IF NOT EXISTS sf_in_at TIMESTAMPTZ;
