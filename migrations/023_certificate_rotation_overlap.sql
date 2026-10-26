-- A lost renewal response or interrupted local save must not strand an agent.
-- Only the immediately preceding, still-valid certificate overlaps briefly.
ALTER TABLE nodes ADD COLUMN previous_cert_serial text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN previous_cert_expires timestamptz;
INSERT INTO schema_migrations(version) VALUES(23);
