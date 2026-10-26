ALTER TABLE nodes ADD COLUMN local_error text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN last_local_check timestamptz;
INSERT INTO schema_migrations(version) VALUES (3);
