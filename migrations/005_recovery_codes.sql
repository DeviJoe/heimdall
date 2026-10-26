CREATE TABLE recovery_codes(user_id uuid REFERENCES users, hash text PRIMARY KEY, used_at timestamptz);
INSERT INTO schema_migrations(version) VALUES(5);
