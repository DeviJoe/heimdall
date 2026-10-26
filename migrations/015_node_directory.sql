ALTER TABLE nodes ADD COLUMN hostname text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN addresses text[] NOT NULL DEFAULT '{}';
ALTER TABLE nodes ADD COLUMN platform text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN metadata_seen timestamptz;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX users_directory_search ON users USING gin ((lower(login || ' ' || display_name)) gin_trgm_ops) WHERE status<>'deleted';
CREATE INDEX nodes_directory_search ON nodes USING gin ((lower(name || ' ' || hostname || ' ' || ssh_host)) gin_trgm_ops);
INSERT INTO schema_migrations(version) VALUES(15);
