CREATE INDEX users_primary_gid ON users(gid) WHERE status<>'deleted';
INSERT INTO schema_migrations(version) VALUES(12);
