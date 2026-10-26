ALTER TABLE join_tokens DROP CONSTRAINT join_tokens_max_uses_check;
ALTER TABLE join_tokens ADD CONSTRAINT join_tokens_max_uses_check CHECK(max_uses>=0);
ALTER TABLE join_tokens ALTER COLUMN uses TYPE bigint;
INSERT INTO schema_migrations(version) VALUES(14);
