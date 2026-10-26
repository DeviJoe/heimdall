ALTER TABLE join_tokens ADD COLUMN name text NOT NULL DEFAULT '' CHECK(length(name)<=120);
WITH expired AS (DELETE FROM join_tokens WHERE expires_at<=now() RETURNING id,name)
INSERT INTO audit_events(actor_id,channel,action,resource_id)
 SELECT 'system','system','join_token.expired',id::text FROM expired;
INSERT INTO schema_migrations(version) VALUES(21);
