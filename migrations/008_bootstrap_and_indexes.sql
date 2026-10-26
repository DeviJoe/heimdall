ALTER TABLE nodes ADD COLUMN bootstrap_nonce text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN bootstrap_token_hash text NOT NULL DEFAULT '';
CREATE INDEX users_login_prefix_idx ON users(login text_pattern_ops) WHERE status<>'deleted';
CREATE INDEX users_kind_id_idx ON users(kind,id) WHERE status<>'deleted';
INSERT INTO schema_migrations(version) VALUES(8);
