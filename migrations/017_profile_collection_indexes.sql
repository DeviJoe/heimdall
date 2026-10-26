CREATE INDEX ssh_keys_user_page ON ssh_keys(user_id,created_at DESC,id DESC);
CREATE INDEX tokens_user_page ON api_tokens(user_id,created_at DESC,id DESC);
CREATE INDEX announcements_page ON announcements(updated_at DESC,id DESC);
CREATE INDEX role_bindings_user_page ON role_bindings(user_id,role_id,id);
CREATE INDEX people_bindings_group_page ON user_group_role_bindings(user_group_id,role_id,id);
INSERT INTO schema_migrations(version) VALUES(17);
