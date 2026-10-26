-- UNIX groups control native access; Heimdall groups control administration.
CREATE TABLE unix_groups(id uuid PRIMARY KEY,name text NOT NULL UNIQUE,gid int NOT NULL UNIQUE CHECK(gid BETWEEN 10000 AND 2147483646));
CREATE TABLE unix_group_members(group_id uuid REFERENCES unix_groups,user_id uuid REFERENCES users,PRIMARY KEY(group_id,user_id));
CREATE INDEX unix_group_members_user ON unix_group_members(user_id);
CREATE TABLE unix_group_role_bindings(id uuid PRIMARY KEY,unix_group_id uuid REFERENCES unix_groups,role_id uuid REFERENCES roles,group_id uuid NOT NULL REFERENCES server_groups,UNIQUE(unix_group_id,role_id,group_id));
CREATE VIEW effective_unix_members AS SELECT group_id,user_id FROM unix_group_members UNION SELECT g.id,u.id FROM unix_groups g JOIN users u ON u.gid=g.gid;
CREATE VIEW native_role_bindings AS SELECT id,user_id,role_id,group_id FROM effective_role_bindings UNION ALL
 SELECT b.id,m.user_id,b.role_id,c.descendant_id::text FROM unix_group_role_bindings b JOIN effective_unix_members m ON m.group_id=b.unix_group_id JOIN server_group_closure c ON c.ancestor_id=b.group_id;
ALTER TABLE roles ADD COLUMN sudoers text NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN occurrences bigint NOT NULL DEFAULT 1;
ALTER TABLE incidents ADD COLUMN last_seen timestamptz NOT NULL DEFAULT now();
UPDATE incidents SET last_seen=updated_at;
ALTER TABLE join_tokens ADD COLUMN revoked_at timestamptz;
CREATE INDEX join_tokens_group ON join_tokens(group_id);
ALTER TABLE users ADD COLUMN require_sk bool NOT NULL DEFAULT false;
ALTER TABLE user_groups ADD COLUMN require_sk bool NOT NULL DEFAULT false;
CREATE FUNCTION sk_required(subject uuid) RETURNS bool LANGUAGE sql STABLE AS $$
 SELECT coalesce((SELECT (value->>'require_sk')::bool FROM runtime_settings WHERE id=true),false) OR u.require_sk OR EXISTS(SELECT 1 FROM user_group_members m JOIN user_groups g ON g.id=m.group_id WHERE m.user_id=u.id AND g.require_sk) FROM users u WHERE u.id=subject
$$;
INSERT INTO schema_migrations(version) VALUES(9);
