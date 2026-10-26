UPDATE roles SET permissions='[]' WHERE permissions='null';
UPDATE roles SET sudo='[]' WHERE sudo='null';
ALTER TABLE server_groups ADD COLUMN parent_id uuid REFERENCES server_groups;
CREATE INDEX server_groups_parent ON server_groups(parent_id);
CREATE TABLE server_group_closure (ancestor_id uuid REFERENCES server_groups, descendant_id uuid REFERENCES server_groups, depth int NOT NULL CHECK(depth BETWEEN 0 AND 32), PRIMARY KEY(ancestor_id,descendant_id));
INSERT INTO server_group_closure SELECT id,id,0 FROM server_groups;
ALTER TABLE nodes ADD COLUMN ssh_host text NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN ssh_port int NOT NULL DEFAULT 22 CHECK(ssh_port BETWEEN 1 AND 65535);
ALTER TABLE users ADD COLUMN kind text NOT NULL DEFAULT 'human' CHECK(kind IN ('human','service'));
ALTER TABLE users ADD COLUMN mfa_policy text NOT NULL DEFAULT 'none' CHECK(mfa_policy IN ('none','any','totp','passkey','both'));
CREATE TABLE user_groups (id uuid PRIMARY KEY, name text NOT NULL UNIQUE, mfa_policy text NOT NULL DEFAULT 'none' CHECK(mfa_policy IN ('none','any','totp','passkey','both')));
CREATE TABLE user_group_members (group_id uuid REFERENCES user_groups, user_id uuid REFERENCES users, PRIMARY KEY(group_id,user_id));
CREATE INDEX user_group_members_user ON user_group_members(user_id);
CREATE TABLE user_group_role_bindings (id uuid PRIMARY KEY, user_group_id uuid REFERENCES user_groups, role_id uuid REFERENCES roles, group_id text NOT NULL, UNIQUE(user_group_id,role_id,group_id));
CREATE VIEW effective_role_bindings AS
SELECT b.id,b.user_id,b.role_id,coalesce(c.descendant_id::text,b.group_id) group_id FROM (
 SELECT id,user_id,role_id,group_id FROM role_bindings
 UNION ALL SELECT b.id,m.user_id,b.role_id,b.group_id FROM user_group_role_bindings b JOIN user_group_members m ON m.group_id=b.user_group_id
) b LEFT JOIN server_group_closure c ON c.ancestor_id::text=b.group_id;
CREATE TABLE runtime_settings (id bool PRIMARY KEY DEFAULT true CHECK(id), version bigint NOT NULL DEFAULT 1, value jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
-- Enrollment policies compose by intersection: each applicable policy must pass.
CREATE FUNCTION mfa_satisfied(subject uuid) RETURNS bool LANGUAGE sql STABLE AS $$
 SELECT u.kind='service' OR NOT EXISTS (
  SELECT 1 FROM (
    SELECT CASE WHEN u.require_mfa AND u.mfa_policy='none' THEN 'any' ELSE u.mfa_policy END policy
    UNION ALL SELECT g.mfa_policy FROM user_group_members m JOIN user_groups g ON g.id=m.group_id WHERE m.user_id=u.id
  ) policies WHERE CASE policy
    WHEN 'none' THEN false
    WHEN 'any' THEN NOT (u.totp_secret<>'' OR EXISTS(SELECT 1 FROM webauthn_credentials w WHERE w.user_id=u.id))
    WHEN 'totp' THEN u.totp_secret=''
    WHEN 'passkey' THEN NOT EXISTS(SELECT 1 FROM webauthn_credentials w WHERE w.user_id=u.id)
    WHEN 'both' THEN u.totp_secret='' OR NOT EXISTS(SELECT 1 FROM webauthn_credentials w WHERE w.user_id=u.id)
  END
 ) FROM users u WHERE u.id=subject
$$;
INSERT INTO schema_migrations(version) VALUES(6);
