ALTER TABLE users ADD COLUMN sync_to_nodes boolean NOT NULL DEFAULT false;
ALTER TABLE roles ADD COLUMN allow_password boolean NOT NULL DEFAULT false;
ALTER TABLE roles ADD COLUMN allow_ssh_keys boolean NOT NULL DEFAULT false;
-- Existing native grants explicitly represented SSH access. Preserve those keys,
-- while removing the former implicit permission to install UNIX passwords.
UPDATE roles SET allow_ssh_keys=true WHERE linux_access;
UPDATE users u SET sync_to_nodes=true WHERE login<>'admin' AND EXISTS (
 SELECT 1 FROM native_role_bindings b JOIN roles r ON r.id=b.role_id
 WHERE b.user_id=u.id AND r.linux_access
);
ALTER TABLE roles ADD CONSTRAINT native_methods_require_access
 CHECK(linux_access OR NOT (allow_password OR allow_ssh_keys));
-- Every existing agent must acknowledge the new policy, including revocations.
WITH revision AS (UPDATE system_state SET revision=revision+1 RETURNING revision),
operation AS (INSERT INTO sync_operations(id,kind,resource_id,revision)
 SELECT gen_random_uuid(),'policy.native_login','native-login',revision FROM revision RETURNING id,revision),
targets AS (UPDATE nodes SET desired_revision=operation.revision,status='pending',pending_since=now(),error=''
 FROM operation RETURNING nodes.id,operation.id operation_id,operation.revision),
delivery AS (INSERT INTO sync_targets(operation_id,node_id,revision) SELECT operation_id,id,revision FROM targets)
INSERT INTO outbox(operation_id) SELECT id FROM operation;
INSERT INTO schema_migrations(version) VALUES(19);
