ALTER TABLE sync_operations ADD COLUMN IF NOT EXISTS user_id uuid REFERENCES users;
CREATE INDEX IF NOT EXISTS sync_operations_user_revision ON sync_operations(user_id,revision);
CREATE TABLE IF NOT EXISTS integration_status (provider text PRIMARY KEY,phase text NOT NULL,error text NOT NULL DEFAULT '',last_attempt timestamptz,last_success timestamptz);
UPDATE sync_operations o SET user_id=u.id FROM users u WHERE o.user_id IS NULL AND o.resource_id=u.id::text AND (o.kind LIKE 'user.%' OR o.kind='key.expire');
UPDATE sync_operations o SET user_id=k.user_id FROM ssh_keys k WHERE o.user_id IS NULL AND o.resource_id=k.id::text AND o.kind LIKE 'key.%';
INSERT INTO schema_migrations(version) VALUES(2);
