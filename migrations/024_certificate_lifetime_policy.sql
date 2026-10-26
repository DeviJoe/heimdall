ALTER TABLE runtime_settings ADD COLUMN certificate_policy_version bigint NOT NULL DEFAULT 1;
UPDATE runtime_settings SET value=jsonb_set(value,'{node_certificate_ttl_seconds}','315360000');
ALTER TABLE nodes ADD COLUMN certificate_policy_version bigint NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN issued_certificate_policy_version bigint NOT NULL DEFAULT 0;
CREATE TRIGGER certificate_fleet_change AFTER UPDATE ON nodes FOR EACH ROW
 WHEN (ROW(OLD.cert_expires,OLD.certificate_policy_version) IS DISTINCT FROM ROW(NEW.cert_expires,NEW.certificate_policy_version))
 EXECUTE FUNCTION notify_fleet_change();
-- Existing agents receive the signed certificate policy after this upgrade.
WITH revision AS (UPDATE system_state SET revision=revision+1 RETURNING revision),
operation AS (INSERT INTO sync_operations(id,kind,resource_id,revision)
 SELECT gen_random_uuid(),'certificate.policy','node-certificates',revision FROM revision RETURNING id,revision),
targets AS (UPDATE nodes SET desired_revision=operation.revision,status='pending',pending_since=now(),error=''
 FROM operation WHERE NOT disabled RETURNING nodes.id,operation.id operation_id,operation.revision),
delivery AS (INSERT INTO sync_targets(operation_id,node_id,revision) SELECT operation_id,id,revision FROM targets)
INSERT INTO outbox(operation_id) SELECT id FROM operation;
INSERT INTO schema_migrations(version) VALUES(24);
