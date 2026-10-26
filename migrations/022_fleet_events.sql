CREATE FUNCTION notify_fleet_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_notify('heimdall_fleet','changed');
 RETURN NULL;
END;
$$;
CREATE TRIGGER fleet_insert AFTER INSERT OR DELETE ON nodes
 FOR EACH STATEMENT EXECUTE FUNCTION notify_fleet_change();
-- Heartbeats without a state or metadata change produce no notification.
CREATE TRIGGER fleet_change AFTER UPDATE ON nodes FOR EACH ROW
 WHEN (ROW(OLD.name,OLD.group_id,OLD.disabled,OLD.desired_revision,OLD.applied_revision,OLD.status,OLD.error,OLD.local_error,OLD.hostname,OLD.addresses,OLD.platform,OLD.ssh_host,OLD.ssh_port)
 IS DISTINCT FROM ROW(NEW.name,NEW.group_id,NEW.disabled,NEW.desired_revision,NEW.applied_revision,NEW.status,NEW.error,NEW.local_error,NEW.hostname,NEW.addresses,NEW.platform,NEW.ssh_host,NEW.ssh_port))
 EXECUTE FUNCTION notify_fleet_change();
INSERT INTO schema_migrations(version) VALUES(22);
