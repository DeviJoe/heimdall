CREATE TABLE security_events (id text NOT NULL,node_id uuid NOT NULL REFERENCES nodes,login text NOT NULL,address text NOT NULL,kind text NOT NULL,severity text NOT NULL,observed_at timestamptz NOT NULL,received_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(node_id,id));
CREATE INDEX security_events_recent ON security_events(received_at DESC);
CREATE INDEX security_events_node_recent ON security_events(node_id,received_at DESC);
INSERT INTO schema_migrations(version) VALUES(7);
