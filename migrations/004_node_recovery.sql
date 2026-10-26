CREATE TABLE node_recovery_tokens (
 id uuid PRIMARY KEY,
 node_id uuid NOT NULL REFERENCES nodes,
 hash text NOT NULL UNIQUE,
 expires_at timestamptz NOT NULL,
 used_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO schema_migrations(version) VALUES(4);
