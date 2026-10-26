CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY);
CREATE SEQUENCE IF NOT EXISTS posix_ids START 10000 MAXVALUE 2147483646 NO CYCLE;
CREATE TABLE system_state (id bool PRIMARY KEY DEFAULT true CHECK (id), epoch uuid NOT NULL, revision bigint NOT NULL DEFAULT 1);
CREATE TABLE users (
 id uuid PRIMARY KEY, login text NOT NULL UNIQUE, display_name text NOT NULL,
 status text NOT NULL CHECK(status IN ('invited','active','disabled','deleted')),
 uid int NOT NULL UNIQUE CHECK(uid>=10000), gid int NOT NULL CHECK(gid>=10000),
 home text NOT NULL, shell text NOT NULL, gecos text NOT NULL DEFAULT '',
 password_hash text NOT NULL DEFAULT '', linux_password_hash text NOT NULL DEFAULT '',
 require_mfa bool NOT NULL DEFAULT false, totp_secret text NOT NULL DEFAULT '', last_totp_step bigint NOT NULL DEFAULT 0,
 auth_version bigint NOT NULL DEFAULT 1, source text NOT NULL DEFAULT 'local', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE identities (provider text NOT NULL, subject text NOT NULL, user_id uuid NOT NULL REFERENCES users, PRIMARY KEY(provider,subject));
CREATE TABLE webauthn_credentials (id text PRIMARY KEY,user_id uuid NOT NULL REFERENCES users,credential jsonb NOT NULL);
CREATE INDEX ON webauthn_credentials(user_id);
CREATE TABLE invitations (hash text PRIMARY KEY,user_id uuid NOT NULL REFERENCES users,expires_at timestamptz NOT NULL,used_at timestamptz);
CREATE TABLE roles (id uuid PRIMARY KEY,name text NOT NULL UNIQUE,permissions jsonb NOT NULL DEFAULT '[]',linux_access bool NOT NULL DEFAULT false,sudo jsonb NOT NULL DEFAULT '[]');
CREATE TABLE server_groups (id uuid PRIMARY KEY,name text NOT NULL UNIQUE);
CREATE TABLE role_bindings (id uuid PRIMARY KEY,user_id uuid NOT NULL REFERENCES users,role_id uuid NOT NULL REFERENCES roles,group_id text NOT NULL,UNIQUE(user_id,role_id,group_id));
CREATE INDEX ON role_bindings(group_id,user_id);
CREATE INDEX ON role_bindings(user_id);
CREATE TABLE ssh_keys (id uuid PRIMARY KEY,user_id uuid NOT NULL REFERENCES users,name text NOT NULL,public_key text NOT NULL,fingerprint text NOT NULL UNIQUE,algorithm text NOT NULL,status text NOT NULL CHECK(status IN ('active','revoked','expired')),expires_at timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX ON ssh_keys(user_id);
CREATE INDEX ON ssh_keys(expires_at) WHERE status='active';
CREATE TABLE nodes (id uuid PRIMARY KEY,name text NOT NULL,group_id uuid NOT NULL REFERENCES server_groups,desired_revision bigint NOT NULL,applied_revision bigint NOT NULL DEFAULT 0,digest text NOT NULL DEFAULT '',last_seen timestamptz,last_progress timestamptz NOT NULL DEFAULT now(),pending_since timestamptz NOT NULL DEFAULT now(),status text NOT NULL DEFAULT 'pending',error text NOT NULL DEFAULT '',cert_serial text NOT NULL,cert_expires timestamptz NOT NULL,disabled bool NOT NULL DEFAULT false,generation bigint NOT NULL DEFAULT 0);
CREATE INDEX ON nodes(group_id);
CREATE INDEX ON nodes(pending_since) WHERE desired_revision>applied_revision;
CREATE TABLE node_accounts (node_id uuid NOT NULL REFERENCES nodes,user_id uuid NOT NULL REFERENCES users,revision bigint NOT NULL,PRIMARY KEY(node_id,user_id));
CREATE INDEX ON node_accounts(user_id,node_id);
CREATE TABLE join_tokens (id uuid PRIMARY KEY,hash text NOT NULL UNIQUE,group_id uuid NOT NULL REFERENCES server_groups,expires_at timestamptz NOT NULL,uses int NOT NULL DEFAULT 0,max_uses int NOT NULL CHECK(max_uses>0));
CREATE TABLE sync_operations (id uuid PRIMARY KEY,kind text NOT NULL,resource_id text NOT NULL,user_id uuid REFERENCES users,revision bigint NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE sync_targets (operation_id uuid NOT NULL REFERENCES sync_operations,node_id uuid NOT NULL REFERENCES nodes,revision bigint NOT NULL,status text NOT NULL DEFAULT 'pending',error text NOT NULL DEFAULT '',updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(operation_id,node_id));
CREATE INDEX ON sync_targets(node_id,revision) WHERE status<>'applied';
CREATE TABLE sync_resources (node_id uuid NOT NULL REFERENCES nodes,user_id uuid NOT NULL REFERENCES users,revision bigint NOT NULL,status text NOT NULL,error text NOT NULL DEFAULT '',updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(node_id,user_id));
CREATE TABLE outbox (id bigserial PRIMARY KEY,operation_id uuid NOT NULL REFERENCES sync_operations,created_at timestamptz NOT NULL DEFAULT now(),processed_at timestamptz);
CREATE INDEX ON outbox(id) WHERE processed_at IS NULL;
CREATE TABLE api_tokens (id uuid PRIMARY KEY,user_id uuid NOT NULL REFERENCES users,name text NOT NULL,hash text NOT NULL UNIQUE,audiences jsonb NOT NULL,scopes jsonb NOT NULL,groups jsonb NOT NULL,expires_at timestamptz NOT NULL,revoked_at timestamptz,last_used timestamptz,created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX ON api_tokens(user_id);
CREATE TABLE incidents (id uuid PRIMARY KEY,dedup_key text NOT NULL UNIQUE,kind text NOT NULL,severity text NOT NULL,node_id uuid REFERENCES nodes,group_id uuid REFERENCES server_groups,user_id uuid REFERENCES users,message text NOT NULL,status text NOT NULL DEFAULT 'open',created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE notification_channels (id uuid PRIMARY KEY,user_id uuid NOT NULL REFERENCES users,provider text NOT NULL,provider_subject text NOT NULL,chat_id text NOT NULL,severity text NOT NULL DEFAULT 'warning',enabled bool NOT NULL DEFAULT true,UNIQUE(provider,provider_subject),UNIQUE(user_id,provider));
CREATE TABLE notification_jobs (id uuid PRIMARY KEY,incident_id uuid NOT NULL REFERENCES incidents,channel_id uuid REFERENCES notification_channels,provider text NOT NULL,event text NOT NULL,status text NOT NULL DEFAULT 'pending',attempts int NOT NULL DEFAULT 0,next_attempt timestamptz NOT NULL DEFAULT now(),lease_until timestamptz,error text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(incident_id,channel_id,event));
CREATE INDEX ON notification_jobs(next_attempt) WHERE status IN ('pending','retrying','sending');
CREATE TABLE telegram_updates (id bigint PRIMARY KEY,created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE integration_status (provider text PRIMARY KEY,phase text NOT NULL,error text NOT NULL DEFAULT '',last_attempt timestamptz,last_success timestamptz);
CREATE TABLE audit_events (id bigserial PRIMARY KEY,actor_id text NOT NULL,token_id text NOT NULL DEFAULT '',channel text NOT NULL,action text NOT NULL,resource_id text NOT NULL,details jsonb NOT NULL DEFAULT '{}',created_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX ON audit_events(created_at DESC);
INSERT INTO schema_migrations(version) VALUES(1);
