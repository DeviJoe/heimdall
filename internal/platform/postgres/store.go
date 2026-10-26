package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/platform/security"
	"Heimdall/migrations"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

var ErrForbidden = application.ErrForbidden
var ErrNotFound = application.ErrNotFound

type Store struct{ Pool *pgxpool.Pool }

// Database handles are used only inside the persistence adapter.
type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func New(ctx context.Context, dsn string) (*Store, error) {
	c, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	c.MaxConns = 32
	c.MinConns = 2
	c.ConnConfig.ConnectTimeout = 5 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		return nil, err
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool}, nil
}
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, "SELECT pg_advisory_lock(72614821)"); err != nil {
		return err
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock(72614821)")
	if _, err = conn.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations(version int PRIMARY KEY)"); err != nil {
		return err
	}
	list, err := migrations.List()
	if err != nil {
		return err
	}
	for _, migration := range list {
		var exists bool
		if err = conn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", migration.Version).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		sql, err := migrations.Files.ReadFile(migration.File)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, string(sql)); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err = tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}
func jsonValue(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
func (s *Store) Bootstrap(ctx context.Context, password, joinToken string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(72614822)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO system_state(id,epoch) VALUES(true,$1) ON CONFLICT DO NOTHING", uuid.NewString()); err != nil {
		return err
	}
	var groupID string
	err = tx.QueryRow(ctx, "INSERT INTO server_groups(id,name) VALUES($1,'Demo Linux') ON CONFLICT(name) DO UPDATE SET name=excluded.name RETURNING id", uuid.NewString()).Scan(&groupID)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO server_group_closure VALUES($1,$1,0) ON CONFLICT DO NOTHING", groupID); err != nil {
		return err
	}
	defaults := []authorization.Role{{Name: "Administrator", Permissions: []string{"*"}}, {Name: "Observer", Permissions: []string{"users.read", "roles.read", "nodes.read", "sync.read", "incidents.read", "audit.read", "api_docs.read"}}, {Name: "Linux user", LinuxAccess: true, AllowSSHKeys: true, Permissions: []string{}}, {Name: "Linux operator", LinuxAccess: true, AllowSSHKeys: true, Permissions: []string{}, Sudo: []authorization.SudoRule{{Command: "/usr/bin/id", RunAs: "root", NoPassword: true}, {Command: "/usr/bin/whoami", RunAs: "root", NoPassword: true}}}}
	var fresh bool
	if err = tx.QueryRow(ctx, "SELECT NOT EXISTS(SELECT 1 FROM users)").Scan(&fresh); err != nil {
		return err
	}
	var adminRole string
	for _, r := range defaults {
		if !fresh {
			break
		}
		r.Normalize()
		var id string
		err = tx.QueryRow(ctx, "INSERT INTO roles(id,name,permissions,linux_access,sudo,allow_password,allow_ssh_keys) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(name) DO UPDATE SET name=excluded.name RETURNING id", uuid.NewString(), r.Name, jsonValue(r.Permissions), r.LinuxAccess, jsonValue(r.Sudo), r.AllowPassword, r.AllowSSHKeys).Scan(&id)
		if err != nil {
			return err
		}
		if r.Name == "Administrator" {
			adminRole = id
		}
	}
	if fresh {
		if _, err = tx.Exec(ctx, `INSERT INTO user_groups(id,name,mfa_policy,purpose) VALUES(gen_random_uuid(),'Факторы: опционально','none','factor_policy'),(gen_random_uuid(),'Факторы: TOTP','totp','factor_policy'),(gen_random_uuid(),'Факторы: Passkey','passkey','factor_policy'),(gen_random_uuid(),'Факторы: TOTP + Passkey','both','factor_policy') ON CONFLICT(name) DO NOTHING`); err != nil {
			return err
		}
	}
	var adminID string
	err = tx.QueryRow(ctx, "SELECT id FROM users WHERE login='admin'").Scan(&adminID)
	if errors.Is(err, pgx.ErrNoRows) {
		hash, e := security.PasswordHash(password)
		if e != nil {
			return e
		}
		adminID = uuid.NewString()
		_, err = tx.Exec(ctx, "INSERT INTO users(id,login,display_name,status,uid,gid,home,shell,password_hash) SELECT $1,'admin','Administrator','active',v,v,'/home/admin','/bin/bash',$2 FROM (SELECT nextval('posix_ids')::int v) q", adminID, hash)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "INSERT INTO role_bindings(id,user_id,role_id,group_id) VALUES($1,$2,$3,'*')", uuid.NewString(), adminID, adminRole)
	}
	if err != nil {
		return err
	}
	if !fresh {
		return tx.Commit(ctx)
	}
	_, err = tx.Exec(ctx, "INSERT INTO join_tokens(id,hash,group_id,expires_at,max_uses) VALUES($1,$2,$3,now()+interval '30 days',100) ON CONFLICT(hash) DO NOTHING", uuid.NewString(), security.HashToken(joinToken), groupID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) Principal(ctx context.Context, userID, tokenID, audience string) (authorization.Principal, error) {
	return s.principal(ctx, s.Pool, userID, tokenID, audience)
}
func (s *Store) principal(ctx context.Context, q queryer, userID, tokenID, audience string) (authorization.Principal, error) {
	p := authorization.Principal{UserID: userID, TokenID: tokenID, Audience: audience, Bindings: []authorization.Binding{}}
	var status string
	var required, enabled bool
	err := q.QueryRow(ctx, "SELECT login,status,auth_version,require_mfa,mfa_satisfied(id) FROM users WHERE id=$1", userID).Scan(&p.Login, &status, &p.AuthVersion, &required, &enabled)
	if err != nil {
		return p, ErrForbidden
	}
	if status != "active" {
		return p, ErrForbidden
	}
	p.Restricted = !enabled
	if tokenID != "" {
		var scopes, groups, audiences []byte
		err = q.QueryRow(ctx, "SELECT scopes,groups,audiences FROM api_tokens WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()", tokenID, userID).Scan(&scopes, &groups, &audiences)
		if err != nil {
			return p, ErrForbidden
		}
		json.Unmarshal(scopes, &p.TokenScopes)
		json.Unmarshal(groups, &p.TokenGroups)
		var aud []string
		json.Unmarshal(audiences, &aud)
		valid := false
		for _, a := range aud {
			if a == audience {
				valid = true
			}
		}
		if !valid {
			return p, ErrForbidden
		}
	}
	rows, err := q.Query(ctx, "SELECT b.id,b.role_id,b.group_id,r.name,r.permissions,r.linux_access,r.sudo,r.sudoers,r.allow_password,r.allow_ssh_keys FROM effective_role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id=$1", userID)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var b authorization.Binding
		var permissions, sudo []byte
		if err = rows.Scan(&b.ID, &b.RoleID, &b.GroupID, &b.Role.Name, &permissions, &b.Role.LinuxAccess, &sudo, &b.Role.Sudoers, &b.Role.AllowPassword, &b.Role.AllowSSHKeys); err != nil {
			return p, err
		}
		b.UserID = userID
		b.Role.ID = b.RoleID
		json.Unmarshal(permissions, &b.Role.Permissions)
		json.Unmarshal(sudo, &b.Role.Sudo)
		b.Role.Normalize()
		p.Bindings = append(p.Bindings, b)
	}
	p.Prepare()
	return p, rows.Err()
}

type change struct {
	Kind, Resource, Permission, Group, UserID, NodeID string
	All, TransportOnly                                bool
}

func (s *Store) mutate(ctx context.Context, p authorization.Principal, c change, fn func(pgx.Tx) error) (string, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var rev int64
	if err = tx.QueryRow(ctx, "UPDATE system_state SET revision=revision+1 WHERE id=true RETURNING revision").Scan(&rev); err != nil {
		return "", err
	}
	current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
	if err != nil {
		return "", err
	}
	if p.Restricted || current.Restricted {
		return "", ErrForbidden
	}
	if c.Permission != "" && !current.Allowed(c.Permission, c.Group) {
		return "", ErrForbidden
	}
	if c.Permission == "" && !current.Self(c.UserID) {
		return "", ErrForbidden
	}
	if err = fn(tx); err != nil {
		return "", err
	}
	return s.record(ctx, tx, p, c, rev)
}
func (s *Store) record(ctx context.Context, tx pgx.Tx, p authorization.Principal, c change, rev int64) (string, error) {
	id := uuid.NewString()
	if _, err := tx.Exec(ctx, "INSERT INTO sync_operations(id,kind,resource_id,revision,user_id) VALUES($1,$2,$3,$4,NULLIF($5,'')::uuid)", id, c.Kind, c.Resource, rev, c.UserID); err != nil {
		return "", err
	}
	condition := "false"
	var args []any
	if c.NodeID != "" {
		condition = "id=$2::uuid"
		args = append(args, c.NodeID)
	} else if c.All {
		condition = "true"
	} else if c.UserID != "" {
		condition = "id IN (SELECT node_id FROM node_accounts WHERE user_id=$2::uuid) OR group_id::text IN (SELECT b.group_id FROM native_role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id=$2::uuid AND r.linux_access) OR EXISTS(SELECT 1 FROM native_role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id=$2::uuid AND b.group_id='*' AND r.linux_access)"
		args = append(args, c.UserID)
	} else if c.Group != "" && c.Group != "*" {
		condition = "group_id=$2::uuid"
		args = append(args, c.Group)
	}
	if c.TransportOnly {
		condition = "false"
		args = nil
	}
	params := append([]any{rev}, args...)
	rows, err := tx.Query(ctx, "UPDATE nodes SET desired_revision=$1,pending_since=CASE WHEN desired_revision=applied_revision THEN now() ELSE pending_since END,status='pending',error='' WHERE ("+condition+") RETURNING id", params...)
	if err != nil {
		return "", err
	}
	var ids []string
	for rows.Next() {
		var v string
		if err = rows.Scan(&v); err != nil {
			rows.Close()
			return "", err
		}
		ids = append(ids, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	if len(ids) > 0 {
		_, err = tx.Exec(ctx, "INSERT INTO sync_targets(operation_id,node_id,revision) SELECT $1,id,$2 FROM unnest($3::uuid[]) id", id, rev, ids)
		if err != nil {
			return "", err
		}
	}
	if _, err = tx.Exec(ctx, "INSERT INTO outbox(operation_id) VALUES($1)", id); err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_events(actor_id,token_id,channel,action,resource_id) VALUES($1,$2,$3,$4,$5)", p.UserID, p.TokenID, channel(p), c.Kind, c.Resource); err != nil {
		return "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	return id, nil
}
func channel(p authorization.Principal) string {
	if p.TokenID != "" {
		return p.Audience
	}
	return "web"
}
func (s *Store) Audit(ctx context.Context, p authorization.Principal, action, resource string) error {
	_, err := s.Pool.Exec(ctx, "INSERT INTO audit_events(actor_id,token_id,channel,action,resource_id) VALUES($1,$2,$3,$4,$5)", p.UserID, p.TokenID, channel(p), action, resource)
	return err
}
func (s *Store) Health(ctx context.Context) error { return s.Pool.Ping(ctx) }
func (s *Store) Epoch(ctx context.Context) (string, error) {
	var v string
	err := s.Pool.QueryRow(ctx, "SELECT epoch FROM system_state").Scan(&v)
	return v, err
}
func (s *Store) Close() { s.Pool.Close() }
func failure(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return fmt.Errorf("database operation failed: %w", err)
}
