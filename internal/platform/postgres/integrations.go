package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/identity"
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
)

func (s *Store) IdentityUser(ctx context.Context, provider, subject string) (identity.User, error) {
	var id string
	if err := s.Pool.QueryRow(ctx, "SELECT i.user_id FROM identities i JOIN users u ON u.id=i.user_id WHERE provider=$1 AND subject=$2 AND u.status='active'", provider, subject).Scan(&id); err != nil {
		return identity.User{}, ErrForbidden
	}
	return s.User(ctx, id)
}
func (s *Store) LinkIdentity(ctx context.Context, p authorization.Principal, provider, subject, userID string) error {
	if !p.Allowed("users.manage", "*") {
		return ErrForbidden
	}
	if provider == "" || subject == "" {
		return errors.New("provider and subject required")
	}
	_, err := s.mutate(ctx, p, change{Kind: "identity.link", Resource: userID, Permission: "users.manage", Group: "*"}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO identities(provider,subject,user_id) VALUES($1,$2,$3)", provider, subject, userID)
		return err
	})
	return err
}
func (s *Store) Notifications(ctx context.Context, p authorization.Principal) ([]map[string]any, error) {
	if !p.Self(p.UserID) {
		return nil, ErrForbidden
	}
	rows, err := s.Pool.Query(ctx, "SELECT id,provider,enabled,severity FROM notification_channels WHERE user_id=$1", p.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, provider, severity string
		var enabled bool
		if err = rows.Scan(&id, &provider, &enabled, &severity); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "provider": provider, "enabled": enabled, "severity": severity})
	}
	return out, rows.Err()
}
func (s *Store) LinkNotification(ctx context.Context, userID, provider, subject, chatID string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var active bool
	if err = tx.QueryRow(ctx, "SELECT status='active' FROM users WHERE id=$1 FOR UPDATE", userID).Scan(&active); err != nil || !active {
		return ErrForbidden
	}
	_, err = tx.Exec(ctx, "INSERT INTO notification_channels(id,user_id,provider,provider_subject,chat_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT(user_id,provider) DO UPDATE SET provider_subject=excluded.provider_subject,chat_id=excluded.chat_id,enabled=true", uuid.NewString(), userID, provider, subject, chatID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO audit_events(actor_id,channel,action,resource_id) VALUES($1,'web','notification.link',$2)", userID, provider)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) UnlinkNotification(ctx context.Context, p authorization.Principal, id string) error {
	if !p.Self(p.UserID) {
		return ErrForbidden
	}
	tag, err := s.Pool.Exec(ctx, "UPDATE notification_channels SET enabled=false WHERE id=$1 AND user_id=$2", id, p.UserID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrForbidden
	}
	return s.Audit(ctx, p, "notification.unlink", id)
}

type NotificationJob = application.NotificationJob

func (s *Store) ClaimNotifications(ctx context.Context) ([]NotificationJob, error) {
	rows, err := s.Pool.Query(ctx, `WITH claimed AS (UPDATE notification_jobs SET status='sending',attempts=attempts+1,lease_until=now()+interval '1 minute' WHERE id IN (SELECT id FROM notification_jobs WHERE (status IN ('pending','retrying') OR (status='sending' AND lease_until<now())) AND next_attempt<=now() ORDER BY next_attempt LIMIT 20 FOR UPDATE SKIP LOCKED) RETURNING *) SELECT j.id,c.user_id,j.provider,c.chat_id,c.provider_subject,i.kind,i.severity,coalesce(i.group_id::text,'*'),coalesce(i.user_id::text,''),i.message,i.status,j.attempts FROM claimed j JOIN notification_channels c ON c.id=j.channel_id JOIN incidents i ON i.id=j.incident_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NotificationJob{}
	for rows.Next() {
		var j NotificationJob
		if err = rows.Scan(&j.ID, &j.UserID, &j.Provider, &j.ChatID, &j.Subject, &j.Kind, &j.Severity, &j.GroupID, &j.IncidentUserID, &j.Message, &j.Status, &j.Attempts); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
func (s *Store) NotificationAllowed(ctx context.Context, j NotificationJob) bool {
	var enabled bool
	err := s.Pool.QueryRow(ctx, "SELECT enabled FROM notification_channels WHERE user_id=$1 AND provider=$2 AND provider_subject=$3", j.UserID, j.Provider, j.Subject).Scan(&enabled)
	if err != nil || !enabled {
		return false
	}
	p, err := s.Principal(ctx, j.UserID, "", "api")
	return err == nil && (p.Allowed("incidents.read", j.GroupID) || p.Self(j.IncidentUserID))
}
func (s *Store) FinishNotification(ctx context.Context, id, status, detail string, retry time.Duration) error {
	_, err := s.Pool.Exec(ctx, "UPDATE notification_jobs SET status=$2,error=$3,next_attempt=$4,lease_until=NULL WHERE id=$1", id, status, detail, time.Now().Add(retry))
	return err
}
func (s *Store) TelegramUpdate(ctx context.Context, id int64) (bool, error) {
	tag, err := s.Pool.Exec(ctx, "INSERT INTO telegram_updates(id) VALUES($1) ON CONFLICT DO NOTHING", id)
	return err == nil && tag.RowsAffected() == 1, err
}
func (s *Store) TelegramPrincipal(ctx context.Context, subject string) (authorization.Principal, error) {
	var id string
	err := s.Pool.QueryRow(ctx, "SELECT user_id FROM notification_channels WHERE provider='telegram' AND provider_subject=$1 AND enabled", subject).Scan(&id)
	if err != nil {
		return authorization.Principal{}, ErrForbidden
	}
	return s.Principal(ctx, id, "", "api")
}

type DirectoryUser = application.DirectoryUser

// ImportDirectory receives only a complete, successfully paged directory result.
// Diffing is linear in directory size; writes use a bounded number of SQL statements.
func (s *Store) ImportDirectory(ctx context.Context, provider string, remote []DirectoryUser) error {
	if len(remote) > 50000 {
		return errors.New("directory size exceeds safety bound")
	}
	type entry struct {
		ID      string `json:"id"`
		Subject string `json:"subject"`
		Login   string `json:"login"`
		Name    string `json:"name"`
		New     bool   `json:"new"`
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var rev int64
	if err = tx.QueryRow(ctx, "UPDATE system_state SET revision=revision+1 RETURNING revision").Scan(&rev); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, "SELECT i.subject,u.id,u.login,u.display_name FROM identities i JOIN users u ON u.id=i.user_id WHERE i.provider=$1", provider)
	if err != nil {
		return err
	}
	existing := map[string]entry{}
	for rows.Next() {
		var e entry
		if err = rows.Scan(&e.Subject, &e.ID, &e.Login, &e.Name); err != nil {
			rows.Close()
			return err
		}
		existing[e.Subject] = e
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(remote) == 0 && len(existing) > 0 {
		return errors.New("empty directory result cannot revoke an existing directory; verify the source and filter")
	}
	seen := make([]string, 0, len(remote))
	changes := make([]entry, 0)
	subjects := map[string]bool{}
	logins := map[string]bool{}
	for _, r := range remote {
		if r.Subject == "" || subjects[r.Subject] || logins[r.Login] {
			return errors.New("directory identities and logins must be unique")
		}
		subjects[r.Subject] = true
		logins[r.Login] = true
		seen = append(seen, r.Subject)
		u := identity.User{ID: "validation", Login: r.Login, UID: 10000, GID: 10000, Home: "/home/" + r.Login, Shell: "/bin/bash", DisplayName: r.DisplayName}
		if err = u.Validate(); err != nil {
			return err
		}
		old, found := existing[r.Subject]
		if found && old.Login != r.Login {
			return errors.New("directory login rename requires explicit maintenance")
		}
		if !found {
			changes = append(changes, entry{ID: uuid.NewString(), Subject: r.Subject, Login: r.Login, Name: r.DisplayName, New: true})
		} else if old.Name != r.DisplayName {
			old.Name = r.DisplayName
			changes = append(changes, old)
		}
	}
	if len(changes) > 0 {
		data := jsonValue(changes)
		if _, err = tx.Exec(ctx, `WITH entries AS (SELECT e.*,nextval('posix_ids')::int AS uid FROM jsonb_to_recordset($2) AS e(id uuid,subject text,login text,name text,new boolean) WHERE e.new) INSERT INTO users(id,login,display_name,status,uid,gid,home,shell,source) SELECT id,login,name,'active',uid,uid,'/home/'||login,'/bin/bash',$1 FROM entries`, provider, data); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO identities(provider,subject,user_id) SELECT $1,subject,id FROM jsonb_to_recordset($2) AS e(id uuid,subject text,login text,name text,new boolean) WHERE e.new`, provider, data); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE users u SET display_name=e.name FROM jsonb_to_recordset($1) AS e(id uuid,subject text,login text,name text,new boolean) WHERE NOT e.new AND u.id=e.id`, data); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, "UPDATE users SET status='disabled',auth_version=auth_version+1,linux_password_hash='' WHERE source=$1 AND status='active' AND id IN (SELECT user_id FROM identities WHERE provider=$1 AND NOT subject=ANY($2::text[]))", provider, seen)
	if err != nil {
		return err
	}
	if len(changes) == 0 && tag.RowsAffected() == 0 {
		return tx.Rollback(ctx)
	}
	if _, err = tx.Exec(ctx, "UPDATE ssh_keys SET status='revoked' WHERE status='active' AND user_id IN (SELECT id FROM users WHERE source=$1 AND status='disabled')", provider); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE api_tokens SET revoked_at=now() WHERE revoked_at IS NULL AND user_id IN (SELECT id FROM users WHERE source=$1 AND status='disabled')", provider); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE notification_channels SET enabled=false WHERE user_id IN (SELECT id FROM users WHERE source=$1 AND status='disabled')", provider); err != nil {
		return err
	}
	_, err = s.record(ctx, tx, authorization.Principal{UserID: "directory:" + provider}, change{Kind: "directory.update", Resource: provider, All: true}, rev)
	return err
}
