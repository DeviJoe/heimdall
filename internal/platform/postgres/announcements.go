package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"time"
)

func (s *Store) Announcements(ctx context.Context, p authorization.Principal, all bool) ([]application.Announcement, error) {
	if p.Restricted || !p.Self(p.UserID) {
		return nil, ErrForbidden
	}
	if all && !p.Allowed("announcements.manage", "*") {
		return nil, ErrForbidden
	}
	rows, err := s.Pool.Query(ctx, "SELECT id,title,markdown,severity,enabled,starts_at,ends_at,version FROM announcements WHERE $1 OR (enabled AND starts_at<=now() AND (ends_at IS NULL OR ends_at>now())) ORDER BY updated_at DESC LIMIT 100", all)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []application.Announcement{}
	for rows.Next() {
		var a application.Announcement
		if err = rows.Scan(&a.ID, &a.Title, &a.Markdown, &a.Severity, &a.Enabled, &a.StartsAt, &a.EndsAt, &a.Version); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) SaveAnnouncement(ctx context.Context, p authorization.Principal, a application.Announcement) (string, error) {
	if len(strings.TrimSpace(a.Title)) < 1 || len(a.Title) > 200 || len(strings.TrimSpace(a.Markdown)) < 1 || len(a.Markdown) > 32768 || strings.ContainsRune(a.Markdown, 0) {
		return "", errors.New("announcement requires a title and 1–32768 bytes of Markdown")
	}
	if a.Severity != "info" && a.Severity != "warning" && a.Severity != "error" && a.Severity != "success" {
		return "", errors.New("invalid announcement severity")
	}
	if a.StartsAt.IsZero() {
		a.StartsAt = time.Now().UTC()
	}
	if a.EndsAt != nil && !a.EndsAt.After(a.StartsAt) {
		return "", errors.New("announcement end must be after its start")
	}
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	return s.mutate(ctx, p, change{Kind: "announcement.update", Resource: a.ID, Permission: "announcements.manage", Group: "*", TransportOnly: true}, func(tx pgx.Tx) error {
		var affected int64
		var err error
		if a.Version == 0 {
			tag, e := tx.Exec(ctx, `INSERT INTO announcements(id,title,markdown,severity,enabled,starts_at,ends_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO NOTHING`, a.ID, a.Title, a.Markdown, a.Severity, a.Enabled, a.StartsAt, a.EndsAt, p.UserID)
			err = e
			affected = tag.RowsAffected()
		} else {
			tag, e := tx.Exec(ctx, `UPDATE announcements SET title=$2,markdown=$3,severity=$4,enabled=$5,starts_at=$6,ends_at=$7,version=version+1,updated_at=now() WHERE id=$1 AND version=$8`, a.ID, a.Title, a.Markdown, a.Severity, a.Enabled, a.StartsAt, a.EndsAt, a.Version)
			err = e
			affected = tag.RowsAffected()
		}

		if err == nil && affected != 1 {
			return errors.New("announcement changed; reload before saving")
		}
		return err
	})
}
func (s *Store) DeleteAnnouncement(ctx context.Context, p authorization.Principal, id string, version int64) (string, error) {
	if version < 1 {
		return "", errors.New("Укажите версию сообщения")
	}
	return s.mutate(ctx, p, change{Kind: "announcement.delete", Resource: id, Permission: "announcements.manage", Group: "*", TransportOnly: true}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "DELETE FROM announcements WHERE id=$1 AND version=$2", id, version)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var exists bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM announcements WHERE id=$1)", id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return application.ErrNotFound
		}
		return application.ErrConflict
	})
}

func (s *Store) keyExpiryNotices(ctx context.Context, tx pgx.Tx) error {
	settings, err := s.Settings(ctx)
	if err != nil {
		return err
	}
	window := settings.KeyWarnSeconds
	if _, err = tx.Exec(ctx, `UPDATE incidents i SET status='resolved',updated_at=now() WHERE kind='key_expiring' AND status<>'resolved' AND NOT EXISTS(SELECT 1 FROM ssh_keys k JOIN users u ON u.id=k.user_id WHERE 'key_expiring:'||k.id::text=i.dedup_key AND k.status='active' AND u.status='active' AND k.expires_at>now() AND k.expires_at<=now()+make_interval(secs=>$1))`, window); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `INSERT INTO incidents(id,dedup_key,kind,severity,user_id,message)
 SELECT gen_random_uuid(),'key_expiring:'||k.id::text,'key_expiring','warning',k.user_id,'SSH-ключ «'||k.name||'» ('||k.fingerprint||') истекает '||to_char(k.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI')||' UTC. Выпустите новый ключ и отзовите прежний.' FROM ssh_keys k JOIN users u ON u.id=k.user_id
 WHERE k.status='active' AND u.status='active' AND k.expires_at>now() AND k.expires_at<=now()+make_interval(secs=>$1) AND NOT EXISTS(SELECT 1 FROM incidents i WHERE i.dedup_key='key_expiring:'||k.id::text AND i.status<>'resolved') ORDER BY k.expires_at LIMIT 1000
 ON CONFLICT(dedup_key) DO UPDATE SET status='open',message=excluded.message,updated_at=now() WHERE incidents.status='resolved' RETURNING id`, window)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		_, err = tx.Exec(ctx, `INSERT INTO notification_jobs(id,incident_id,channel_id,provider,event) SELECT gen_random_uuid(),i.id,c.id,c.provider,'key_expiring:'||i.updated_at::text FROM incidents i JOIN notification_channels c ON c.enabled AND c.user_id=i.user_id JOIN users u ON u.id=c.user_id WHERE i.id=ANY($1::uuid[]) AND u.status='active' AND mfa_satisfied(u.id) ON CONFLICT DO NOTHING`, ids)
	}
	return err
}
