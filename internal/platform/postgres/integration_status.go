package postgres

import (
	"Heimdall/internal/authorization"
	"Heimdall/internal/platform/security"
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) IntegrationStarted(ctx context.Context, provider string) error {
	_, err := s.Pool.Exec(ctx, "INSERT INTO integration_status(provider,phase,last_attempt) VALUES($1,'running',now()) ON CONFLICT(provider) DO UPDATE SET phase='running',last_attempt=now()", provider)
	return err
}

func (s *Store) IntegrationResult(ctx context.Context, provider string, result error) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	detail := ""
	phase := "healthy"
	if result != nil {
		detail = result.Error()
		phase = "failed"
	}
	_, err = tx.Exec(ctx, "INSERT INTO integration_status(provider,phase,error,last_attempt,last_success) VALUES($1,$2,$3,now(),CASE WHEN $2='healthy' THEN now() END) ON CONFLICT(provider) DO UPDATE SET phase=excluded.phase,error=excluded.error,last_attempt=now(),last_success=coalesce(excluded.last_success,integration_status.last_success)", provider, phase, detail)
	if err != nil {
		return err
	}
	var id, status string
	err = tx.QueryRow(ctx, "SELECT id,status FROM incidents WHERE dedup_key=$1 FOR UPDATE", "directory:"+provider).Scan(&id, &status)
	changed := false
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
		if result != nil {
			id = uuid.NewString()
			_, err = tx.Exec(ctx, "INSERT INTO incidents(id,dedup_key,kind,severity,message) VALUES($1,$2,'directory_sync_failed','critical',$3)", id, "directory:"+provider, "Directory synchronization failed: "+provider+": "+detail)
			changed = true
		}
	} else if err == nil {
		next := "open"
		if result == nil {
			next = "resolved"
		}
		if status != next {
			_, err = tx.Exec(ctx, "UPDATE incidents SET status=$2,updated_at=now(),message=$3 WHERE id=$1", id, next, "Directory synchronization: "+provider+": "+phase)
			changed = true
		}
	}
	if err != nil {
		return err
	}
	if changed {
		if err = s.scheduleNotifications(ctx, tx, id, "directory:"+security.Random(8)); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func (s *Store) IntegrationStatuses(ctx context.Context, p authorization.Principal) ([]map[string]any, error) {
	if !p.Allowed("integrations.manage", "*") {
		return nil, ErrForbidden
	}
	rows, err := s.Pool.Query(ctx, "SELECT provider,phase,error,last_attempt::text,coalesce(last_success::text,'') FROM integration_status ORDER BY provider")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var provider, phase, detail, attempt, success string
		if err = rows.Scan(&provider, &phase, &detail, &attempt, &success); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"provider": provider, "phase": phase, "error": detail, "last_attempt": attempt, "last_success": success})
	}
	return out, rows.Err()
}
