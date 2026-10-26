package postgres

import (
	"Heimdall/internal/authorization"
	"Heimdall/internal/synchronization"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"net"
	"time"
)

func (s *Store) RecordActivity(ctx context.Context, nodeID, serial string, events []synchronization.ActivityEvent) ([]string, error) {
	if len(events) > 100 {
		return nil, errors.New("security event batch too large")
	}
	ids := []string{}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var group string
	if err = tx.QueryRow(ctx, "SELECT group_id FROM nodes WHERE id=$1 AND cert_serial=$2 AND NOT disabled AND cert_expires>now() FOR SHARE", nodeID, serial).Scan(&group); err != nil {
		return nil, ErrForbidden
	}
	for _, event := range events {
		id, err := hex.DecodeString(event.ID)
		if err != nil || len(id) != 32 || len(event.Login) > 64 || net.ParseIP(event.Address) == nil || event.ObservedAt.Before(time.Now().Add(-30*24*time.Hour)) || event.ObservedAt.After(time.Now().Add(5*time.Minute)) {
			return nil, errors.New("invalid security event")
		}
		if event.Kind != "managed_login" && event.Kind != "unmanaged_login" && event.Kind != "failed_authentication" {
			return nil, errors.New("unknown activity kind")
		}
		if event.Severity != "info" && event.Severity != "warning" && event.Severity != "critical" {
			return nil, errors.New("invalid severity")
		}
		tag, err := tx.Exec(ctx, "INSERT INTO security_events(id,node_id,login,address,kind,severity,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING", event.ID, nodeID, event.Login, event.Address, event.Kind, event.Severity, event.ObservedAt)
		if err != nil {
			return nil, err
		}
		ids = append(ids, event.ID)
		if tag.RowsAffected() > 0 && event.Severity != "info" {
			incident := uuid.NewString()
			// Same node/login/address/kind in a five-minute window forms one
			// actionable incident. Individual events stay in security_events.
			sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%s:%d", nodeID, event.Kind, event.Login, event.Address, event.ObservedAt.Unix()/300)))
			var changed bool
			err = tx.QueryRow(ctx, `INSERT INTO incidents(id,dedup_key,kind,severity,node_id,group_id,message,last_seen)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(dedup_key) DO UPDATE SET occurrences=CASE WHEN incidents.status='resolved' THEN 1 ELSE incidents.occurrences+1 END,last_seen=greatest(incidents.last_seen,excluded.last_seen),updated_at=now(),status=CASE WHEN incidents.status='resolved' THEN 'open' ELSE incidents.status END
             RETURNING id,occurrences=1`, incident, fmt.Sprintf("activity:%x", sum), event.Kind, event.Severity, nodeID, group, fmt.Sprintf("%s: user %s from %s", event.Kind, event.Login, event.Address), event.ObservedAt).Scan(&incident, &changed)
			if err != nil {
				return nil, err
			}
			if changed {
				if err = s.scheduleNotifications(ctx, tx, incident, "activity:"+event.ID); err != nil {
					return nil, err
				}
			}

		}
	}
	return ids, tx.Commit(ctx)
}
func (s *Store) SecurityEvents(ctx context.Context, p authorization.Principal) ([]synchronization.ActivityEvent, error) {
	groups, err := s.allowedGroups(ctx, p, "security.read")
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, "SELECT e.id,e.node_id,e.login,e.address,e.kind,e.severity,e.observed_at FROM security_events e JOIN nodes n ON n.id=e.node_id WHERE ($1 OR n.group_id=ANY($2::uuid[])) ORDER BY e.received_at DESC LIMIT 200", groups == nil, groups)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []synchronization.ActivityEvent{}
	for rows.Next() {
		var event synchronization.ActivityEvent
		if err = rows.Scan(&event.ID, &event.NodeID, &event.Login, &event.Address, &event.Kind, &event.Severity, &event.ObservedAt); err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

// ResolveActivityIncident closes an investigated security event. Synchronization
// incidents only resolve through detector evidence, never by this endpoint.
func (s *Store) ResolveActivityIncident(ctx context.Context, p authorization.Principal, id string) error {
	return s.ResolveIncidents(ctx, p, []string{id})
}
func (s *Store) ResolveIncidents(ctx context.Context, p authorization.Principal, ids []string) error {
	if len(ids) < 1 || len(ids) > 500 {
		return errors.New("select 1–500 incidents")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if _, err := uuid.Parse(id); err != nil || seen[id] {
			return errors.New("invalid or duplicate incident")
		}
		seen[id] = true
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, "SELECT id,coalesce(group_id::text,'*'),kind FROM incidents WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE", ids)
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var id, group, kind string
		if err = rows.Scan(&id, &group, &kind); err != nil {
			rows.Close()
			return err
		}
		if !current.Allowed("incidents.manage", group) {
			rows.Close()
			return ErrForbidden
		}
		if kind != "unmanaged_login" && kind != "failed_authentication" {
			rows.Close()
			return errors.New("Synchronization incidents close only after confirmed recovery; acknowledge them instead")
		}
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if count != len(ids) {
		return ErrNotFound
	}
	if _, err = tx.Exec(ctx, "UPDATE incidents SET status='resolved',updated_at=now() WHERE id=ANY($1::uuid[])", ids); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_events(actor_id,token_id,channel,action,resource_id) SELECT $1,$2,$3,'incident.resolve',id::text FROM unnest($4::uuid[]) id", p.UserID, p.TokenID, channel(p), ids); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
