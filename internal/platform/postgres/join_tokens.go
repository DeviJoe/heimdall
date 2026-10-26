package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

func (s *Store) JoinTokens(ctx context.Context, p authorization.Principal) ([]application.JoinToken, error) {
	groups, err := s.allowedGroups(ctx, p, "nodes.manage")
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, "SELECT id,group_id,uses,max_uses,expires_at,revoked_at,name FROM join_tokens WHERE expires_at>now() AND revoked_at IS NULL AND (max_uses=0 OR uses<max_uses) AND ($1 OR group_id=ANY($2::uuid[])) ORDER BY expires_at DESC LIMIT 1000", groups == nil, groups)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []application.JoinToken{}
	for rows.Next() {
		var t application.JoinToken
		if err = rows.Scan(&t.ID, &t.GroupID, &t.Uses, &t.MaxUses, &t.ExpiresAt, &t.RevokedAt, &t.Name); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
func (s *Store) RevokeJoinToken(ctx context.Context, p authorization.Principal, id string) error {
	var group string
	if err := s.Pool.QueryRow(ctx, "SELECT group_id FROM join_tokens WHERE id=$1", id).Scan(&group); err != nil {
		return failure(err)
	}
	_, err := s.mutate(ctx, p, change{Kind: "join_token.revoke", Resource: id, Permission: "nodes.manage", Group: group, TransportOnly: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE join_tokens SET revoked_at=coalesce(revoked_at,now()) WHERE id=$1 AND group_id=$2", id, group)
		return err
	})
	return err
}

func (s *Store) UpdateJoinToken(ctx context.Context, p authorization.Principal, id string, maxUses int, expires time.Time) error {
	if maxUses < 0 || maxUses > 1000000000 || time.Until(expires) < time.Minute || time.Until(expires) > 3650*24*time.Hour {
		return errors.New("invalid join token limits")
	}
	var group string
	if err := s.Pool.QueryRow(ctx, "SELECT group_id FROM join_tokens WHERE id=$1", id).Scan(&group); err != nil {
		return failure(err)
	}
	_, err := s.mutate(ctx, p, change{Kind: "join_token.update", Resource: id, Permission: "nodes.manage", Group: group, TransportOnly: true}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE join_tokens SET max_uses=$2,expires_at=$3 WHERE id=$1 AND revoked_at IS NULL AND expires_at>now()", id, maxUses, expires)
		if err == nil && tag.RowsAffected() != 1 {
			return errors.New("expired, revoked or unknown join token")
		}
		return err
	})
	return err
}
