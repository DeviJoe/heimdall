package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
)

func (s *Store) UnixGroup(ctx context.Context, p authorization.Principal, id string) (application.UnixGroup, error) {
	var g application.UnixGroup
	if !p.Allowed("users.read", "*") {
		return g, ErrForbidden
	}
	err := s.Pool.QueryRow(ctx, `SELECT g.id,g.name,g.gid,ARRAY(SELECT user_id::text FROM unix_group_members WHERE group_id=g.id ORDER BY user_id),ARRAY(SELECT id::text FROM users WHERE gid=g.gid AND status<>'deleted' ORDER BY id) FROM unix_groups g WHERE id=$1`, id).Scan(&g.ID, &g.Name, &g.GID, &g.Members, &g.PrimaryMembers)
	return g, failureIf(err)
}
func (s *Store) UpdateUnixMembers(ctx context.Context, p authorization.Principal, id string, add, remove []string) (string, error) {
	if len(add)+len(remove) < 1 || len(add)+len(remove) > 500 {
		return "", errors.New("select 1–500 membership changes")
	}
	return s.mutate(ctx, p, change{Kind: "unix_group.update", Resource: id, Permission: "users.manage", Group: "*", All: true}, func(tx pgx.Tx) error {
		if err := s.authorizeUnixMembership(ctx, tx, p, []string{id}, nil); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM unix_group_members WHERE group_id=$1 AND user_id=ANY($2::uuid[])", id, remove); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO unix_group_members SELECT $1,id FROM unnest($2::uuid[]) id ON CONFLICT DO NOTHING", id, add)
		return err
	})
}
