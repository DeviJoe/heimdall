package postgres

import (
	"Heimdall/internal/authorization"
	"context"
	"github.com/jackc/pgx/v5"
)

// Membership is a native role grant, including primary GID. A directory
// operator must not bypass roles.manage/sudo.manage by changing memberships.
func (s *Store) authorizeUnixMembership(ctx context.Context, tx pgx.Tx, p authorization.Principal, ids []string, gids []int) error {
	current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT b.group_id,(r.sudo<>'[]'::jsonb AND r.sudo<>'null'::jsonb) OR r.sudoers<>''
 FROM unix_group_role_bindings b JOIN unix_groups g ON g.id=b.unix_group_id JOIN roles r ON r.id=b.role_id
 WHERE g.id=ANY($1::uuid[]) OR g.gid=ANY($2::int[])`, ids, gids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var group string
		var sudo bool
		if err = rows.Scan(&group, &sudo); err != nil {
			return err
		}
		if !current.Allowed("roles.manage", group) || (sudo && !current.Allowed("sudo.manage", group)) {
			return ErrForbidden
		}
	}
	return rows.Err()
}
