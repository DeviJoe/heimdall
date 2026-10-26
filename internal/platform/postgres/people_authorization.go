package postgres

import (
	"Heimdall/internal/authorization"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
)

// Changing membership in a group with roles is also a role assignment change.
// users.manage alone must not let an operator promote somebody to administrator.
func (s *Store) authorizePeopleMembership(ctx context.Context, tx pgx.Tx, p authorization.Principal, ids []string) error {
	current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT b.group_id,r.permissions,(r.sudo<>'[]'::jsonb OR r.sudoers<>'') FROM user_group_role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_group_id=ANY($1::uuid[])`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var group string
		var raw []byte
		var sudo bool
		if err = rows.Scan(&group, &raw, &sudo); err != nil {
			return err
		}
		if !current.Allowed("roles.manage", group) || (sudo && !current.Allowed("sudo.manage", group)) {
			return ErrForbidden
		}
		var permissions []string
		if err = json.Unmarshal(raw, &permissions); err != nil {
			return err
		}
		for _, permission := range permissions {
			if !current.Allowed(permission, group) {
				return ErrForbidden
			}
		}
	}
	return rows.Err()
}
