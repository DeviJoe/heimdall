package postgres

import (
	"Heimdall/internal/authorization"
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
)

func (s *Store) UserGroupBindings(ctx context.Context, p authorization.Principal, id string) ([]authorization.Binding, error) {
	if !p.Allowed("users.read", "*") {
		return nil, ErrForbidden
	}
	rows, err := s.Pool.Query(ctx, "SELECT b.id,b.role_id,b.group_id,r.name,r.permissions,r.linux_access,r.sudo,r.sudoers,r.allow_password,r.allow_ssh_keys FROM user_group_role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_group_id=$1 ORDER BY r.name,b.group_id LIMIT 1000", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []authorization.Binding{}
	for rows.Next() {
		var b authorization.Binding
		var permissions, rules []byte
		if err = rows.Scan(&b.ID, &b.RoleID, &b.GroupID, &b.Role.Name, &permissions, &b.Role.LinuxAccess, &rules, &b.Role.Sudoers, &b.Role.AllowPassword, &b.Role.AllowSSHKeys); err != nil {
			return nil, err
		}
		b.Role.ID = b.RoleID
		if err = json.Unmarshal(permissions, &b.Role.Permissions); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(rules, &b.Role.Sudo); err != nil {
			return nil, err
		}
		b.Role.Normalize()
		if p.Allowed("roles.read", b.GroupID) || p.Allowed("roles.manage", b.GroupID) {
			out = append(out, b)
		}
	}
	return out, rows.Err()
}
func (s *Store) UnbindUserGroupRole(ctx context.Context, p authorization.Principal, id, bindingID string) (string, error) {
	var scope string
	if err := s.Pool.QueryRow(ctx, "SELECT group_id FROM user_group_role_bindings WHERE id=$1 AND user_group_id=$2", bindingID, id).Scan(&scope); err != nil {
		return "", failure(err)
	}
	return s.mutate(ctx, p, change{Kind: "user_group.unbind", Resource: bindingID, Permission: "roles.manage", Group: scope, All: true}, func(tx pgx.Tx) error {
		if err := s.authorizeRoleRevocation(ctx, tx, p, "user_group_role_bindings", bindingID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "DELETE FROM user_group_role_bindings WHERE id=$1 AND user_group_id=$2", bindingID, id)
		if err == nil && tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return requireAdministrator(ctx, tx)
	})
}
