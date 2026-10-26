package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"context"
)

func (s *Store) NativeAccessPolicy(ctx context.Context, p authorization.Principal, id string) (application.NativeAccessPolicy, error) {
	var out application.NativeAccessPolicy
	if p.TokenID != "" || (id != p.UserID && !p.Allowed("users.manage", "*")) {
		return out, ErrForbidden
	}
	err := s.Pool.QueryRow(ctx, `SELECT u.sync_to_nodes,
 u.sync_to_nodes AND coalesce(bool_or(r.linux_access AND r.allow_password),false),
 u.sync_to_nodes AND coalesce(bool_or(r.linux_access AND r.allow_ssh_keys),false)
 FROM users u LEFT JOIN native_role_bindings b ON b.user_id=u.id LEFT JOIN roles r ON r.id=b.role_id
 WHERE u.id=$1 GROUP BY u.id`, id).Scan(&out.SyncToNodes, &out.AllowPassword, &out.AllowSSHKeys)
	return out, failureIf(err)
}
