package postgres

import (
	"Heimdall/internal/authorization"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
)

// All assignment sources use the same revocation checks. Table names are
// internal constants; caller-controlled SQL identifiers are never accepted.
func (s *Store) authorizeRoleRevocation(ctx context.Context, tx pgx.Tx, p authorization.Principal, table, id string) error {
	switch table {
	case "role_bindings", "user_group_role_bindings", "unix_group_role_bindings":
	default:
		return errors.New("unknown role assignment source")
	}
	var scope string
	var sudo bool
	err := tx.QueryRow(ctx, "SELECT b.group_id::text,(r.sudo<>'[]' AND r.sudo<>'null') OR r.sudoers<>'' FROM "+table+" b JOIN roles r ON r.id=b.role_id WHERE b.id=$1", id).Scan(&scope, &sudo)
	if err != nil {
		return failure(err)
	}
	current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
	if err != nil {
		return err
	}
	if !current.Allowed("roles.manage", scope) || (sudo && !current.Allowed("sudo.manage", scope)) {
		return ErrForbidden
	}
	return nil
}
