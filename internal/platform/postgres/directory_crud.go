package postgres

import (
	"Heimdall/internal/authorization"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
)

func requireAdministrator(ctx context.Context, tx pgx.Tx) error {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users u JOIN effective_role_bindings b ON b.user_id=u.id JOIN roles r ON r.id=b.role_id WHERE u.status='active' AND u.kind='human' AND u.source<>'acceptance-fixture' AND b.group_id='*' AND r.permissions @> '["*"]')`).Scan(&exists)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("Должен остаться хотя бы один активный администратор Heimdall с глобальными правами")
	}
	return nil
}

func (s *Store) DeleteGroup(ctx context.Context, p authorization.Principal, id string) (string, error) {
	// Deleting a tree node changes inherited authorization, so it requires global administration.
	return s.mutate(ctx, p, change{Kind: "group.delete", Resource: id, Permission: "nodes.manage", Group: "*", All: true}, func(tx pgx.Tx) error {
		var present, occupied bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM server_groups WHERE id=$1),EXISTS(SELECT 1 FROM nodes WHERE group_id=$1) OR EXISTS(SELECT 1 FROM server_groups WHERE parent_id=$1)", id).Scan(&present, &occupied); err != nil {
			return err
		}
		if !present {
			return ErrNotFound
		}
		if occupied {
			return errors.New("Группа содержит ноды или дочерние группы. Сначала переместите их.")
		}
		for _, q := range []string{"DELETE FROM role_bindings WHERE group_id=$1", "DELETE FROM user_group_role_bindings WHERE group_id=$1", "DELETE FROM unix_group_role_bindings WHERE group_id=$1::uuid", "DELETE FROM join_tokens WHERE group_id=$1::uuid", "UPDATE incidents SET group_id=NULL,status='resolved',updated_at=now() WHERE group_id=$1::uuid", "DELETE FROM group_security WHERE group_id=$1::uuid", "DELETE FROM server_group_closure WHERE ancestor_id=$1::uuid OR descendant_id=$1::uuid", "DELETE FROM server_groups WHERE id=$1::uuid"} {
			if _, err := tx.Exec(ctx, q, id); err != nil {
				return err
			}
		}
		return requireAdministrator(ctx, tx)
	})
}
func (s *Store) DeleteUserGroup(ctx context.Context, p authorization.Principal, id string) (string, error) {
	return s.mutate(ctx, p, change{Kind: "user_group.delete", Resource: id, Permission: "users.manage", Group: "*", All: true}, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM user_groups WHERE id=$1)", id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		var roles bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM user_group_role_bindings WHERE user_group_id=$1)", id).Scan(&roles); err != nil {
			return err
		}
		current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
		if err != nil {
			return err
		}
		if roles && !current.Allowed("roles.manage", "*") {
			return ErrForbidden
		}
		if roles {
			if err := s.authorizePeopleMembership(ctx, tx, p, []string{id}); err != nil {
				return err
			}
		}
		for _, q := range []string{"UPDATE users SET auth_version=auth_version+1 WHERE id IN(SELECT user_id FROM user_group_members WHERE group_id=$1)", "DELETE FROM user_group_role_bindings WHERE user_group_id=$1", "DELETE FROM user_group_members WHERE group_id=$1", "DELETE FROM user_groups WHERE id=$1"} {
			if _, err := tx.Exec(ctx, q, id); err != nil {
				return err
			}
		}
		return requireAdministrator(ctx, tx)
	})
}
func (s *Store) DeleteUnixGroup(ctx context.Context, p authorization.Principal, id string) (string, error) {
	return s.mutate(ctx, p, change{Kind: "unix_group.delete", Resource: id, Permission: "users.manage", Group: "*", All: true}, func(tx pgx.Tx) error {
		var primary, assigned bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users u JOIN unix_groups g ON g.gid=u.gid WHERE g.id=$1 AND u.status<>'deleted'), EXISTS(SELECT 1 FROM unix_group_role_bindings WHERE unix_group_id=$1)", id).Scan(&primary, &assigned); err != nil {
			return err
		}
		if primary {
			return errors.New("Группа используется как primary GID. Сначала измените профили пользователей через обслуживание.")
		}
		if assigned {
			return errors.New("Сначала снимите назначения группы на ноды.")
		}
		if _, err := tx.Exec(ctx, "DELETE FROM unix_group_members WHERE group_id=$1", id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "DELETE FROM unix_groups WHERE id=$1", id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		return nil
	})
}
