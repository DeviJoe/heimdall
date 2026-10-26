package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/identity"
	"Heimdall/internal/synchronization"
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) UnixGroups(ctx context.Context, p authorization.Principal) ([]application.UnixGroup, error) {
	if !p.Allowed("users.read", "*") {
		return nil, ErrForbidden
	}
	rows, err := s.Pool.Query(ctx, `SELECT g.id,g.name,g.gid,ARRAY(SELECT user_id::text FROM unix_group_members WHERE group_id=g.id ORDER BY user_id),ARRAY(SELECT id::text FROM users WHERE gid=g.gid AND status<>'deleted' ORDER BY id) FROM unix_groups g ORDER BY name LIMIT 10000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []application.UnixGroup{}
	for rows.Next() {
		var g application.UnixGroup
		if err = rows.Scan(&g.ID, &g.Name, &g.GID, &g.Members, &g.PrimaryMembers); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (s *Store) SaveUnixGroup(ctx context.Context, p authorization.Principal, g application.UnixGroup) (string, error) {
	if len(g.Members) > 20000 {
		return "", errors.New("UNIX group exceeds 20000 members")
	}
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	return s.mutate(ctx, p, change{Kind: "unix_group.update", Resource: g.ID, Permission: "users.manage", Group: "*", All: true}, func(tx pgx.Tx) error {
		var name string
		var gid int
		err := tx.QueryRow(ctx, "SELECT name,gid FROM unix_groups WHERE id=$1", g.ID).Scan(&name, &gid)
		if err == nil && (name != g.Name || gid != g.GID) {
			return errors.New("UNIX group name and GID are immutable; create a new group and migrate accounts in maintenance")
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if g.GID == 0 {
			if err = tx.QueryRow(ctx, "SELECT nextval('posix_ids')::int").Scan(&g.GID); err != nil {
				return err
			}
		}
		if err = identity.ValidateGroup(g.Name, g.GID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO unix_groups(id,name,gid) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING", g.ID, g.Name, g.GID); err != nil {
			return err
		}
		if g.Members == nil {
			return nil
		}
		if err := s.authorizeUnixMembership(ctx, tx, p, []string{g.ID}, nil); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "DELETE FROM unix_group_members WHERE group_id=$1", g.ID); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "INSERT INTO unix_group_members SELECT $1,id FROM unnest($2::uuid[]) id ON CONFLICT DO NOTHING", g.ID, g.Members)
		return err
	})
}
func (s *Store) UnixAssignments(ctx context.Context, p authorization.Principal) ([]application.UnixAssignment, error) {
	rows, err := s.Pool.Query(ctx, "SELECT id,unix_group_id,role_id,group_id FROM unix_group_role_bindings ORDER BY id LIMIT 10000")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []application.UnixAssignment{}
	for rows.Next() {
		var b application.UnixAssignment
		if err = rows.Scan(&b.ID, &b.UnixGroupID, &b.RoleID, &b.GroupID); err != nil {
			return nil, err
		}
		if p.Allowed("roles.read", b.GroupID) || p.Allowed("roles.manage", b.GroupID) {
			out = append(out, b)
		}
	}
	return out, rows.Err()
}
func (s *Store) AssignUnixGroup(ctx context.Context, p authorization.Principal, b application.UnixAssignment) (string, error) {
	if b.ID == "" {
		b.ID = uuid.NewString()
	}
	return s.mutate(ctx, p, change{Kind: "unix_group.bind", Resource: b.ID, Permission: "roles.manage", Group: b.GroupID, All: true}, func(tx pgx.Tx) error {
		current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
		if err != nil {
			return err
		}
		var native, hasSudo bool
		if err = tx.QueryRow(ctx, "SELECT linux_access,(sudo<>'[]' AND sudo<>'null') OR sudoers<>'' FROM roles WHERE id=$1", b.RoleID).Scan(&native, &hasSudo); err != nil {
			return failure(err)
		}
		if !native {
			return errors.New("UNIX assignment requires a role with node access")
		}
		if hasSudo && !current.Allowed("sudo.manage", b.GroupID) {
			return ErrForbidden
		}
		if !current.Allowed("users.manage", "*") {
			return ErrForbidden
		}
		_, err = tx.Exec(ctx, "INSERT INTO unix_group_role_bindings(id,unix_group_id,role_id,group_id) VALUES($1,$2,$3,$4) ON CONFLICT(unix_group_id,role_id,group_id) DO NOTHING", b.ID, b.UnixGroupID, b.RoleID, b.GroupID)
		return err
	})
}
func (s *Store) UnassignUnixGroup(ctx context.Context, p authorization.Principal, id string) (string, error) {
	var group string
	if err := s.Pool.QueryRow(ctx, "SELECT group_id FROM unix_group_role_bindings WHERE id=$1", id).Scan(&group); err != nil {
		return "", failure(err)
	}
	return s.mutate(ctx, p, change{Kind: "unix_group.unbind", Resource: id, Permission: "roles.manage", Group: group, All: true}, func(tx pgx.Tx) error {
		if err := s.authorizeRoleRevocation(ctx, tx, p, "unix_group_role_bindings", id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "DELETE FROM unix_group_role_bindings WHERE id=$1 AND group_id=$2", id, group)
		if err == nil && tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		return err
	})
}
func (s *Store) projectUnixGroups(ctx context.Context, tx pgx.Tx, state *synchronization.Snapshot, ids []string, indices map[string]int) error {
	// One indexed join for all accounts; no per-user query or user×group scan.
	rows, err := tx.Query(ctx, `SELECT g.id,g.name,g.gid,m.user_id FROM unix_groups g JOIN effective_unix_members m ON m.group_id=g.id WHERE m.user_id=ANY($1::uuid[]) ORDER BY g.name,m.user_id`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var g synchronization.UnixGroup
		var user string
		if err = rows.Scan(&g.ID, &g.Name, &g.GID, &user); err != nil {
			return err
		}
		a := &state.Accounts[indices[user]]
		if !a.Enabled && a.User.GID != g.GID {
			continue
		}
		if !seen[g.ID] {
			state.Groups = append(state.Groups, g)
			seen[g.ID] = true
		}
		if a.Enabled && a.User.GID != g.GID {
			a.Groups = append(a.Groups, g.Name)
		}
	}
	return rows.Err()
}
func (s *Store) RequireSK(ctx context.Context, id string) (bool, error) {
	var required bool
	err := s.Pool.QueryRow(ctx, "SELECT sk_required($1)", id).Scan(&required)
	return required, err
}
func revokeNonSK(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "UPDATE ssh_keys SET status='revoked' WHERE status='active' AND algorithm NOT LIKE 'sk-%' AND sk_required(user_id)")
	return err
}
