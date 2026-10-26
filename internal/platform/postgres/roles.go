package postgres

import (
	"Heimdall/internal/authorization"
	"Heimdall/internal/fleet"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) Roles(ctx context.Context) ([]authorization.Role, error) {
	rows, err := s.Pool.Query(ctx, "SELECT id,name,permissions,linux_access,sudo,sudoers,allow_password,allow_ssh_keys FROM roles ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []authorization.Role{}
	for rows.Next() {
		var r authorization.Role
		var permissions, sudo []byte
		if err = rows.Scan(&r.ID, &r.Name, &permissions, &r.LinuxAccess, &sudo, &r.Sudoers, &r.AllowPassword, &r.AllowSSHKeys); err != nil {
			return nil, err
		}
		json.Unmarshal(permissions, &r.Permissions)
		json.Unmarshal(sudo, &r.Sudo)
		r.Normalize()
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) SaveRole(ctx context.Context, p authorization.Principal, r authorization.Role) (string, error) {
	r.Normalize()
	if err := r.Validate(); err != nil {
		return "", err
	}
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	for _, permission := range r.Permissions {
		if !p.Allowed(permission, "*") {
			return "", ErrForbidden
		}
	}
	if (len(r.Sudo) > 0 || r.Sudoers != "") && !p.Allowed("sudo.manage", "*") {
		return "", ErrForbidden
	}
	return s.mutate(ctx, p, change{Kind: "role.update", Resource: r.ID, Permission: "roles.manage", Group: "*", All: true}, func(tx pgx.Tx) error {
		current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
		if err != nil {
			return err
		}
		for _, permission := range r.Permissions {
			if !current.Allowed(permission, "*") {
				return ErrForbidden
			}
		}
		if (len(r.Sudo) > 0 || r.Sudoers != "") && !current.Allowed("sudo.manage", "*") {
			return ErrForbidden
		}
		// Removing existing sudo is also a sudo change. Checking only the new
		// definition would allow roles.manage to bypass sudo.manage.
		var oldSudo bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM roles WHERE id=$1 AND ((sudo<>'[]' AND sudo<>'null') OR sudoers<>''))", r.ID).Scan(&oldSudo); err != nil {
			return err
		}
		if oldSudo && !current.Allowed("sudo.manage", "*") {
			return ErrForbidden
		}
		_, err = tx.Exec(ctx, "INSERT INTO roles(id,name,permissions,linux_access,sudo,sudoers,allow_password,allow_ssh_keys) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET name=excluded.name,permissions=excluded.permissions,linux_access=excluded.linux_access,sudo=excluded.sudo,sudoers=excluded.sudoers,allow_password=excluded.allow_password,allow_ssh_keys=excluded.allow_ssh_keys", r.ID, r.Name, jsonValue(r.Permissions), r.LinuxAccess, jsonValue(r.Sudo), r.Sudoers, r.AllowPassword, r.AllowSSHKeys)
		if err != nil {
			return err
		}
		return requireAdministrator(ctx, tx)
	})
}
func (s *Store) Bindings(ctx context.Context, p authorization.Principal, userID string) ([]authorization.Binding, error) {
	if !p.Self(userID) && !p.Allowed("users.read", "*") {
		return nil, ErrForbidden
	}
	q := authorization.Principal{Bindings: []authorization.Binding{}}
	var status string
	if err := s.Pool.QueryRow(ctx, "SELECT status FROM users WHERE id=$1", userID).Scan(&status); err != nil {
		return nil, failure(err)
	}
	rows, err := s.Pool.Query(ctx, "SELECT b.id,b.user_id,b.role_id,b.group_id,r.name,r.permissions,r.linux_access,r.sudo,r.sudoers,r.allow_password,r.allow_ssh_keys FROM role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id=$1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var b authorization.Binding
		var perms, sudo []byte
		if err = rows.Scan(&b.ID, &b.UserID, &b.RoleID, &b.GroupID, &b.Role.Name, &perms, &b.Role.LinuxAccess, &sudo, &b.Role.Sudoers, &b.Role.AllowPassword, &b.Role.AllowSSHKeys); err != nil {
			return nil, err
		}
		b.Role.ID = b.RoleID
		json.Unmarshal(perms, &b.Role.Permissions)
		json.Unmarshal(sudo, &b.Role.Sudo)
		b.Role.Normalize()
		q.Bindings = append(q.Bindings, b)
	}
	return q.Bindings, rows.Err()
}
func (s *Store) BindRole(ctx context.Context, p authorization.Principal, b authorization.Binding) (string, error) {
	b.ID = uuid.NewString()
	return s.mutate(ctx, p, change{Kind: "role.bind", Resource: b.ID, Permission: "roles.manage", Group: b.GroupID, UserID: b.UserID}, func(tx pgx.Tx) error {
		var permissions []byte
		var sudo []byte
		var nativeRules string
		if err := tx.QueryRow(ctx, "SELECT permissions,sudo,sudoers FROM roles WHERE id=$1", b.RoleID).Scan(&permissions, &sudo, &nativeRules); err != nil {
			return failure(err)
		}
		current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
		if err != nil {
			return err
		}
		var perms []string
		json.Unmarshal(permissions, &perms)
		for _, permission := range perms {
			if !current.Allowed(permission, b.GroupID) {
				return ErrForbidden
			}
		}
		var rules []authorization.SudoRule
		json.Unmarshal(sudo, &rules)
		if (len(rules) > 0 || nativeRules != "") && !current.Allowed("sudo.manage", b.GroupID) {
			return ErrForbidden
		}
		if b.GroupID != "*" {
			var exists bool
			if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM server_groups WHERE id::text=$1)", b.GroupID).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return errors.New("unknown server group")
			}
		}
		_, err = tx.Exec(ctx, "INSERT INTO role_bindings(id,user_id,role_id,group_id) VALUES($1,$2,$3,$4) ON CONFLICT(user_id,role_id,group_id) DO NOTHING", b.ID, b.UserID, b.RoleID, b.GroupID)
		return err
	})
}
func (s *Store) UnbindRole(ctx context.Context, p authorization.Principal, id string) (string, error) {
	var userID, groupID string
	if err := s.Pool.QueryRow(ctx, "SELECT user_id,group_id FROM role_bindings WHERE id=$1", id).Scan(&userID, &groupID); err != nil {
		return "", failure(err)
	}
	return s.mutate(ctx, p, change{Kind: "role.unbind", Resource: id, Permission: "roles.manage", Group: groupID, UserID: userID}, func(tx pgx.Tx) error {
		if err := s.authorizeRoleRevocation(ctx, tx, p, "role_bindings", id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, "DELETE FROM role_bindings WHERE id=$1", id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		return requireAdministrator(ctx, tx)
	})
}
func (s *Store) Groups(ctx context.Context, p authorization.Principal) ([]fleet.Group, error) {
	rows, err := s.Pool.Query(ctx, "SELECT g.id,g.name,coalesce(g.parent_id::text,''),coalesce(n.total,0),coalesce(n.active,0) FROM server_groups g LEFT JOIN (SELECT group_id,count(*) total,count(*) FILTER(WHERE NOT disabled) active FROM nodes GROUP BY group_id) n ON n.group_id=g.id ORDER BY g.name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []fleet.Group{}
	for rows.Next() {
		var g fleet.Group
		if err = rows.Scan(&g.ID, &g.Name, &g.ParentID, &g.Nodes, &g.ActiveNodes); err != nil {
			return nil, err
		}
		if p.Allowed("nodes.read", g.ID) || p.Allowed("nodes.manage", g.ID) || p.Allowed("roles.manage", g.ID) || p.Allowed("inventory.read", g.ID) || (p.TokenID == "" && linuxGroup(p, g.ID)) {
			out = append(out, g)
		}
	}
	return out, rows.Err()
}
func (s *Store) CreateGroup(ctx context.Context, p authorization.Principal, name string) (fleet.Group, error) {
	g := fleet.Group{ID: uuid.NewString(), Name: name}
	_, err := s.SaveGroup(ctx, p, g)
	return g, err
}

func linuxGroup(p authorization.Principal, group string) bool {
	if p.Restricted {
		return false
	}
	for _, binding := range p.Bindings {
		if binding.Role.LinuxAccess && (binding.GroupID == "*" || binding.GroupID == group) {
			return true
		}
	}
	return false
}

func (s *Store) DeleteRole(ctx context.Context, p authorization.Principal, id string) (string, error) {
	return s.mutate(ctx, p, change{Kind: "role.unbind", Resource: id, Permission: "roles.manage", Group: "*", All: true}, func(tx pgx.Tx) error {
		var hasSudo bool
		if err := tx.QueryRow(ctx, "SELECT (sudo<>'[]' AND sudo<>'null') OR sudoers<>'' FROM roles WHERE id=$1", id).Scan(&hasSudo); err != nil {
			return failure(err)
		}
		current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
		if err != nil {
			return err
		}
		if hasSudo && !current.Allowed("sudo.manage", "*") {
			return ErrForbidden
		}
		for _, table := range []string{"role_bindings", "user_group_role_bindings", "unix_group_role_bindings"} {
			if _, err = tx.Exec(ctx, "DELETE FROM "+table+" WHERE role_id=$1", id); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, "DELETE FROM roles WHERE id=$1", id); err != nil {
			return err
		}
		return requireAdministrator(ctx, tx)
	})
}
