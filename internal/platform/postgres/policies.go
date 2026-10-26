package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/fleet"
	"Heimdall/internal/synchronization"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net"
	"regexp"
	"strings"
)

func (s *Store) InitSettings(ctx context.Context, v application.Settings) error {
	if v.NodeCertificateTTLSeconds == 0 {
		v.NodeCertificateTTLSeconds = synchronization.DefaultNodeCertificateTTLSeconds
	}
	if v.ApplyTimeoutSeconds == 0 {
		v.ApplyTimeoutSeconds = 900
	}
	if err := v.Validate(); err != nil {
		return err
	}
	_, err := s.Pool.Exec(ctx, "INSERT INTO runtime_settings(id,value) VALUES(true,$1) ON CONFLICT DO NOTHING", jsonValue(v))
	return err
}
func (s *Store) Settings(ctx context.Context) (application.Settings, error) {
	var v application.Settings
	var raw []byte
	var version int64
	var certificateVersion int64
	var total, pending int
	err := s.Pool.QueryRow(ctx, `SELECT version,value,certificate_policy_version,
 (SELECT count(*) FROM nodes WHERE NOT disabled),
 (SELECT count(*) FROM nodes WHERE NOT disabled AND nodes.certificate_policy_version<runtime_settings.certificate_policy_version)
 FROM runtime_settings WHERE id=true`).Scan(&version, &raw, &certificateVersion, &total, &pending)
	if err != nil {
		return v, err
	}
	err = json.Unmarshal(raw, &v)
	v.Version = version
	v.CertificatePolicyVersion = certificateVersion
	v.CertificatesTotal, v.CertificatesPending = total, pending
	if v.NodeCertificateTTLSeconds == 0 {
		v.NodeCertificateTTLSeconds = synchronization.DefaultNodeCertificateTTLSeconds
	}
	if v.ApplyTimeoutSeconds == 0 {
		v.ApplyTimeoutSeconds = 900
	}
	if _, ok := mapField(raw, "key_warn_seconds"); !ok {
		v.KeyWarnSeconds = 7 * 86400
	}
	return v, err
}
func (s *Store) SaveSettings(ctx context.Context, p authorization.Principal, v application.Settings) (string, error) {
	if v.NodeCertificateTTLSeconds == 0 {
		current, err := s.Settings(ctx)
		if err != nil {
			return "", err
		}
		v.NodeCertificateTTLSeconds = current.NodeCertificateTTLSeconds
	}
	if v.ApplyTimeoutSeconds == 0 {
		current, err := s.Settings(ctx)
		if err != nil {
			return "", err
		}
		v.ApplyTimeoutSeconds = current.ApplyTimeoutSeconds
	}
	if err := v.Validate(); err != nil {
		return "", err
	}
	return s.mutate(ctx, p, change{Kind: "settings.update", Resource: "runtime", Permission: "settings.manage", Group: "*", All: true}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE runtime_settings SET version=version+1,value=$2,updated_at=now(),
 certificate_policy_version=certificate_policy_version+CASE WHEN coalesce((value->>'node_certificate_ttl_seconds')::int,315360000)<>$3 THEN 1 ELSE 0 END
 WHERE id=true AND version=$1`, v.Version, jsonValue(v), v.NodeCertificateTTLSeconds)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return application.ErrConflict
		}
		_, err = tx.Exec(ctx, "UPDATE ssh_keys SET expires_at=least(expires_at,created_at+make_interval(secs=>$1)) WHERE status='active'", v.KeyTTLSeconds)
		if err != nil {
			return err
		}
		return revokeNonSK(ctx, tx)
	})
}
func (s *Store) SaveGroup(ctx context.Context, p authorization.Principal, g fleet.Group) (string, error) {
	g.Name = strings.TrimSpace(g.Name)
	if len(g.Name) < 1 || len(g.Name) > 100 {
		return "", errors.New("invalid group name")
	}
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	return s.mutate(ctx, p, change{Kind: "group.update", Resource: g.ID, Permission: "nodes.manage", Group: "*", All: true}, func(tx pgx.Tx) error {
		if g.ParentID != "" {
			var cycle bool
			err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM server_group_closure WHERE ancestor_id=$1 AND descendant_id=$2)", g.ID, g.ParentID).Scan(&cycle)
			if err != nil {
				return err
			}
			if cycle || g.ID == g.ParentID {
				return errors.New("group hierarchy cannot contain a cycle")
			}
		}
		_, err := tx.Exec(ctx, "INSERT INTO server_groups(id,name,parent_id) VALUES($1,$2,NULLIF($3,'')::uuid) ON CONFLICT(id) DO UPDATE SET name=excluded.name,parent_id=excluded.parent_id", g.ID, g.Name, g.ParentID)
		if err != nil {
			return err
		}
		// A tree edit is rare; rebuild its closure once, never on the authorization path.
		if _, err = tx.Exec(ctx, "DELETE FROM server_group_closure"); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `WITH RECURSIVE paths(ancestor_id,descendant_id,depth) AS (SELECT id,id,0 FROM server_groups UNION ALL SELECT p.ancestor_id,g.id,p.depth+1 FROM paths p JOIN server_groups g ON g.parent_id=p.descendant_id WHERE p.depth<=32) INSERT INTO server_group_closure SELECT * FROM paths`)
		if err != nil {
			return err
		}
		var tooMany bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT c.descendant_id FROM server_group_closure c JOIN group_security s ON s.group_id=c.ancestor_id CROSS JOIN LATERAL unnest(s.categories) tag GROUP BY c.descendant_id HAVING count(DISTINCT tag)>64)`).Scan(&tooMany); err != nil {
			return err
		}
		if tooMany {
			return errors.New("inherited node categories exceed 64")
		}
		return nil
	})
}
func (s *Store) MoveNodes(ctx context.Context, p authorization.Principal, ids []string, group string) (string, error) {
	if len(ids) < 1 || len(ids) > 500 {
		return "", errors.New("select 1–500 nodes")
	}
	return s.mutate(ctx, p, change{Kind: "nodes.move", Resource: group, Permission: "nodes.manage", Group: group, All: true}, func(tx pgx.Tx) error {
		current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
		if err != nil {
			return err
		}
		rows, err := tx.Query(ctx, "SELECT group_id FROM nodes WHERE id=ANY($1::uuid[]) FOR UPDATE", ids)
		if err != nil {
			return err
		}
		count := 0
		for rows.Next() {
			var old string
			if err = rows.Scan(&old); err != nil {
				rows.Close()
				return err
			}
			if !current.Allowed("nodes.manage", old) {
				rows.Close()
				return ErrForbidden
			}
			count++
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if count != len(ids) {
			return errors.New("duplicate or missing nodes")
		}
		_, err = tx.Exec(ctx, "UPDATE nodes SET group_id=$2 WHERE id=ANY($1::uuid[])", ids, group)
		return err
	})
}

var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)

func validSSHHost(host string) bool { return hostPattern.MatchString(host) || net.ParseIP(host) != nil }
func (s *Store) SetNodeSSH(ctx context.Context, p authorization.Principal, id, host string, port int) error {
	if !validSSHHost(host) || port < 1 || port > 65535 {
		return errors.New("invalid SSH hostname/address or port")
	}
	var group string
	if err := s.Pool.QueryRow(ctx, "SELECT group_id FROM nodes WHERE id=$1", id).Scan(&group); err != nil {
		return failure(err)
	}
	_, err := s.mutate(ctx, p, change{Kind: "node.ssh", Resource: id, Permission: "nodes.manage", Group: group, NodeID: id}, func(tx pgx.Tx) error {
		var actual string
		if err := tx.QueryRow(ctx, "SELECT group_id FROM nodes WHERE id=$1", id).Scan(&actual); err != nil {
			return failure(err)
		}
		current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
		if err != nil {
			return err
		}
		if !current.Allowed("nodes.manage", actual) {
			return ErrForbidden
		}

		tag, err := tx.Exec(ctx, "UPDATE nodes SET ssh_host=$2,ssh_port=$3 WHERE id=$1", id, host, port)
		if err == nil && tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		return err
	})
	return err
}
func (s *Store) Inventory(ctx context.Context, p authorization.Principal) ([]application.InventoryHost, error) {
	if p.TokenID == "" || p.Restricted {
		return nil, ErrForbidden
	}
	groups, err := s.allowedGroups(ctx, p, "inventory.read")
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT n.id,n.name,n.group_id,g.name,coalesce(g.parent_id::text,''),coalesce(nullif(n.ssh_host,''),n.name),n.ssh_port,u.login
 FROM nodes n JOIN server_groups g ON g.id=n.group_id CROSS JOIN users u
 WHERE u.id=$1 AND u.sync_to_nodes AND u.status='active' AND u.shell<>'/usr/sbin/nologin' AND mfa_satisfied(u.id) AND NOT n.disabled AND mandatory_allowed(u.id,n.group_id)
 AND ($2 OR n.group_id=ANY($3::uuid[])) AND EXISTS(SELECT 1 FROM native_role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id=u.id AND r.linux_access AND (r.allow_password OR r.allow_ssh_keys) AND (b.group_id='*' OR b.group_id=n.group_id::text)) ORDER BY n.id LIMIT 20001`, p.UserID, groups == nil, groups)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []application.InventoryHost{}
	for rows.Next() {
		var h application.InventoryHost
		if err = rows.Scan(&h.ID, &h.Name, &h.GroupID, &h.GroupName, &h.ParentID, &h.Host, &h.Port, &h.Login); err != nil {
			return nil, err
		}
		if !validSSHHost(h.Host) {
			return nil, errors.New("configure a valid SSH address for node " + h.ID)
		}
		out = append(out, h)
	}
	if len(out) > 20000 {
		return nil, errors.New("inventory exceeds 20000 hosts")
	}
	return out, rows.Err()
}
func validMFAPolicy(policy string) bool {
	return policy == "none" || policy == "any" || policy == "totp" || policy == "passkey" || policy == "both"
}
func (s *Store) SetMFAPolicy(ctx context.Context, p authorization.Principal, id, policy string) (string, error) {
	if !validMFAPolicy(policy) {
		return "", errors.New("invalid enrollment policy")
	}
	return s.mutate(ctx, p, change{Kind: "user.policy", Resource: id, Permission: "users.manage", Group: "*", UserID: id}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE users SET mfa_policy=$2,require_mfa=$2<>'none',auth_version=auth_version+1 WHERE id=$1 AND kind='human'", id, policy)
		if err == nil && tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		return err
	})
}
func (s *Store) UserGroups(ctx context.Context, p authorization.Principal) ([]application.UserGroup, error) {
	if !p.Allowed("users.read", "*") {
		return nil, ErrForbidden
	}
	rows, err := s.Pool.Query(ctx, `SELECT g.id,g.name,g.mfa_policy,g.require_sk,g.purpose,coalesce(array_agg(m.user_id::text) FILTER(WHERE m.user_id IS NOT NULL),'{}'),count(*) FILTER(WHERE u.status<>'deleted' AND u.totp_secret<>''),count(*) FILTER(WHERE u.status<>'deleted' AND EXISTS(SELECT 1 FROM webauthn_credentials w WHERE w.user_id=u.id)),count(*) FILTER(WHERE u.status='active' AND NOT mfa_satisfied(u.id)) FROM user_groups g LEFT JOIN user_group_members m ON m.group_id=g.id LEFT JOIN users u ON u.id=m.user_id GROUP BY g.id ORDER BY g.name LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []application.UserGroup{}
	for rows.Next() {
		var g application.UserGroup
		if err = rows.Scan(&g.ID, &g.Name, &g.MFAPolicy, &g.RequireSK, &g.Purpose, &g.Members, &g.TOTPCount, &g.PasskeyCount, &g.MissingFactors); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
func (s *Store) SaveUserGroup(ctx context.Context, p authorization.Principal, g application.UserGroup) (string, error) {
	if g.Purpose == "" {
		g.Purpose = "general"
	}
	if g.Purpose != "general" && g.Purpose != "factor_policy" {
		return "", errors.New("invalid group purpose")
	}
	if !validMFAPolicy(g.MFAPolicy) || len(strings.TrimSpace(g.Name)) < 1 || len(g.Name) > 100 || len(g.Members) > 20000 {
		return "", errors.New("invalid user group")
	}
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	return s.mutate(ctx, p, change{Kind: "user_group.update", Resource: g.ID, Permission: "users.manage", Group: "*", All: true}, func(tx pgx.Tx) error {
		if g.Members != nil {
			if err := s.authorizePeopleMembership(ctx, tx, p, []string{g.ID}); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, "INSERT INTO user_groups(id,name,mfa_policy,require_sk,purpose) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET name=excluded.name,mfa_policy=excluded.mfa_policy,require_sk=excluded.require_sk", g.ID, g.Name, g.MFAPolicy, g.RequireSK, g.Purpose); err != nil {
			return err
		}
		if g.Members == nil {
			if _, err := tx.Exec(ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id IN(SELECT user_id FROM user_group_members WHERE group_id=$1)", g.ID); err != nil {
				return err
			}
			return revokeNonSK(ctx, tx)
		}
		if _, err := tx.Exec(ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=ANY($1::uuid[]) OR id IN (SELECT user_id FROM user_group_members WHERE group_id=$2)", g.Members, g.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM user_group_members WHERE group_id=$1", g.ID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO user_group_members SELECT $1,id FROM unnest($2::uuid[]) id ON CONFLICT DO NOTHING", g.ID, g.Members)
		if err != nil {
			return err
		}
		if err := requireAdministrator(ctx, tx); err != nil {
			return err
		}
		return revokeNonSK(ctx, tx)
	})
}
func (s *Store) BindUserGroupRole(ctx context.Context, p authorization.Principal, id string, b authorization.Binding) (string, error) {
	return s.mutate(ctx, p, change{Kind: "user_group.role", Resource: id, Permission: "roles.manage", Group: b.GroupID, All: true}, func(tx pgx.Tx) error {
		current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
		if err != nil {
			return err
		}
		var raw, sudo []byte
		var nativeRules string
		if err = tx.QueryRow(ctx, "SELECT permissions,sudo,sudoers FROM roles WHERE id=$1", b.RoleID).Scan(&raw, &sudo, &nativeRules); err != nil {
			return failure(err)
		}
		var permissions []string
		var rules []authorization.SudoRule
		if err = json.Unmarshal(raw, &permissions); err != nil {
			return err
		}
		if err = json.Unmarshal(sudo, &rules); err != nil {
			return err
		}
		for _, permission := range permissions {
			if !current.Allowed(permission, b.GroupID) {
				return ErrForbidden
			}
		}
		if (len(rules) > 0 || nativeRules != "") && !current.Allowed("sudo.manage", b.GroupID) {
			return ErrForbidden
		}
		if b.GroupID != "*" {
			var exists bool
			if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM server_groups WHERE id::text=$1)", b.GroupID).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return ErrNotFound
			}
		}
		_, err = tx.Exec(ctx, "INSERT INTO user_group_role_bindings(id,user_group_id,role_id,group_id) VALUES($1,$2,$3,$4) ON CONFLICT(user_group_id,role_id,group_id) DO NOTHING", uuid.NewString(), id, b.RoleID, b.GroupID)
		return err
	})
}

func mapField(data []byte, key string) (any, bool) {
	var fields map[string]any
	_ = json.Unmarshal(data, &fields)
	v, ok := fields[key]
	return v, ok
}
