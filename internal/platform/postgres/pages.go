package postgres

import (
	"Heimdall/internal/authorization"
	"Heimdall/internal/fleet"
	"Heimdall/internal/identity"
	"context"
	"fmt"
	"github.com/google/uuid"
	"strings"
	"time"
)

func (s *Store) allowedGroups(ctx context.Context, p authorization.Principal, permission string) ([]string, error) {
	if p.Allowed(permission, "*") {
		return nil, nil
	}
	// Principal already contains expanded inherited scopes. Enumerating the
	// whole fleet on each scoped read would make pagination O(all groups).
	candidates := make(map[string]bool, len(p.Bindings)+len(p.TokenGroups))
	for _, binding := range p.Bindings {
		if binding.GroupID != "*" {
			candidates[binding.GroupID] = true
		}
	}
	for _, group := range p.TokenGroups {
		if group != "*" {
			candidates[group] = true
		}
	}
	ids := []string{}
	for id := range candidates {
		if p.Allowed(permission, id) {
			ids = append(ids, id)
		}
	}
	return ids, nil
}
func (s *Store) NodesPage(ctx context.Context, p authorization.Principal, offline time.Duration, limit int, after string) ([]fleet.Node, string, error) {
	return s.NodesInGroupPage(ctx, p, offline, limit, after, "")
}
func (s *Store) NodesInGroupPage(ctx context.Context, p authorization.Principal, offline time.Duration, limit int, after, group string) ([]fleet.Node, string, error) {
	return s.QueryNodesPage(ctx, p, offline, limit, after, group, "")
}
func (s *Store) QueryNodesPage(ctx context.Context, p authorization.Principal, offline time.Duration, limit int, after, group, search string) ([]fleet.Node, string, error) {
	return s.FilteredNodesPage(ctx, p, offline, limit, after, group, search, "", "")
}
func (s *Store) FilteredNodesPage(ctx context.Context, p authorization.Principal, offline time.Duration, limit int, after, group, search, status, platform string) ([]fleet.Node, string, error) {
	if status != "" && status != "healthy" && status != "warning" && status != "offline" && status != "disabled" {
		return nil, "", fmt.Errorf("invalid node status")
	}
	if platform != "" && platform != "linux" && platform != "freebsd" {
		return nil, "", fmt.Errorf("invalid platform")
	}
	if len(search) > 200 {
		return nil, "", fmt.Errorf("search too long")
	}
	if after != "" {
		if _, err := uuid.Parse(after); err != nil {
			return nil, "", fmt.Errorf("invalid cursor")
		}
	}
	if limit < 1 || limit > 500 {
		limit = 100
	}
	if group != "" {
		if _, err := uuid.Parse(group); err != nil {
			return nil, "", fmt.Errorf("invalid group")
		}
	}
	groups, err := s.allowedGroups(ctx, p, "nodes.read")
	if err != nil {
		return nil, "", err
	}
	certificatePending := "n.certificate_policy_version<(SELECT certificate_policy_version FROM runtime_settings WHERE id=true)"
	healthSQL := "CASE WHEN n.disabled THEN 'disabled' WHEN n.cert_expires<=now() OR n.last_seen IS NULL OR n.last_seen<=now()-$7::interval THEN 'offline' WHEN n.last_seen<=now()-($7::interval/2) OR n.status<>'in_sync' OR n.desired_revision<>n.applied_revision OR n.local_error<>'' OR " + certificatePending + " THEN 'warning' ELSE 'healthy' END"
	rows, err := s.Pool.Query(ctx, "SELECT n.id,n.name,n.group_id,g.name,n.desired_revision,n.applied_revision,n.status,n.error,n.last_seen,n.last_progress,n.pending_since,n.cert_expires,n.disabled,n.ssh_host,n.ssh_port,n.hostname,n.addresses,n.platform,n.metadata_seen,"+healthSQL+",CASE WHEN n.cert_expires<=now() THEN 'expired' WHEN "+certificatePending+" THEN 'pending' ELSE 'current' END FROM nodes n JOIN server_groups g ON g.id=n.group_id WHERE ($1 OR n.group_id=ANY($2::uuid[])) AND ($3='' OR n.id>NULLIF($3,'')::uuid) AND ($5='' OR n.group_id=NULLIF($5,'')::uuid) AND ($6='' OR lower(n.name || ' ' || n.hostname || ' ' || n.ssh_host) LIKE $6 OR EXISTS(SELECT 1 FROM unnest(n.addresses) a WHERE a LIKE $6)) AND ($8='' OR ("+healthSQL+")=$8) AND ($9='' OR lower(split_part(n.platform,'/',1))=$9) ORDER BY n.id LIMIT $4", groups == nil, groups, after, limit+1, group, searchPattern(search), fmt.Sprintf("%f seconds", offline.Seconds()), status, platform)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []fleet.Node{}
	for rows.Next() {
		var n fleet.Node
		if err = rows.Scan(&n.ID, &n.Name, &n.GroupID, &n.GroupName, &n.DesiredRevision, &n.AppliedRevision, &n.Status, &n.Error, &n.LastSeen, &n.LastProgress, &n.PendingSince, &n.CertExpires, &n.Disabled, &n.SSHHost, &n.SSHPort, &n.Hostname, &n.Addresses, &n.Platform, &n.MetadataSeen, &n.Health, &n.CertificateStatus); err != nil {
			return nil, "", err
		}
		n.Connectivity = "offline"
		if n.LastSeen != nil {
			elapsed := time.Since(*n.LastSeen)
			if elapsed < offline/2 {
				n.Connectivity = "online"
			} else if elapsed < offline {
				n.Connectivity = "suspect"
			}
		}
		out = append(out, n)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].ID
	}
	return out, next, nil
}
func (s *Store) UsersPage(ctx context.Context, p authorization.Principal, limit int, after string) ([]identity.User, string, error) {
	return s.SearchUsersPage(ctx, p, limit, after, "")
}
func (s *Store) SearchUsersPage(ctx context.Context, p authorization.Principal, limit int, after, search string) ([]identity.User, string, error) {
	return s.FilterUsersPage(ctx, p, limit, after, search, "")
}
func (s *Store) FilterUsersPage(ctx context.Context, p authorization.Principal, limit int, after, search, kind string) ([]identity.User, string, error) {
	return s.QueryUsersPage(ctx, p, limit, after, search, kind, "", "")
}
func (s *Store) QueryUsersPage(ctx context.Context, p authorization.Principal, limit int, after, search, kind, group, factor string) ([]identity.User, string, error) {
	return s.queryUsers(ctx, p, limit, after, search, kind, group, factor, "", false, "", "")
}
func (s *Store) QueryUnixUsersPage(ctx context.Context, p authorization.Principal, limit int, after, search, unix string, only bool) ([]identity.User, string, error) {
	return s.queryUsers(ctx, p, limit, after, search, "", "", "", unix, only, "", "")
}
func (s *Store) FilteredUsersPage(ctx context.Context, p authorization.Principal, limit int, after, search, kind, group, factor, status, sync string) ([]identity.User, string, error) {
	return s.queryUsers(ctx, p, limit, after, search, kind, group, factor, "", false, status, sync)
}
func (s *Store) queryUsers(ctx context.Context, p authorization.Principal, limit int, after, search, kind, group, factor, unix string, only bool, status, sync string) ([]identity.User, string, error) {
	if unix != "" {
		if _, err := uuid.Parse(unix); err != nil {
			return nil, "", fmt.Errorf("invalid UNIX group")
		}
	}

	if group != "" {
		if _, err := uuid.Parse(group); err != nil {
			return nil, "", fmt.Errorf("invalid people group")
		}
	}
	if status != "" && status != "active" && status != "invited" && status != "disabled" {
		return nil, "", fmt.Errorf("invalid user status")
	}
	if sync != "" && sync != "enabled" && sync != "disabled" {
		return nil, "", fmt.Errorf("invalid UNIX sync filter")
	}
	if factor != "" && factor != "totp" && factor != "passkey" && factor != "missing" && factor != "none" {
		return nil, "", fmt.Errorf("unknown factor filter")
	}
	if kind != "" && kind != "human" && kind != "service" {
		return nil, "", fmt.Errorf("unknown account kind")
	}
	if len(search) > 200 {
		return nil, "", fmt.Errorf("search too long")
	}
	if !p.Allowed("users.read", "*") {
		v, err := s.Users(ctx, p)
		return v, "", err
	}
	if after != "" {
		if _, err := uuid.Parse(after); err != nil {
			return nil, "", fmt.Errorf("invalid cursor")
		}
	}
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.Pool.Query(ctx, "SELECT "+userColumns+",($7<>'' AND id IN(SELECT user_id FROM unix_group_members WHERE group_id=NULLIF($7,'')::uuid)),($7<>'' AND gid=(SELECT gid FROM unix_groups WHERE id=NULLIF($7,'')::uuid)) FROM users WHERE status<>'deleted' AND ($1='' OR id>NULLIF($1,'')::uuid) AND ($3='' OR lower(login || ' ' || display_name) LIKE $3) AND ($4='' OR kind=$4) AND ($5='' OR id IN(SELECT user_id FROM user_group_members WHERE group_id=NULLIF($5,'')::uuid)) AND ($6='' OR ($6='totp' AND totp_secret<>'') OR ($6='passkey' AND EXISTS(SELECT 1 FROM webauthn_credentials w WHERE w.user_id=users.id)) OR ($6='missing' AND NOT mfa_satisfied(id)) OR ($6='none' AND totp_secret='' AND NOT EXISTS(SELECT 1 FROM webauthn_credentials w WHERE w.user_id=users.id))) AND ($7='' OR NOT $8 OR gid=(SELECT gid FROM unix_groups WHERE id=NULLIF($7,'')::uuid) OR id IN(SELECT user_id FROM unix_group_members WHERE group_id=NULLIF($7,'')::uuid)) AND ($9='' OR status=$9) AND ($10='' OR sync_to_nodes=($10='enabled')) ORDER BY id LIMIT $2", after, limit+1, searchPattern(search), kind, group, factor, unix, only, status, sync)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []identity.User{}
	for rows.Next() {
		var member, primary bool
		u, err := scanUserExtra(rows, &member, &primary)
		u.UnixMember, u.UnixPrimary = member, primary
		if err != nil {
			return nil, "", err
		}
		out = append(out, u)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].ID
	}
	return out, next, nil
}
func (s *Store) FleetSummary(ctx context.Context, p authorization.Principal, offline time.Duration) (map[string]int, error) {
	groups, err := s.allowedGroups(ctx, p, "nodes.read")
	if err != nil {
		return nil, err
	}
	var total, healthy, pending, incidents, offlineCount, warning int
	err = s.Pool.QueryRow(ctx, "SELECT count(*),count(*) FILTER(WHERE NOT disabled AND status='in_sync' AND desired_revision=applied_revision AND local_error='' AND last_seen>now()-($3::interval/2)),count(*) FILTER(WHERE desired_revision>applied_revision),count(*) FILTER(WHERE disabled OR last_seen IS NULL OR last_seen<=now()-$3::interval) FROM nodes WHERE $1 OR group_id=ANY($2::uuid[])", groups == nil, groups, fmt.Sprintf("%f seconds", offline.Seconds())).Scan(&total, &healthy, &pending, &offlineCount)
	if err != nil {
		return nil, err
	}
	incidentGroups, err := s.allowedGroups(ctx, p, "incidents.read")
	if err != nil {
		return nil, err
	}
	err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM incidents WHERE status<>'resolved' AND ($1 OR group_id=ANY($2::uuid[]) OR user_id::text=$3)", incidentGroups == nil, incidentGroups, p.UserID).Scan(&incidents)
	warning = total - healthy - offlineCount
	return map[string]int{"warning": warning, "offline": offlineCount, "nodes": total, "healthy": healthy, "pending": pending, "incidents": incidents}, err
}
func (s *Store) PendingConnections(ctx context.Context, ids []string) ([]string, error) {
	rows, err := s.Pool.Query(ctx, "SELECT id FROM nodes WHERE id=ANY($1::uuid[]) AND desired_revision>applied_revision AND NOT disabled", ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func searchPattern(value string) string {
	if value == "" {
		return ""
	}
	return "%" + strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(strings.ToLower(value)) + "%"
}
