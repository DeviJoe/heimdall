package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"strings"
)

func (s *Store) AccessibleNodesPage(ctx context.Context, p authorization.Principal, userID string, limit int, after, query string) ([]application.AccessibleNode, string, error) {
	if p.TokenID != "" || p.Restricted || p.UserID == "" {
		return nil, "", ErrForbidden
	}
	if userID != p.UserID && !p.Allowed("users.manage", "*") {
		return nil, "", ErrForbidden
	}
	if after != "" {
		if _, err := uuid.Parse(after); err != nil {
			return nil, "", errors.New("invalid cursor")
		}
	}
	if limit < 1 || limit > 100 {
		limit = 100
	}
	// This view includes people-group inheritance and UNIX-group assignments.
	// nodes.read grants visibility to operators, not permission to log in.
	rows, err := s.Pool.Query(ctx, `WITH user_grants AS MATERIALIZED (
 SELECT DISTINCT b.group_id,r.id,r.name,r.sudoers,r.sudo,r.allow_password,r.allow_ssh_keys FROM native_role_bindings b
 JOIN roles r ON r.id=b.role_id WHERE b.user_id=$1 AND r.linux_access AND (r.allow_password OR r.allow_ssh_keys)
) SELECT n.id,n.name,n.hostname,n.addresses,n.platform,g.name,
 coalesce(nullif(n.ssh_host,''),n.name),n.ssh_port,u.login,
 CASE WHEN n.desired_revision>n.applied_revision OR NOT EXISTS(SELECT 1 FROM node_accounts a WHERE a.node_id=n.id AND a.user_id=u.id)
 THEN 'pending' ELSE 'applied' END, grants.roles,
 CASE WHEN n.last_seen IS NULL OR n.last_seen<=now()-make_interval(secs=>settings.offline_seconds) THEN 'offline' WHEN n.last_seen<=now()-make_interval(secs=>settings.offline_seconds/2) OR n.local_error<>'' OR n.status<>'in_sync' OR n.desired_revision<>n.applied_revision THEN 'warning' ELSE 'healthy' END
 FROM nodes n CROSS JOIN (SELECT coalesce((SELECT (value->>'offline_seconds')::int FROM runtime_settings WHERE id=true),90) offline_seconds) settings JOIN server_groups g ON g.id=n.group_id JOIN users u ON u.id=$1
 JOIN LATERAL (
   SELECT jsonb_agg(jsonb_build_object('name',r.name,'sudoers',r.sudoers,'sudo',r.sudo,'allow_password',r.allow_password,'allow_ssh_keys',r.allow_ssh_keys) ORDER BY r.name) roles
   FROM (SELECT DISTINCT id,name,sudoers,sudo,allow_password,allow_ssh_keys FROM user_grants WHERE group_id='*' OR group_id=n.group_id::text) r
 ) grants ON grants.roles IS NOT NULL
 WHERE u.sync_to_nodes AND u.status='active' AND u.kind='human' AND u.shell NOT IN ('/usr/sbin/nologin','/sbin/nologin','/bin/false')
 AND mfa_satisfied(u.id) AND NOT n.disabled AND mandatory_allowed(u.id,n.group_id)
 AND ($2='' OR n.id>NULLIF($2,'')::uuid)
 AND ($3='' OR lower(n.name||' '||n.hostname||' '||coalesce(n.ssh_host,'')||' '||array_to_string(n.addresses,' ')||' '||g.name) LIKE $3)
 ORDER BY n.id LIMIT $4`, userID, after, searchPattern(strings.TrimSpace(query)), limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []application.AccessibleNode{}
	for rows.Next() {
		var n application.AccessibleNode
		var roles []byte
		if err = rows.Scan(&n.ID, &n.Name, &n.Hostname, &n.Addresses, &n.Platform, &n.GroupName, &n.Host, &n.Port, &n.Login, &n.AccessStatus, &roles, &n.Health); err != nil {
			return nil, "", err
		}
		if err = json.Unmarshal(roles, &n.Roles); err != nil {
			return nil, "", err
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
