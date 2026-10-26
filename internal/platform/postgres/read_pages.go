package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"strconv"
	"strings"
)

// Every public collection has an allowlisted projection and a keyset cursor.
// Pagination happens before expensive per-row aggregate projections.
func (s *Store) ReadPage(ctx context.Context, p authorization.Principal, collection string, q application.PageQuery) (application.Page, error) {
	out := application.Page{Items: []json.RawMessage{}}
	if q.Limit < 1 || q.Limit > 500 {
		q.Limit = 100
	}
	if len(q.Search) > 200 || len(q.After) > 1024 {
		return out, errors.New("invalid page query")
	}
	permission, table, projection, sortKey, filter, search := "", "", "", "", "", ""
	args := []any{q.Limit + 1}
	switch collection {
	case "keys", "bindings", "people-bindings":
		if _, err := uuid.Parse(q.Parent); err != nil {
			return out, errors.New("invalid collection owner")
		}
		if collection == "people-bindings" {
			if !p.Allowed("users.read", "*") {
				return out, ErrForbidden
			}
			permission = "roles.read"
			table = "user_group_role_bindings t JOIN roles r ON r.id=t.role_id LEFT JOIN server_groups g ON g.id::text=t.group_id"
			filter = "t.user_group_id=$6::uuid AND ($2 OR t.group_id=ANY(SELECT unnest($3::uuid[])::text))"
		} else {
			if !p.Self(q.Parent) && !p.Allowed("users.read", "*") {
				return out, ErrForbidden
			}
			filter = "t.user_id=$6::uuid"
			table = "role_bindings t JOIN roles r ON r.id=t.role_id LEFT JOIN server_groups g ON g.id::text=t.group_id"
		}
		args = append(args, nil, nil, nil, nil, q.Parent)
		if collection == "keys" {
			table = "ssh_keys t"
			sortKey = "t.created_at"
			search = "t.name||' '||t.fingerprint||' '||t.algorithm"
			projection = "to_jsonb(t)||jsonb_build_object('status',CASE WHEN t.status='active' AND t.expires_at<=now() THEN 'expired' ELSE t.status END)"
		} else {
			sortKey = "lower(r.name)"
			search = "r.name||' '||coalesce(g.name,t.group_id)"
			projection = "to_jsonb(t)||jsonb_build_object('role',to_jsonb(r),'group_name',coalesce(g.name,t.group_id))"
		}
	case "unix-memberships":
		if _, err := uuid.Parse(q.Parent); err != nil {
			return out, errors.New("invalid collection owner")
		}
		if !p.Self(q.Parent) && !p.Allowed("users.read", "*") {
			return out, ErrForbidden
		}
		table = "unix_groups t"
		sortKey = "lower(t.name)"
		search = "t.name||' '||t.gid::text"
		args = append(args, nil, nil, nil, nil, q.Parent)
		filter = "EXISTS(SELECT 1 FROM effective_unix_members m WHERE m.group_id=t.id AND m.user_id=$6::uuid)"
		projection = "to_jsonb(t)||jsonb_build_object('primary',t.gid=(SELECT gid FROM users WHERE id=$6::uuid),'supplementary',EXISTS(SELECT 1 FROM unix_group_members m WHERE m.group_id=t.id AND m.user_id=$6::uuid))"
	case "security/labels":
		permission = "security.manage"
		table = "(SELECT 'user' AS resource_type,user_id AS id,level,categories FROM user_security UNION ALL SELECT 'node_group',group_id,level,categories FROM group_security) t"
		sortKey = "t.resource_type||t.id::text"
		projection = "jsonb_build_object('resource_type',t.resource_type,'resource_id',t.id,'label',jsonb_build_object('level',t.level,'categories',t.categories))"
		search = "t.resource_type||' '||t.id::text"
		if q.Parent != "" {
			if _, err := uuid.Parse(q.Parent); err != nil {
				return out, errors.New("invalid label owner")
			}
		}
		if q.Status != "" && q.Status != "user" && q.Status != "node_group" {
			return out, errors.New("invalid label resource")
		}
		args = append(args, nil, nil, nil, nil, q.Parent, q.Status)
		filter = "($6='' OR t.id=NULLIF($6,'')::uuid) AND ($7='' OR t.resource_type=$7)"
		if !p.Allowed(permission, "*") {
			return out, ErrForbidden
		}
	case "audit":
		permission = "audit.read"
		table = "audit_events t"
		sortKey = "t.id"
		projection = "jsonb_build_object('id',t.id,'actor_id',t.actor_id,'channel',t.channel,'action',t.action,'resource_id',t.resource_id,'created_at',t.created_at)"
		search = "t.actor_id||' '||t.action||' '||t.resource_id"
	case "operations":
		permission = "sync.read"
		table = "sync_operations t"
		sortKey = "t.revision"
		projection = `(SELECT jsonb_build_object('id',t.id,'kind',t.kind,'resource_id',t.resource_id,'revision',t.revision,'created_at',t.created_at,'total',count(*),'applied',count(*) FILTER(WHERE x.status='applied'),'failed',count(*) FILTER(WHERE x.status='failed'),'status',CASE WHEN count(*)=count(*) FILTER(WHERE x.status='applied') THEN 'succeeded' WHEN count(*) FILTER(WHERE x.status='failed')>0 THEN 'failed' ELSE 'pending' END) FROM sync_targets x JOIN nodes n ON n.id=x.node_id WHERE x.operation_id=t.id AND ($2 OR n.group_id=ANY($3::uuid[]) OR ($4 AND t.user_id=$5::uuid)))`
		search = "t.kind||' '||t.resource_id"
		filter = "($2 OR EXISTS(SELECT 1 FROM sync_targets x JOIN nodes n ON n.id=x.node_id WHERE x.operation_id=t.id AND n.group_id=ANY($3::uuid[])) OR ($4 AND t.user_id=$5::uuid))"
	case "incidents":
		permission = "incidents.read"
		table = "incidents t LEFT JOIN nodes n ON n.id=t.node_id"
		sortKey = "t.last_seen"
		projection = "(to_jsonb(t)-'dedup_key')||jsonb_build_object('node_name',n.name)"
		search = "t.kind||' '||t.message||' '||coalesce(n.name,'')"
		filter = "($2 OR t.group_id=ANY($3::uuid[]) OR ($4 AND t.user_id=$5::uuid))"
	case "security/events":
		permission = "security.read"
		table = "security_events t JOIN nodes n ON n.id=t.node_id"
		sortKey = "t.received_at"
		projection = "jsonb_build_object('id',t.id,'node_id',t.node_id,'node_name',n.name,'login',t.login,'address',t.address,'kind',t.kind,'severity',t.severity,'observed_at',t.observed_at)"
		search = "t.login||' '||t.address||' '||t.kind||' '||n.name"
		filter = "($2 OR n.group_id=ANY($3::uuid[]))"
	case "groups":
		permission = "nodes.read"
		table = "server_groups t"
		sortKey = "lower(t.name)"
		projection = "to_jsonb(t)||jsonb_build_object('nodes',(SELECT count(*) FROM nodes n WHERE n.group_id=t.id),'active_nodes',(SELECT count(*) FROM nodes n WHERE n.group_id=t.id AND NOT n.disabled))"
		search = "t.name"
		filter = "($2 OR t.id=ANY($3::uuid[]))"
	case "user-groups":
		permission = "users.read"
		table = "user_groups t"
		sortKey = "lower(t.name)"
		projection = `to_jsonb(t)||jsonb_build_object('member_count',(SELECT count(*) FROM user_group_members m JOIN users u ON u.id=m.user_id WHERE m.group_id=t.id AND u.status<>'deleted'),'totp_count',(SELECT count(*) FROM user_group_members m JOIN users u ON u.id=m.user_id WHERE m.group_id=t.id AND u.status<>'deleted' AND u.totp_secret<>''),'passkey_count',(SELECT count(*) FROM user_group_members m JOIN users u ON u.id=m.user_id WHERE m.group_id=t.id AND u.status<>'deleted' AND EXISTS(SELECT 1 FROM webauthn_credentials w WHERE w.user_id=u.id)),'missing_factors',(SELECT count(*) FROM user_group_members m JOIN users u ON u.id=m.user_id WHERE m.group_id=t.id AND u.status='active' AND NOT mfa_satisfied(u.id)))`
		search = "t.name"
	case "unix-groups":
		permission = "users.read"
		table = "unix_groups t"
		sortKey = "lower(t.name)"
		projection = `to_jsonb(t)||jsonb_build_object('member_count',(SELECT count(*) FROM unix_group_members WHERE group_id=t.id),'primary_count',(SELECT count(*) FROM users WHERE gid=t.gid AND status<>'deleted'))`
		search = "t.name||' '||t.gid::text"
	case "unix-assignments":
		permission = "roles.read"
		table = "unix_group_role_bindings t JOIN unix_groups u ON u.id=t.unix_group_id JOIN server_groups g ON g.id=t.group_id JOIN roles r ON r.id=t.role_id"
		sortKey = "t.id::text"
		projection = "to_jsonb(t)||jsonb_build_object('unix_group_name',u.name,'group_name',g.name,'role_name',r.name)"
		search = "u.name||' '||g.name||' '||r.name"
		filter = "($2 OR t.group_id=ANY($3::uuid[]))"
	case "tokens":
		permission = ""
		table = "api_tokens t JOIN users u ON u.id=t.user_id"
		sortKey = "t.created_at"
		projection = "(to_jsonb(t)-'hash')||jsonb_build_object('owner_login',u.login)"
		search = "t.name||' '||u.login"
		filter = "t.expires_at>now() AND t.revoked_at IS NULL AND (t.user_id=$5::uuid OR (" + strconv.FormatBool(p.Allowed("tokens.manage", "*")) + " AND u.kind='service'))"
		if !p.Self(p.UserID) {
			return out, ErrForbidden
		}
	case "announcements":
		permission = ""
		table = "announcements t"
		sortKey = "t.updated_at"
		projection = "to_jsonb(t)"
		search = "t.title"
		filter = "true"
		if !p.Self(p.UserID) {
			return out, ErrForbidden
		}
		if q.Status == "all" {
			if !p.Allowed("announcements.manage", "*") {
				return out, ErrForbidden
			}
		} else {
			filter = "t.enabled AND t.starts_at<=now() AND (t.ends_at IS NULL OR t.ends_at>now())"
		}
	case "roles":
		if !p.Allowed("roles.read", "*") && !p.Allowed("roles.manage", "*") {
			return out, ErrForbidden
		}
		if q.Status != "" && q.Status != "all" && q.Status != "unix" && q.Status != "application" {
			return out, errors.New("invalid role kind")
		}
		if q.Status == "unix" {
			filter = "t.linux_access"
		}
		if q.Status == "application" {
			filter = "t.permissions <> '[]'::jsonb AND t.permissions <> 'null'::jsonb"
		}
		permission = "roles.read"
		table = "roles t"
		sortKey = "lower(t.name)"
		projection = "to_jsonb(t)"
		search = "t.name"
	case "join-tokens":
		permission = "nodes.manage"
		table = "join_tokens t JOIN server_groups g ON g.id=t.group_id"
		sortKey = "t.expires_at"
		projection = "(to_jsonb(t)-'hash')||jsonb_build_object('group_name',g.name)"
		search = "t.name||' '||t.id::text||' '||g.name"
		filter = "t.expires_at>now() AND t.revoked_at IS NULL AND (t.max_uses=0 OR t.uses<t.max_uses) AND ($2 OR t.group_id=ANY($3::uuid[]))"
	default:
		return out, errors.New("unknown collection")
	}
	var groups []string
	var err error
	if permission != "" {
		groups, err = s.allowedGroups(ctx, p, permission)
	}
	if err != nil {
		return out, err
	}
	if collection == "people-bindings" || collection == "unix-assignments" {
		more, err := s.allowedGroups(ctx, p, "roles.manage")
		if err != nil {
			return out, err
		}
		if groups == nil || more == nil {
			groups = nil
		} else {
			groups = append(groups, more...)
		}
	}
	if collection == "groups" {
		groups = []string{}
		seen := map[string]bool{}
		global := false
		for _, b := range p.Bindings {
			allowed := p.Allowed("nodes.read", b.GroupID) || p.Allowed("nodes.manage", b.GroupID) || p.Allowed("roles.manage", b.GroupID) || p.Allowed("inventory.read", b.GroupID) || (p.TokenID == "" && !p.Restricted && b.Role.LinuxAccess)
			if !allowed {
				continue
			}
			if b.GroupID == "*" {
				global = true
				break
			}
			if b.GroupID != "*" && !seen[b.GroupID] {
				groups = append(groups, b.GroupID)
				seen[b.GroupID] = true
			}
		}
		if global {
			groups = nil
		} else {
			for _, id := range p.TokenGroups {
				if id != "*" && !seen[id] && (p.Allowed("nodes.read", id) || p.Allowed("nodes.manage", id) || p.Allowed("inventory.read", id)) {
					groups = append(groups, id)
					seen[id] = true
				}
			}
		}
	}

	if filter == "" && !p.Allowed(permission, "*") && !(collection == "roles" && p.Allowed("roles.manage", "*")) {
		return out, ErrForbidden
	}
	if len(args) == 1 {
		args = append(args, nil, nil, nil, nil)
	}
	args[1], args[2], args[3], args[4] = groups == nil, groups, p.Self(p.UserID), p.UserID
	conditions := []string{}
	if filter != "" {
		conditions = append(conditions, filter)
	}
	if q.Search != "" {
		args = append(args, searchPattern(q.Search))
		conditions = append(conditions, "lower("+search+") LIKE $"+strconv.Itoa(len(args)))
	}
	descending := collection == "audit" || collection == "operations" || collection == "incidents" || collection == "security/events" || collection == "join-tokens" || collection == "tokens" || collection == "announcements" || collection == "keys"
	comparison, order := ">", "ASC"
	if descending {
		comparison, order = "<", "DESC"
	}
	keyType, idType := "text", "uuid"
	if collection == "audit" || collection == "operations" {
		keyType = "bigint"
	}
	if collection == "audit" {
		idType = "bigint"
	}
	if collection == "security/events" {
		idType = "text"
	}
	if collection == "incidents" || collection == "security/events" || collection == "join-tokens" || collection == "tokens" || collection == "announcements" || collection == "keys" {
		keyType = "timestamptz"
	}
	if q.After != "" {
		raw, err := base64.RawURLEncoding.DecodeString(q.After)
		var cursor struct{ Value, ID string }
		if err != nil || json.Unmarshal(raw, &cursor) != nil || cursor.ID == "" {
			return out, errors.New("invalid cursor")
		}
		args = append(args, cursor.Value, cursor.ID)
		conditions = append(conditions, "("+sortKey+",t.id)"+comparison+"($"+strconv.Itoa(len(args)-1)+"::"+keyType+",$"+strconv.Itoa(len(args))+"::"+idType+")")
	}

	if collection == "incidents" && q.Status != "all" {
		conditions = append(conditions, "t.status<>'resolved'")
	}
	if collection == "unix-groups" && q.Parent != "" {
		if _, err := uuid.Parse(q.Parent); err != nil {
			return out, errors.New("invalid UNIX group")
		}
		args = append(args, q.Parent)
		conditions = append(conditions, "t.id=$"+strconv.Itoa(len(args))+"::uuid")
	}
	if collection == "groups" && q.Parent != "" {
		if q.Parent == "root" {
			conditions = append(conditions, "t.parent_id IS NULL")
		} else {
			args = append(args, q.Parent)
			conditions = append(conditions, "t.parent_id::text=$"+strconv.Itoa(len(args)))
		}
	}
	where := "true"
	if len(conditions) > 0 {
		where = strings.Join(conditions, " AND ")
	}
	// The parameter placeholder types are stable even when a collection has no scope filter.
	conditionsSQL := " AND ($2::bool OR NOT $2::bool) AND ($3::uuid[] IS NULL OR $3::uuid[] IS NOT NULL) AND ($4::bool OR NOT $4::bool) AND ($5::text IS NULL OR $5::text IS NOT NULL)"
	query := "SELECT " + projection + "," + sortKey + "::text,t.id::text FROM " + table + " WHERE " + where + conditionsSQL + " ORDER BY " + sortKey + " " + order + ",t.id " + order + " LIMIT $1"
	rows, err := s.Pool.Query(ctx, query, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	var last struct{ Value, ID string }
	for rows.Next() {
		var raw json.RawMessage
		var key, id string
		if err = rows.Scan(&raw, &key, &id); err != nil {
			return out, err
		}
		if len(out.Items) == q.Limit {
			out.Next = encodePageCursor(last.Value, last.ID)
			break
		}
		out.Items = append(out.Items, raw)
		last.Value, last.ID = key, id
	}
	return out, rows.Err()
}

func encodePageCursor(value, id string) string {
	raw, _ := json.Marshal(struct{ Value, ID string }{value, id})
	return base64.RawURLEncoding.EncodeToString(raw)
}
