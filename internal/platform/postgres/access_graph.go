package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"context"
	"encoding/json"
	"errors"
)

func (s *Store) AccessGraph(ctx context.Context, p authorization.Principal, q application.PageQuery) (application.AccessGraph, string, error) {
	out := application.AccessGraph{Connections: []application.AccessConnection{}, Recommendations: []application.AccessRecommendation{}}
	// The graph names users and both directory types. Require visibility to each,
	// rather than leaking names through role-only permissions.
	if !p.Allowed("roles.read", "*") || !p.Allowed("users.read", "*") || !p.Allowed("nodes.read", "*") {
		return out, "", ErrForbidden
	}
	if q.Limit < 1 || q.Limit > 100 {
		q.Limit = 25
	}
	if len(q.Search) > 200 || len(q.After) > 100 {
		return out, "", errors.New("invalid graph query")
	}
	if q.Status != "" && q.Status != "unix_group" && q.Status != "people_group" && q.Status != "user" {
		return out, "", errors.New("invalid graph subject kind")
	}
	rows, err := s.Pool.Query(ctx, `WITH connections AS (
 SELECT 'unix:'||b.id id,b.unix_group_id subject_id,u.name subject_name,'unix_group' subject_kind,b.role_id,b.group_id::text group_id FROM unix_group_role_bindings b JOIN unix_groups u ON u.id=b.unix_group_id
 UNION ALL SELECT 'people:'||b.id,b.user_group_id,u.name,'people_group',b.role_id,b.group_id FROM user_group_role_bindings b JOIN user_groups u ON u.id=b.user_group_id
 UNION ALL SELECT 'user:'||b.id,b.user_id,u.login,'user',b.role_id,b.group_id FROM role_bindings b JOIN users u ON u.id=b.user_id WHERE u.status<>'deleted'
), page AS (
 SELECT c.*,r.name role_name FROM connections c JOIN roles r ON r.id=c.role_id LEFT JOIN server_groups g ON g.id::text=c.group_id
 WHERE ($1='' OR c.id>$1) AND ($2='' OR lower(c.subject_name||' '||r.name||' '||coalesce(g.name,'Все ноды')) LIKE $2) AND ($3='' OR c.subject_kind=$3)
 ORDER BY c.id LIMIT $4
) SELECT p.id,p.subject_id,p.subject_name,p.subject_kind,p.group_id,coalesce(g.name,'Все ноды'),to_jsonb(r),coalesce((SELECT array_agg(c.ancestor_id::text ORDER BY c.depth) FROM server_group_closure c WHERE c.descendant_id=g.id),'{}'::text[])
 FROM page p JOIN roles r ON r.id=p.role_id LEFT JOIN server_groups g ON g.id::text=p.group_id ORDER BY p.id`, q.After, searchPattern(q.Search), q.Status, q.Limit+1)
	if err != nil {
		return out, "", err
	}
	defer rows.Close()
	next := ""
	for rows.Next() {
		var c application.AccessConnection
		var raw []byte
		if err = rows.Scan(&c.ID, &c.SubjectID, &c.SubjectName, &c.SubjectKind, &c.GroupID, &c.GroupName, &raw, &c.Ancestors); err != nil {
			return out, "", err
		}
		if len(out.Connections) == q.Limit {
			next = out.Connections[len(out.Connections)-1].ID
			break
		}
		if err = json.Unmarshal(raw, &c.Role); err != nil {
			return out, "", err
		}
		c.Role.Normalize()
		out.Connections = append(out.Connections, c)
	}
	if err = rows.Err(); err != nil {
		return out, "", err
	}
	out.Recommendations = application.AccessRecommendations(out.Connections)
	return out, next, nil
}
