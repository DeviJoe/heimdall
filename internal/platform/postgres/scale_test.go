//go:build loadtest

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"encoding/json"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestTwentyThousandUsersProjectionAndPaging(t *testing.T) {
	ctx, s, admin, join := isolatedStore(t, true)
	started := time.Now()
	_, err := s.Pool.Exec(ctx, `INSERT INTO users(id,login,display_name,status,uid,gid,home,shell,source) SELECT md5('scale-user-'||n)::uuid,'scale_'||n,'Scale user '||n,'active',100000+n,100000+n,'/home/scale_'||n,'/bin/bash','ldap:scale' FROM generate_series(1,20000) n`)
	if err != nil {
		t.Fatal(err)
	}
	group := uuid.NewString()
	_, err = s.SaveUserGroup(ctx, admin, application.UserGroup{ID: group, Name: "Scale", MFAPolicy: "none", Members: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Pool.Exec(ctx, "INSERT INTO user_group_members SELECT $1,id FROM users WHERE source='ldap:scale'", group); err != nil {
		t.Fatal(err)
	}
	roles, err := s.Roles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	groups, err := s.Groups(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		if role.Name == "Linux user" {
			_, err = s.BindUserGroupRole(ctx, admin, group, authorization.Binding{RoleID: role.ID, GroupID: groups[0].ID})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	node := uuid.NewString()
	if _, err = s.Enroll(ctx, join, "scale.internal", "123", time.Now().Add(time.Hour), node); err != nil {
		t.Fatal(err)
	}
	projectionStarted := time.Now()
	state, err := s.Snapshot(ctx, node)
	if err != nil {
		t.Fatal(err)
	}
	duration := time.Since(projectionStarted)
	if len(state.Accounts) != 20000 {
		t.Fatalf("projection contains %d users", len(state.Accounts))
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 16<<20 {
		t.Fatalf("manifest %d bytes exceeds transport limit", len(raw))
	}
	total := 0
	after := ""
	seen := map[string]bool{}
	for {
		users, next, err := s.UsersPage(ctx, admin, 500, after)
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range users {
			if seen[u.ID] {
				t.Fatal("duplicate cursor result")
			}
			seen[u.ID] = true
		}
		total += len(users)
		if next == "" {
			break
		}
		after = next
	}
	if total != 20001 {
		t.Fatalf("paging contains %d users", total)
	}
	prefix, _, err := s.FilterUsersPage(ctx, admin, 100, "", "scale_1999", "human")
	if err != nil || len(prefix) != 11 {
		t.Fatalf("literal prefix filter: %d %v", len(prefix), err)
	}
	t.Logf("20000 users: manifest=%d bytes projection=%s total=%s", len(raw), duration, time.Since(started))
}
