//go:build integration

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/fleet"
	"Heimdall/internal/identity"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestCollectionPaginationAndLiteralSearch(t *testing.T) {
	ctx, s, admin, _ := isolatedStore(t)
	for _, name := range []string{"Zone beta", "zone ALPHA", "Zone gamma", "Zone_underscore"} {
		if _, err := s.SaveGroup(ctx, admin, fleet.Group{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	cursor := ""
	for {
		page, err := s.ReadPage(ctx, admin, "groups", application.PageQuery{Limit: 1, After: cursor, Search: "oNe "})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) > 1 {
			t.Fatal("unbounded page")
		}
		for _, raw := range page.Items {
			var group fleet.Group
			if err = json.Unmarshal(raw, &group); err != nil {
				t.Fatal(err)
			}
			if seen[group.ID] {
				t.Fatal("duplicate cursor row")
			}
			seen[group.ID] = true
		}
		if page.Next == "" {
			break
		}
		cursor = page.Next
	}
	if len(seen) != 3 {
		t.Fatalf("missing search results: %d", len(seen))
	}
	page, err := s.ReadPage(ctx, admin, "groups", application.PageQuery{Search: "_"})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("LIKE wildcard was not escaped: %v, %d", err, len(page.Items))
	}
	if _, err = s.ReadPage(ctx, admin, "groups", application.PageQuery{After: "invalid cursor"}); err == nil {
		t.Fatal("malformed cursor accepted")
	}
}

func TestReusableJoinTokenLifetimeAndUseLimit(t *testing.T) {
	ctx, s, admin, _ := isolatedStore(t)
	groups, err := s.Groups(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.CreateJoinToken(ctx, admin, groups[0].ID, 0, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := s.JoinTokens(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, tok := range tokens {
		if tok.MaxUses == 0 {
			id = tok.ID
		}
	}
	if id == "" {
		t.Fatal("unlimited token missing")
	}
	for i := 0; i < 3; i++ {
		if _, err = s.Enroll(ctx, secret, "unlimited", "serial", time.Now().Add(time.Hour), uuid.NewString()); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.UpdateJoinToken(ctx, admin, id, 3, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Enroll(ctx, secret, "exhausted", "serial", time.Now().Add(time.Hour), uuid.NewString()); err == nil {
		t.Fatal("use ceiling ignored")
	}
	if err = s.UpdateJoinToken(ctx, admin, id, 0, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Pool.Exec(ctx, "UPDATE join_tokens SET expires_at=now()-interval '1 second' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Enroll(ctx, secret, "expired", "serial", time.Now().Add(time.Hour), uuid.NewString()); err == nil {
		t.Fatal("unlimited uses bypassed expiry")
	}
}

func TestPeopleMembershipCannotEscalateRole(t *testing.T) {
	ctx, s, admin, _ := isolatedStore(t)
	user, _, err := s.CreateUser(ctx, admin, identity.User{Login: "directory_operator", Kind: "service"}, "")
	if err != nil {
		t.Fatal(err)
	}
	role := authorization.Role{ID: uuid.NewString(), Name: "People manager", Permissions: []string{"users.manage", "users.read"}}
	if _, err = s.SaveRole(ctx, admin, role); err != nil {
		t.Fatal(err)
	}
	if _, err = s.BindRole(ctx, admin, authorization.Binding{UserID: user.ID, RoleID: role.ID, GroupID: "*"}); err != nil {
		t.Fatal(err)
	}
	operator, err := s.Principal(ctx, user.ID, "", "api")
	if err != nil {
		t.Fatal(err)
	}
	group := application.UserGroup{ID: uuid.NewString(), Name: "Privileged people", MFAPolicy: "none"}
	if _, err = s.SaveUserGroup(ctx, admin, group); err != nil {
		t.Fatal(err)
	}
	if _, err = s.BindUserGroupRole(ctx, admin, group.ID, authorization.Binding{RoleID: admin.Bindings[0].RoleID, GroupID: "*"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.MovePeople(ctx, operator, "", group.ID, []string{user.ID}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("role escalation through membership: %v", err)
	}
	var count int
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM user_group_members WHERE group_id=$1", group.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed move altered membership")
	}
	if _, err = s.DeleteRole(ctx, admin, admin.Bindings[0].RoleID); err == nil {
		t.Fatal("last administrator role deleted")
	}
}

func TestBulkIncidentResolutionIsAtomic(t *testing.T) {
	ctx, s, admin, _ := isolatedStore(t)
	activity, protected := uuid.NewString(), uuid.NewString()
	for id, kind := range map[string]string{activity: "failed_authentication", protected: "revocation_pending"} {
		if _, err := s.Pool.Exec(ctx, "INSERT INTO incidents(id,dedup_key,kind,severity,message) VALUES($1::uuid,$1::uuid::text,$2,'warning','fixture')", id, kind); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ResolveIncidents(ctx, admin, []string{activity, protected}); err == nil {
		t.Fatal("sync incident manually closed")
	}
	var status string
	if err := s.Pool.QueryRow(ctx, "SELECT status FROM incidents WHERE id=$1", activity).Scan(&status); err != nil || status != "open" {
		t.Fatal("rejected batch partially applied")
	}
	if err := s.ResolveIncidents(ctx, admin, []string{activity}); err != nil {
		t.Fatal(err)
	}
	page, err := s.ReadPage(ctx, admin, "incidents", application.PageQuery{Limit: 1})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("active incident filter: %v", err)
	}
	history, err := s.ReadPage(ctx, admin, "incidents", application.PageQuery{Status: "all"})
	if err != nil || len(history.Items) != 2 {
		t.Fatalf("history filter: %v", err)
	}
}
