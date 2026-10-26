//go:build integration

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/fleet"
	"Heimdall/internal/identity"
	"Heimdall/internal/platform/security"
	"errors"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestAccessibleNodesUsesNativeAssignmentsBeforePagination(t *testing.T) {
	ctx, s, admin, join := isolatedStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	groups, err := s.Groups(ctx, admin)
	must(err)
	parent := groups[0]
	child := fleet.Group{ID: uuid.NewString(), Name: "Child", ParentID: parent.ID}
	_, err = s.SaveGroup(ctx, admin, child)
	must(err)
	hidden := fleet.Group{ID: uuid.NewString(), Name: "Hidden"}
	_, err = s.SaveGroup(ctx, admin, hidden)
	must(err)
	user, _, err := s.CreateUser(ctx, admin, identity.User{SyncToNodes: true, Login: "engineer", Kind: "human"}, security.HashToken("invite-access"))
	must(err)
	_, err = s.AcceptInvite(ctx, "invite-access", "fixture-password-hash")
	must(err)
	role := authorization.Role{ID: uuid.NewString(), Name: "Native only", LinuxAccess: true, AllowSSHKeys: true, Permissions: []string{}, Sudoers: "ALL=(root) NOPASSWD: /usr/bin/id"}
	_, err = s.SaveRole(ctx, admin, role)
	must(err)
	unix := application.UnixGroup{ID: uuid.NewString(), Name: "engineers", GID: 21000}
	_, err = s.SaveUnixGroup(ctx, admin, unix)
	must(err)
	_, err = s.UpdateUnixMembers(ctx, admin, unix.ID, []string{user.ID}, nil)
	must(err)
	_, err = s.AssignUnixGroup(ctx, admin, application.UnixAssignment{UnixGroupID: unix.ID, RoleID: role.ID, GroupID: parent.ID})
	must(err)
	for _, entry := range []struct{ name, group string }{{"visible-a", child.ID}, {"visible-b", child.ID}, {"hidden", hidden.ID}} {
		id := uuid.NewString()
		_, err = s.Enroll(ctx, join, entry.name, "serial-"+entry.name, time.Now().Add(time.Hour), id)
		must(err)
		_, err = s.MoveNodes(ctx, admin, []string{id}, entry.group)
		must(err)
		_, err = s.Pool.Exec(ctx, "UPDATE nodes SET hostname=$2,addresses=ARRAY[$3] WHERE id=$1", id, entry.name+".internal", "10.20.30.40")
		must(err)
	}
	p, err := s.Principal(ctx, user.ID, "", "api")
	must(err)
	if p.Allowed("nodes.read", "*") {
		t.Fatal("fixture unexpectedly has management permission")
	}
	first, next, err := s.AccessibleNodesPage(ctx, p, p.UserID, 1, "", "")
	must(err)
	if len(first) != 1 || next == "" || first[0].Login != "engineer" || len(first[0].Roles) != 1 || first[0].Roles[0].Name != "Native only" {
		t.Fatalf("first page %+v next %s", first, next)
	}
	second, last, err := s.AccessibleNodesPage(ctx, p, p.UserID, 1, next, "")
	must(err)
	if len(second) != 1 || last != "" || second[0].ID == first[0].ID {
		t.Fatal("native pagination lost or duplicated access")
	}
	search, _, err := s.AccessibleNodesPage(ctx, p, p.UserID, 100, "", "10.20.30.40")
	must(err)
	if len(search) != 2 {
		t.Fatalf("IP search returned %d nodes", len(search))
	}
	noMatch, _, err := s.AccessibleNodesPage(ctx, p, p.UserID, 100, "", "hidden")
	must(err)
	if len(noMatch) != 0 {
		t.Fatal("search exposed an unassigned node")
	}
	_, err = s.SaveLabelPolicy(ctx, admin, application.LabelPolicy{ResourceType: "node_group", ResourceID: child.ID, Label: authorization.SecurityLabel{Level: 2, Categories: []string{"production"}}})
	must(err)
	blocked, _, err := s.AccessibleNodesPage(ctx, p, p.UserID, 100, "", "")
	must(err)
	if len(blocked) != 0 {
		t.Fatal("native role bypassed mandatory labels")
	}
	_, err = s.SaveLabelPolicy(ctx, admin, application.LabelPolicy{ResourceType: "user", ResourceID: user.ID, Label: authorization.SecurityLabel{Level: 3, Categories: []string{"production"}}})
	must(err)
	visible, _, err := s.AccessibleNodesPage(ctx, p, p.UserID, 100, "", "")
	must(err)
	if len(visible) != 2 {
		t.Fatal("matching mandatory labels lost native access")
	}
	if _, _, err = s.AccessibleNodesPage(ctx, p, admin.UserID, 100, "", ""); !errors.Is(err, ErrForbidden) {
		t.Fatal("ordinary user read another user's access")
	}
	adminView, _, err := s.AccessibleNodesPage(ctx, admin, p.UserID, 100, "", "")
	must(err)
	if len(adminView) != 2 {
		t.Fatal("administrator cannot inspect native grants")
	}
	p.TokenID = "automation"
	if _, _, err = s.AccessibleNodesPage(ctx, p, p.UserID, 100, "", ""); !errors.Is(err, ErrForbidden) {
		t.Fatal("token used browser self-service directory")
	}
	p.TokenID = ""
	p.Restricted = true
	if _, _, err = s.AccessibleNodesPage(ctx, p, p.UserID, 100, "", ""); !errors.Is(err, ErrForbidden) {
		t.Fatal("restricted caller queried native access")
	}
}
