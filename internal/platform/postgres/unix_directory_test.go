//go:build integration

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/identity"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestUnixAssignmentsDefaultDenyAndScope(t *testing.T) {
	ctx, s, admin, join := isolatedStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	u, _, err := s.CreateUser(ctx, admin, identity.User{SyncToNodes: true, Login: "unix_service", Kind: "service"}, "")
	must(err)
	node := uuid.NewString()
	_, err = s.Enroll(ctx, join, "unix-node", "123", time.Now().Add(time.Hour), node)
	must(err)
	state, err := s.Snapshot(ctx, node)
	must(err)
	if len(state.Accounts) != 0 {
		t.Fatal("unassigned user received native access")
	}
	g := application.UnixGroup{ID: uuid.NewString(), Name: "engineers", GID: 22000, Members: []string{u.ID}}
	_, err = s.SaveUnixGroup(ctx, admin, g)
	must(err)
	role := authorization.Role{ID: uuid.NewString(), Name: "Scoped sudo", LinuxAccess: true, AllowSSHKeys: true, Permissions: []string{"*"}, Sudoers: "ALL=(root:root) NOPASSWD: /usr/bin/id, /usr/bin/whoami"}
	_, err = s.SaveRole(ctx, admin, role)
	must(err)
	groups, err := s.Groups(ctx, admin)
	must(err)
	b := application.UnixAssignment{ID: uuid.NewString(), UnixGroupID: g.ID, GroupID: groups[0].ID, RoleID: role.ID}
	_, err = s.AssignUnixGroup(ctx, admin, b)
	must(err)
	p, err := s.Principal(ctx, u.ID, "", "api")
	must(err)
	if p.Allowed("users.manage", "*") {
		t.Fatal("UNIX assignment leaked CP administrative permissions")
	}
	state, err = s.Snapshot(ctx, node)
	must(err)
	if len(state.Accounts) != 1 || !state.Accounts[0].Enabled || len(state.Groups) != 1 || len(state.Accounts[0].Groups) != 1 || len(state.Accounts[0].Sudoers) != 1 {
		t.Fatalf("incomplete UNIX manifest %+v", state)
	}
	_, err = s.UnassignUnixGroup(ctx, admin, b.ID)
	must(err)
	state, err = s.Snapshot(ctx, node)
	must(err)
	if len(state.Accounts) != 1 || state.Accounts[0].Enabled || len(state.Accounts[0].Sudoers) > 0 || len(state.Accounts[0].Groups) > 0 {
		t.Fatal("revoked group access retained grants")
	}
	if _, err = s.SaveUnixGroup(ctx, admin, application.UnixGroup{ID: g.ID, Name: "changed", GID: g.GID}); err == nil {
		t.Fatal("native group identity changed silently")
	}
	token, err := s.CreateJoinToken(ctx, admin, groups[0].ID, 2, time.Hour)
	must(err)
	for i := 0; i < 2; i++ {
		_, err = s.Enroll(ctx, token, "repeat", "456", time.Now().Add(time.Hour), uuid.NewString())
		must(err)
	}
	if _, err = s.Enroll(ctx, token, "too-many", "789", time.Now().Add(time.Hour), uuid.NewString()); err == nil {
		t.Fatal("join use limit bypassed")
	}
	fresh, err := s.CreateJoinToken(ctx, admin, groups[0].ID, 10, time.Hour)
	must(err)
	tokens, err := s.JoinTokens(ctx, admin)
	must(err)
	var target string
	for _, tok := range tokens {
		if tok.MaxUses == 10 {
			target = tok.ID
		}
	}
	must(s.RevokeJoinToken(ctx, admin, target))
	if _, err = s.Enroll(ctx, fresh, "revoked", "789", time.Now().Add(time.Hour), uuid.NewString()); err == nil {
		t.Fatal("revoked join token used")
	}
	_, err = s.SaveUserGroup(ctx, admin, application.UserGroup{ID: uuid.NewString(), Name: "Hardware only", MFAPolicy: "none", RequireSK: true, Members: []string{u.ID}})
	must(err)
	required, err := s.RequireSK(ctx, u.ID)
	must(err)
	if !required {
		t.Fatal("group SK policy not inherited")
	}
}

func TestMandatoryLabelsAndAnnouncements(t *testing.T) {
	ctx, s, p, join := isolatedStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	groups, err := s.Groups(ctx, p)
	must(err)
	g := groups[0]
	u, _, err := s.CreateUser(ctx, p, identity.User{SyncToNodes: true, Login: "clearance_test", Kind: "service"}, "")
	must(err)
	role := authorization.Role{ID: uuid.NewString(), Name: "Broad native access", LinuxAccess: true, AllowSSHKeys: true, Permissions: []string{"*"}}
	_, err = s.SaveRole(ctx, p, role)
	must(err)
	_, err = s.BindRole(ctx, p, authorization.Binding{UserID: u.ID, RoleID: role.ID, GroupID: "*"})
	must(err)
	node := uuid.NewString()
	_, err = s.Enroll(ctx, join, "label-test", "serial", time.Now().Add(time.Hour), node)
	must(err)
	label := authorization.SecurityLabel{Level: 2, Categories: []string{"production"}}
	_, err = s.SaveLabelPolicy(ctx, p, application.LabelPolicy{ResourceType: "node_group", ResourceID: g.ID, Label: label})
	must(err)
	snap, err := s.Snapshot(ctx, node)
	must(err)
	if len(snap.Accounts) != 1 || snap.Accounts[0].Enabled {
		t.Fatal("wildcard RBAC bypassed mandatory label")
	}
	_, err = s.SaveLabelPolicy(ctx, p, application.LabelPolicy{ResourceType: "user", ResourceID: u.ID, Label: authorization.SecurityLabel{Level: 3, Categories: []string{"production"}}})
	must(err)
	snap, err = s.Snapshot(ctx, node)
	must(err)
	if !snap.Accounts[0].Enabled {
		t.Fatal("matching clearance was denied")
	}
	_, err = s.SaveLabelPolicy(ctx, p, application.LabelPolicy{ResourceType: "user", ResourceID: u.ID, Label: authorization.SecurityLabel{Level: 3}})
	must(err)
	snap, err = s.Snapshot(ctx, node)
	must(err)
	if snap.Accounts[0].Enabled {
		t.Fatal("missing category allowed")
	}
	a := application.Announcement{ID: uuid.NewString(), Title: "Maintenance", Markdown: "**Planned** restart", Severity: "info", Enabled: true}
	_, err = s.SaveAnnouncement(ctx, p, a)
	must(err)
	announcements, err := s.Announcements(ctx, p, false)
	must(err)
	if len(announcements) != 1 {
		t.Fatal("active announcement missing")
	}
	a = announcements[0]
	a.Enabled = false
	_, err = s.SaveAnnouncement(ctx, p, a)
	must(err)
	if _, err = s.SaveAnnouncement(ctx, p, a); err == nil {
		t.Fatal("stale announcement overwrote newer edit")
	}
	announcements, err = s.Announcements(ctx, p, false)
	must(err)
	if len(announcements) != 0 {
		t.Fatal("disabled announcement still shown")
	}
}
