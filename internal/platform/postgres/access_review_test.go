//go:build integration

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/identity"
	"errors"
	"github.com/google/uuid"
	"testing"
)

func TestUnixMembershipCannotBypassRoleAndSudoManagement(t *testing.T) {
	ctx, s, admin, _ := isolatedStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	groups, err := s.Groups(ctx, admin)
	must(err)
	privileged := authorization.Role{ID: uuid.NewString(), Name: "Restricted sudo", LinuxAccess: true, AllowSSHKeys: true, Sudoers: "ALL=(root) NOPASSWD: /usr/bin/id"}
	_, err = s.SaveRole(ctx, admin, privileged)
	must(err)
	unix := application.UnixGroup{ID: uuid.NewString(), Name: "privileged", GID: 24000}
	_, err = s.SaveUnixGroup(ctx, admin, unix)
	must(err)
	_, err = s.AssignUnixGroup(ctx, admin, application.UnixAssignment{UnixGroupID: unix.ID, RoleID: privileged.ID, GroupID: groups[0].ID})
	must(err)
	operator, _, err := s.CreateUser(ctx, admin, identity.User{Login: "directory_operator", Kind: "service"}, "")
	must(err)
	directoryRole := authorization.Role{ID: uuid.NewString(), Name: "Directory only", Permissions: []string{"users.manage", "users.read"}}
	_, err = s.SaveRole(ctx, admin, directoryRole)
	must(err)
	_, err = s.BindRole(ctx, admin, authorization.Binding{UserID: operator.ID, RoleID: directoryRole.ID, GroupID: "*"})
	must(err)
	p, err := s.Principal(ctx, operator.ID, "", "api")
	must(err)
	target, _, err := s.CreateUser(ctx, admin, identity.User{Login: "target_user", Kind: "service"}, "")
	must(err)
	if _, err = s.UpdateUnixMembers(ctx, p, unix.ID, []string{target.ID}, nil); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("supplementary escalation allowed: %v", err)
	}
	unix.Members = []string{target.ID}
	if _, err = s.SaveUnixGroup(ctx, p, unix); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("replacement escalation allowed: %v", err)
	}
	if _, _, err = s.CreateUser(ctx, p, identity.User{Login: "primary_attack", Kind: "service", GID: unix.GID}, ""); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("primary create escalation allowed: %v", err)
	}
	target.GID = unix.GID
	if _, err = s.UpdateUser(ctx, p, target, false); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("primary update escalation allowed: %v", err)
	}
	_, err = s.UpdateUnixMembers(ctx, admin, unix.ID, []string{target.ID}, nil)
	must(err)
	graph, _, err := s.AccessGraph(ctx, admin, application.PageQuery{Limit: 1, Search: "Restricted sudo"})
	must(err)
	if len(graph.Connections) != 1 || graph.Connections[0].SubjectKind != "unix_group" {
		t.Fatalf("wrong graph %+v", graph)
	}
	if _, _, err = s.AccessGraph(ctx, p, application.PageQuery{}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("directory-only principal saw role graph")
	}
	if _, err = s.ReadPage(ctx, p, "roles", application.PageQuery{Status: "unix"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("role kind filter bypassed read authorization")
	}
	manager := authorization.Role{ID: uuid.NewString(), Name: "Scoped assignments manager", Permissions: []string{"roles.manage"}}
	_, err = s.SaveRole(ctx, admin, manager)
	must(err)
	_, err = s.BindRole(ctx, admin, authorization.Binding{UserID: operator.ID, RoleID: manager.ID, GroupID: groups[0].ID})
	must(err)
	p, err = s.Principal(ctx, operator.ID, "", "api")
	must(err)
	page, err := s.ReadPage(ctx, p, "unix-assignments", application.PageQuery{})
	must(err)
	if len(page.Items) != 1 {
		t.Fatalf("scoped manager cannot inspect assigned scope: %+v", page)
	}
	if _, err = s.ReadPage(ctx, p, "roles", application.PageQuery{Status: "unix"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("scoped manager exposed global role definitions")
	}
}
