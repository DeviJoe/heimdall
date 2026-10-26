//go:build integration

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/identity"
	"Heimdall/internal/platform/security"
	"errors"
	"github.com/google/uuid"
	"testing"
)

func TestLastAdministratorProtectedAcrossAssignmentSources(t *testing.T) {
	for _, source := range []string{"direct", "people_group"} {
		t.Run(source, func(t *testing.T) {
			ctx, s, admin, _ := isolatedStore(t)
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			operator, _, err := s.CreateUser(ctx, admin, identity.User{Login: "role_operator", Kind: "service"}, "")
			must(err)
			manager := authorization.Role{ID: uuid.NewString(), Name: "Role manager", Permissions: []string{"roles.manage"}}
			_, err = s.SaveRole(ctx, admin, manager)
			must(err)
			_, err = s.BindRole(ctx, admin, authorization.Binding{UserID: operator.ID, RoleID: manager.ID, GroupID: "*"})
			must(err)
			p, err := s.Principal(ctx, operator.ID, "", "api")
			must(err)
			var original, adminRole string
			must(s.Pool.QueryRow(ctx, "SELECT id,role_id FROM role_bindings WHERE user_id=$1 AND group_id='*'", admin.UserID).Scan(&original, &adminRole))
			if _, err = s.UnbindRole(ctx, p, original); err == nil {
				t.Fatal("last administrator's direct assignment removed")
			}
			second, _, err := s.CreateUser(ctx, admin, identity.User{Login: "second_admin", Kind: "human"}, security.HashToken("second-invite"))
			must(err)
			_, err = s.AcceptInvite(ctx, "second-invite", "fixture-password-hash")
			must(err)
			var binding, group string
			if source == "direct" {
				_, err = s.BindRole(ctx, admin, authorization.Binding{UserID: second.ID, RoleID: adminRole, GroupID: "*"})
				must(err)
				must(s.Pool.QueryRow(ctx, "SELECT id FROM role_bindings WHERE user_id=$1", second.ID).Scan(&binding))
			} else {
				group = uuid.NewString()
				_, err = s.SaveUserGroup(ctx, admin, application.UserGroup{ID: group, Name: "Administrators", MFAPolicy: "none", Members: []string{second.ID}})
				must(err)
				_, err = s.BindUserGroupRole(ctx, admin, group, authorization.Binding{RoleID: adminRole, GroupID: "*"})
				must(err)
				must(s.Pool.QueryRow(ctx, "SELECT id FROM user_group_role_bindings WHERE user_group_id=$1", group).Scan(&binding))
			}
			// A confirmed removal of one's own assignment is safe while another
			// real administrator remains, including one reached through a group.
			_, err = s.UnbindRole(ctx, admin, original)
			must(err)
			if source == "direct" {
				_, err = s.UnbindRole(ctx, p, binding)
			} else {
				_, err = s.UnbindUserGroupRole(ctx, p, group, binding)
			}
			if err == nil {
				t.Fatal("last administrator removed through " + source)
			}
			remaining, err := s.Principal(ctx, second.ID, "", "api")
			must(err)
			if !remaining.Allowed("*", "*") {
				t.Fatal("rejected revocation changed effective administrator rights")
			}
			var audits int
			must(s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action IN('role.unbind','user_group.unbind')", binding).Scan(&audits))
			if audits != 0 {
				t.Fatal("rejected revocation wrote a success audit")
			}
		})
	}
}

func TestSudoManagementCannotBeBypassedByRemovingRulesOrAssignments(t *testing.T) {
	ctx, s, admin, _ := isolatedStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	groups, err := s.Groups(ctx, admin)
	must(err)
	role := authorization.Role{ID: uuid.NewString(), Name: "Sudo access", LinuxAccess: true, AllowSSHKeys: true, Sudoers: "ALL=(root) NOPASSWD: /usr/bin/id"}
	_, err = s.SaveRole(ctx, admin, role)
	must(err)
	operator, _, err := s.CreateUser(ctx, admin, identity.User{Login: "role_operator", Kind: "service"}, "")
	must(err)
	manager := authorization.Role{ID: uuid.NewString(), Name: "Role manager", Permissions: []string{"roles.manage", "users.manage", "users.read"}}
	_, err = s.SaveRole(ctx, admin, manager)
	must(err)
	_, err = s.BindRole(ctx, admin, authorization.Binding{UserID: operator.ID, RoleID: manager.ID, GroupID: "*"})
	must(err)
	target, _, err := s.CreateUser(ctx, admin, identity.User{Login: "target_user", Kind: "service"}, "")
	must(err)
	_, err = s.BindRole(ctx, admin, authorization.Binding{UserID: target.ID, RoleID: role.ID, GroupID: groups[0].ID})
	must(err)
	var direct string
	must(s.Pool.QueryRow(ctx, "SELECT id FROM role_bindings WHERE user_id=$1", target.ID).Scan(&direct))
	people := application.UserGroup{ID: uuid.NewString(), Name: "Sudo people", MFAPolicy: "none", Members: []string{target.ID}}
	_, err = s.SaveUserGroup(ctx, admin, people)
	must(err)
	_, err = s.BindUserGroupRole(ctx, admin, people.ID, authorization.Binding{RoleID: role.ID, GroupID: groups[0].ID})
	must(err)
	var peopleBinding string
	must(s.Pool.QueryRow(ctx, "SELECT id FROM user_group_role_bindings WHERE user_group_id=$1", people.ID).Scan(&peopleBinding))
	unix := application.UnixGroup{ID: uuid.NewString(), Name: "sudo_team", GID: 24000}
	_, err = s.SaveUnixGroup(ctx, admin, unix)
	must(err)
	assignment := application.UnixAssignment{ID: uuid.NewString(), UnixGroupID: unix.ID, RoleID: role.ID, GroupID: groups[0].ID}
	_, err = s.AssignUnixGroup(ctx, admin, assignment)
	must(err)
	p, err := s.Principal(ctx, operator.ID, "", "api")
	must(err)
	withoutSudo := role
	withoutSudo.Sudoers = ""
	if _, err = s.SaveRole(ctx, p, withoutSudo); !errors.Is(err, ErrForbidden) {
		t.Fatalf("sudo removal bypass: %v", err)
	}
	if _, err = s.DeleteUserGroup(ctx, p, people.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("group deletion bypassed sudo management: %v", err)
	}
	for name, revoke := range map[string]func(authorization.Principal) (string, error){
		"direct": func(p authorization.Principal) (string, error) { return s.UnbindRole(ctx, p, direct) },
		"people": func(p authorization.Principal) (string, error) {
			return s.UnbindUserGroupRole(ctx, p, people.ID, peopleBinding)
		},
		"unix": func(p authorization.Principal) (string, error) { return s.UnassignUnixGroup(ctx, p, assignment.ID) },
	} {
		if _, err = revoke(p); !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s sudo revocation bypass: %v", name, err)
		}
		_, err = revoke(admin)
		must(err)
	}
	_, err = s.SaveRole(ctx, admin, withoutSudo)
	must(err)
}
