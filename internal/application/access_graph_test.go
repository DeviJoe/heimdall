package application

import (
	"Heimdall/internal/authorization"
	"testing"
)

func TestGraphRecommendationsRespectSubjectScopeAndNativeProjection(t *testing.T) {
	a := AccessConnection{ID: "a", SubjectID: "u", SubjectKind: "unix_group", GroupID: "parent", Ancestors: []string{"parent"}, Role: authorization.Role{ID: "r1", Name: "one", LinuxAccess: true, AllowSSHKeys: true, Permissions: []string{"users.manage"}}}
	b := a
	b.ID = "b"
	b.GroupID = "child"
	b.Ancestors = []string{"child", "parent"}
	b.Role.ID = "r2"
	b.Role.Name = "two"
	b.Role.AllowPassword = true
	r := AccessRecommendations([]AccessConnection{a, b})
	if len(r) != 1 || r[0].Kind != "overlap" || len(r[0].Common) != 1 || r[0].Common[0] != "unix.ssh_keys" {
		t.Fatalf("wrong intersection %+v", r)
	}
	b.SubjectID = "different"
	if len(AccessRecommendations([]AccessConnection{a, b})) != 0 {
		t.Fatal("invented group membership overlap")
	}
	b.SubjectID = a.SubjectID
	b.Ancestors = []string{"other"}
	b.GroupID = "other"
	if len(AccessRecommendations([]AccessConnection{a, b})) != 0 {
		t.Fatal("invented scope overlap")
	}
}
func TestGraphDetectsEqualRoleDefinitionsWithoutRenamingAssignments(t *testing.T) {
	a := AccessConnection{ID: "a", Role: authorization.Role{ID: "r1", Name: "A", Permissions: []string{"users.read", "nodes.read"}}}
	b := AccessConnection{ID: "b", Role: authorization.Role{ID: "r2", Name: "B", Permissions: []string{"nodes.read", "users.read"}}}
	r := AccessRecommendations([]AccessConnection{a, b})
	if len(r) != 1 || r[0].Kind != "duplicate_role" {
		t.Fatalf("duplicate missing %+v", r)
	}
	if a.Role.Permissions[0] != "users.read" {
		t.Fatal("analysis changed caller's role")
	}
}
