package authorization

import "testing"

func TestScopesAndGroupIntersection(t *testing.T) {
	p := Principal{UserID: "alice", TokenID: "token", TokenScopes: []string{"nodes.read"}, TokenGroups: []string{"prod"}, Bindings: []Binding{{GroupID: "*", Role: Role{Permissions: []string{"*"}}}}}
	if !p.Allowed("nodes.read", "prod") {
		t.Fatal("valid intersection rejected")
	}
	for _, v := range []struct{ permission, group string }{{"nodes.manage", "prod"}, {"nodes.read", "dev"}, {"nodes.read", "*"}} {
		if p.Allowed(v.permission, v.group) {
			t.Fatalf("privilege escalated: %+v", v)
		}
	}
	if p.Self("alice") {
		t.Fatal("read-only token acquired self-service permissions")
	}
	p.Restricted = true
	if p.Allowed("nodes.read", "prod") {
		t.Fatal("MFA restriction bypassed")
	}
}
func TestSudoValidationRejectsInjection(t *testing.T) {
	for _, command := range []string{"ALL", "/bin/id\nroot ALL=ALL", "/usr/bin/../bin/bash", "/usr/bin/*"} {
		if (Role{Name: "Operator", LinuxAccess: true, Sudo: []SudoRule{{Command: command, RunAs: "root"}}}).Validate() == nil {
			t.Fatalf("unsafe command accepted: %q", command)
		}
	}
	if (Role{Name: "Operator", LinuxAccess: true, Sudo: []SudoRule{{Command: "/usr/bin/id", RunAs: "root", Arguments: []string{"a,b"}}}}).Validate() == nil {
		t.Fatal("sudo argument separator accepted")
	}
}
