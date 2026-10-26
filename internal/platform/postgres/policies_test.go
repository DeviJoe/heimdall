//go:build integration

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/fleet"
	"Heimdall/internal/identity"
	"Heimdall/internal/platform/security"
	"Heimdall/internal/synchronization"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestPoliciesHierarchyAndServiceInventory(t *testing.T) {
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
	parent.ParentID = child.ID
	if _, err = s.SaveGroup(ctx, admin, parent); err == nil {
		t.Fatal("group cycle accepted")
	}
	parent.ParentID = ""
	role := authorization.Role{ID: uuid.NewString(), Name: "Automation", LinuxAccess: true, AllowSSHKeys: true, Permissions: []string{"inventory.read"}}
	_, err = s.SaveRole(ctx, admin, role)
	must(err)
	service, _, err := s.CreateUser(ctx, admin, identity.User{SyncToNodes: true, Login: "automation", DisplayName: "Automation", Kind: "service"}, "")
	must(err)
	_, err = s.BindRole(ctx, admin, authorization.Binding{UserID: service.ID, RoleID: role.ID, GroupID: parent.ID})
	must(err)
	node := uuid.NewString()
	_, err = s.EnrollBound(ctx, join, "ssh.internal", "123", time.Now().Add(time.Hour), node, security.HashToken("root-nonce"))
	must(err)
	manifest, err := s.Snapshot(ctx, node)
	must(err)
	if manifest.BootstrapNonce != security.HashToken("root-nonce") || manifest.BootstrapTokenHash != security.HashToken(join) {
		t.Fatal("enrollment binding missing from signed state projection")
	}
	services, _, err := s.FilterUsersPage(ctx, admin, 100, "", "auto", "service")
	must(err)
	if len(services) != 1 || services[0].ID != service.ID {
		t.Fatal("service owner filter failed")
	}
	_, err = s.MoveNodes(ctx, admin, []string{node}, child.ID)
	must(err)
	_, secret, err := s.CreateToken(ctx, admin, application.Token{UserID: service.ID, Name: "inventory", Audiences: []string{"api"}, Scopes: []string{"inventory.read"}, Groups: []string{child.ID}, ExpiresAt: time.Now().Add(time.Hour)})
	must(err)
	p, err := s.Bearer(ctx, secret, "api")
	must(err)
	hosts, err := s.Inventory(ctx, p)
	must(err)
	if len(hosts) != 1 || hosts[0].Login != "automation" {
		t.Fatalf("inventory %+v", hosts)
	}
	if _, err = s.Auth(ctx, "automation"); err == nil {
		t.Fatal("service account accepted interactive authentication")
	}
	human, _, err := s.CreateUser(ctx, admin, identity.User{SyncToNodes: true, Login: "engineer", DisplayName: "Engineer"}, security.HashToken("invite"))
	must(err)
	_, err = s.AcceptInvite(ctx, "invite", "test-password-hash")
	must(err)
	group := application.UserGroup{ID: uuid.NewString(), Name: "Engineering", MFAPolicy: "passkey", Members: []string{human.ID}}
	_, err = s.SaveUserGroup(ctx, admin, group)
	must(err)
	_, err = s.BindUserGroupRole(ctx, admin, group.ID, authorization.Binding{RoleID: role.ID, GroupID: parent.ID})
	must(err)
	hp, err := s.Principal(ctx, human.ID, "", "api")
	must(err)
	if !hp.Restricted {
		t.Fatal("passkey enrollment policy bypassed")
	}
	recovery := []string{}
	for i := 0; i < 10; i++ {
		recovery = append(recovery, security.HashToken(security.Random(32)))
	}
	must(s.EnableTOTP(ctx, human.ID, "encrypted-secret", recovery))
	hp, err = s.Principal(ctx, human.ID, "", "api")
	must(err)
	if !hp.Restricted {
		t.Fatal("TOTP satisfied mandatory passkey policy")
	}
	must(s.EnableWebAuthn(ctx, human.ID, "test-credential", []byte(`{"id":"test"}`), recovery))
	hp, err = s.Principal(ctx, human.ID, "", "api")
	must(err)
	if hp.Restricted || !hp.Allowed("inventory.read", child.ID) {
		t.Fatal("enrolled group member lost inherited role")
	}
	bindings, err := s.UserGroupBindings(ctx, admin, group.ID)
	must(err)
	if len(bindings) != 1 {
		t.Fatal("group role not visible")
	}
	_, err = s.UnbindUserGroupRole(ctx, admin, group.ID, bindings[0].ID)
	must(err)
	hp, err = s.Principal(ctx, human.ID, "", "api")
	must(err)
	if hp.Allowed("inventory.read", child.ID) {
		t.Fatal("removed user group role retained access")
	}
	v, err := s.Settings(ctx)
	must(err)
	_, err = s.SaveSettings(ctx, admin, v)
	must(err)
	if _, err = s.SaveSettings(ctx, admin, v); err == nil {
		t.Fatal("stale settings version overwrote change")
	}
	_, err = s.SetUserStatus(ctx, admin, service.ID, "disabled")
	must(err)
	if _, err = s.Bearer(ctx, secret, "api"); err == nil {
		t.Fatal("disabled service token stayed valid")
	}
}
func TestActivityAcknowledgementAndHeartbeatMonitoring(t *testing.T) {
	ctx, s, admin, join := isolatedStore(t)
	node := uuid.NewString()
	if _, err := s.EnrollBound(ctx, join, "activity.internal", "123", time.Now().Add(time.Hour), node, security.HashToken("activity-root")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, "UPDATE nodes SET applied_revision=desired_revision,status='in_sync',last_seen=now()-interval '2 minutes' WHERE id=$1", node); err != nil {
		t.Fatal(err)
	}
	state, err := s.Metrics(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if state.Connectivity["offline"] != 1 || state.Pending != 0 {
		t.Fatalf("lost synchronized node is hidden: %+v", state)
	}
	if err = s.Detect(ctx, 45*time.Second, 45*time.Second, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	incidents, err := s.Incidents(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 1 || incidents[0].Kind != "node_offline" {
		t.Fatalf("lost node incident missing: %+v", incidents)
	}
	if s.ResolveActivityIncident(ctx, admin, incidents[0].ID) == nil {
		t.Fatal("manual resolution hid an offline node")
	}
	event := synchronization.ActivityEvent{ID: security.HashToken("activity-event"), Login: "outside", Address: "192.0.2.10", Kind: "unmanaged_login", Severity: "warning", ObservedAt: time.Now()}
	for i := 0; i < 2; i++ {
		ids, err := s.RecordActivity(ctx, node, "123", []synchronization.ActivityEvent{event})
		if err != nil || len(ids) != 1 {
			t.Fatal("event not durably acknowledged", err)
		}
	}
	events, err := s.SecurityEvents(ctx, admin)
	if err != nil || len(events) != 1 {
		t.Fatal("event deduplication failed", err)
	}
	incidents, err = s.Incidents(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	for _, incident := range incidents {
		if incident.Kind == "unmanaged_login" {
			if err = s.ResolveActivityIncident(ctx, admin, incident.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	var count int
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='incident.resolve'").Scan(&count); err != nil || count != 1 {
		t.Fatal("resolution audit missing", err)
	}
}

func TestTransportDisableDoesNotInventAnUnconfirmedNativeChange(t *testing.T) {
	ctx, s, admin, join := isolatedStore(t)
	node := uuid.NewString()
	if _, err := s.Enroll(ctx, join, "transport.internal", "123", time.Now().Add(time.Hour), node); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, "UPDATE nodes SET applied_revision=desired_revision,status='in_sync',last_seen=now() WHERE id=$1", node); err != nil {
		t.Fatal(err)
	}
	groups, err := s.Groups(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SetNode(ctx, admin, node, groups[0].ID, true); err != nil {
		t.Fatal(err)
	}
	var desired, applied int64
	if err = s.Pool.QueryRow(ctx, "SELECT desired_revision,applied_revision FROM nodes WHERE id=$1", node).Scan(&desired, &applied); err != nil || desired != applied {
		t.Fatalf("transport disable invented pending native change: %d/%d %v", desired, applied, err)
	}
	if _, err = s.SetNode(ctx, admin, node, groups[0].ID, false); err != nil {
		t.Fatal(err)
	}
	if err = s.Pool.QueryRow(ctx, "SELECT desired_revision,applied_revision FROM nodes WHERE id=$1", node).Scan(&desired, &applied); err != nil || desired <= applied {
		t.Fatal("reenablement must resynchronize", err)
	}
	if _, err = s.SetNode(ctx, admin, node, groups[0].ID, true); err != nil {
		t.Fatal(err)
	}
	var stillApplied int64
	if err = s.Pool.QueryRow(ctx, "SELECT applied_revision FROM nodes WHERE id=$1", node).Scan(&stillApplied); err != nil || stillApplied != applied {
		t.Fatal("disable fabricated native acknowledgement", err)
	}
}
