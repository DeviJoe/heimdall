//go:build integration

package postgres

import (
	"Heimdall/internal/authorization"
	"Heimdall/internal/identity"
	"Heimdall/internal/platform/security"
	"errors"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestNativeProvisioningAndPasswordAreExplicit(t *testing.T) {
	ctx, s, admin, join := isolatedStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	u, _, err := s.CreateUser(ctx, admin, identity.User{Login: "policy_service", Kind: "service"}, "")
	must(err)
	role := authorization.Role{ID: uuid.NewString(), Name: "Native keys", Permissions: []string{}, LinuxAccess: true, AllowSSHKeys: true}
	_, err = s.SaveRole(ctx, admin, role)
	must(err)
	groups, err := s.Groups(ctx, admin)
	must(err)
	_, err = s.BindRole(ctx, admin, authorization.Binding{UserID: u.ID, RoleID: role.ID, GroupID: groups[0].ID})
	must(err)
	node := uuid.NewString()
	_, err = s.Enroll(ctx, join, "policy-node", "serial", time.Now().Add(time.Hour), node)
	must(err)
	snapshot, err := s.Snapshot(ctx, node)
	must(err)
	if len(snapshot.Accounts) != 0 {
		t.Fatal("role implicitly provisioned disabled UNIX profile")
	}
	hash, err := security.LinuxHash("fixture-password")
	must(err)
	if _, err = s.SetLinuxPassword(ctx, admin, u.ID, hash); !errors.Is(err, ErrForbidden) {
		t.Fatal("password provisioned despite default deny")
	}
	u.SyncToNodes = true
	_, err = s.UpdateUser(ctx, admin, u, false)
	must(err)
	snapshot, err = s.Snapshot(ctx, node)
	must(err)
	if len(snapshot.Accounts) != 1 || !snapshot.Accounts[0].Enabled || snapshot.Accounts[0].AllowPassword || snapshot.Accounts[0].PasswordHash != "" {
		t.Fatal("key-only manifest inconsistent")
	}
	if _, err = s.SetLinuxPassword(ctx, admin, u.ID, hash); !errors.Is(err, ErrForbidden) {
		t.Fatal("key-only role enabled UNIX password")
	}
	role.AllowPassword = true
	_, err = s.SaveRole(ctx, admin, role)
	must(err)
	_, err = s.SetLinuxPassword(ctx, admin, u.ID, hash)
	must(err)
	snapshot, err = s.Snapshot(ctx, node)
	must(err)
	if !snapshot.Accounts[0].AllowPassword || snapshot.Accounts[0].PasswordHash != hash {
		t.Fatal("explicit password grant missing")
	}
	u.SyncToNodes = false
	_, err = s.UpdateUser(ctx, admin, u, false)
	must(err)
	snapshot, err = s.Snapshot(ctx, node)
	must(err)
	if len(snapshot.Accounts) != 1 || snapshot.Accounts[0].Enabled || snapshot.Accounts[0].PasswordHash != "" || snapshot.Accounts[0].AllowSSHKeys {
		t.Fatal("sync flag failed to revoke existing native identity")
	}
}
