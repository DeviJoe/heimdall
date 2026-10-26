//go:build integration

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/credentials"
	"Heimdall/internal/platform/security"
	"Heimdall/internal/synchronization"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"
	"os"
	"testing"
	"time"
)

func TestTransactionalDirectoryAndRevocation(t *testing.T) {
	dsn := os.Getenv("HEIMDALL_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration database not configured")
	}
	c, err := pgxpool.ParseConfig(dsn)
	if err != nil || c.ConnConfig.Database != "linpam_test" {
		t.Fatal("integration test is restricted to database linpam_test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	store, err := New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(store.Migrate(ctx))
	_, err = store.Pool.Exec(ctx, "TRUNCATE users,server_groups,roles,system_state RESTART IDENTITY CASCADE")
	must(err)
	join := security.Random(32)
	must(store.Bootstrap(ctx, "Strong integration password", join))
	must(store.InitSettings(ctx, application.Settings{KeyTTLSeconds: 3600, StalledSeconds: 45, OfflineSeconds: 45, RevocationAlertSeconds: 20, SwaggerEnabled: true, MCPEnabled: true}))
	adminUser, err := store.Auth(ctx, "admin")
	must(err)
	admin, err := store.Principal(ctx, adminUser.User.ID, "", "api")
	must(err)
	source := []application.DirectoryUser{{Subject: "source-alice", Login: "directory_alice", DisplayName: "Alice"}, {Subject: "source-bob", Login: "directory_bob", DisplayName: "Bob"}}
	must(store.ImportDirectory(ctx, "ldap:test", source))
	alice, err := store.IdentityUser(ctx, "ldap:test", "source-alice")
	must(err)
	bob, err := store.IdentityUser(ctx, "ldap:test", "source-bob")
	must(err)
	var revision int64
	must(store.Pool.QueryRow(ctx, "SELECT revision FROM system_state").Scan(&revision))
	must(store.ImportDirectory(ctx, "ldap:test", source))
	var unchanged int64
	must(store.Pool.QueryRow(ctx, "SELECT revision FROM system_state").Scan(&unchanged))
	if revision != unchanged {
		t.Fatal("unchanged directory created a synchronization revision")
	}
	if store.ImportDirectory(ctx, "ldap:test", nil) == nil {
		t.Fatal("empty directory revoked users")
	}
	renamed := append([]application.DirectoryUser(nil), source...)
	renamed[0].Login = "renamed"
	if store.ImportDirectory(ctx, "ldap:test", renamed) == nil {
		t.Fatal("implicit directory rename was accepted")
	}
	groups, err := store.Groups(ctx, admin)
	must(err)
	roles, err := store.Roles(ctx)
	must(err)
	var linuxRole authorization.Role
	for _, r := range roles {
		if r.Name == "Linux user" {
			linuxRole = r
		}
	}
	linuxRole.AllowPassword = true
	_, err = store.SaveRole(ctx, admin, linuxRole)
	must(err)
	bob.SyncToNodes = true
	_, err = store.UpdateUser(ctx, admin, bob, false)
	must(err)
	_, err = store.BindRole(ctx, admin, authorization.Binding{UserID: bob.ID, RoleID: linuxRole.ID, GroupID: groups[0].ID})
	must(err)
	nodeID := uuid.NewString()
	_, err = store.Enroll(ctx, join, "transaction-test-node", "123", time.Now().Add(time.Hour), nodeID)
	must(err)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	pub, err := ssh.NewPublicKey(private.Public())
	must(err)
	canonical, fp, alg, err := credentials.Parse(string(ssh.MarshalAuthorizedKey(pub)), false)
	must(err)
	_, _, err = store.AddKey(ctx, admin, credentials.Key{UserID: bob.ID, Name: "test", PublicKey: canonical, Fingerprint: fp, Algorithm: alg, ExpiresAt: time.Now().Add(time.Hour)})
	must(err)
	linuxHash, err := security.LinuxHash("Strong Linux password")
	must(err)
	_, err = store.SetLinuxPassword(ctx, admin, bob.ID, linuxHash)
	must(err)
	bobPrincipal, err := store.Principal(ctx, bob.ID, "", "api")
	must(err)
	token, secret, err := store.CreateToken(ctx, bobPrincipal, Token{Name: "self", Scopes: []string{"self"}, Audiences: []string{"api"}, ExpiresAt: time.Now().Add(time.Hour)})
	must(err)
	must(store.ImportDirectory(ctx, "ldap:test", source[:1]))
	disabled, err := store.User(ctx, bob.ID)
	must(err)
	if disabled.Status != "disabled" {
		t.Fatal("missing directory user was not disabled")
	}
	if _, err = store.Bearer(ctx, secret, "api"); err == nil {
		t.Fatal("disabled user token remained usable")
	}
	var revoked bool
	must(store.Pool.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM api_tokens WHERE id=$1", token.ID).Scan(&revoked))
	if !revoked {
		t.Fatal("token not permanently revoked")
	}
	var hash string
	must(store.Pool.QueryRow(ctx, "SELECT linux_password_hash FROM users WHERE id=$1", bob.ID).Scan(&hash))
	if hash != "" {
		t.Fatal("Linux password not cleared")
	}
	state, err := store.SnapshotForAgent(ctx, nodeID, 0)
	must(err)
	if !state.Full || len(state.Accounts) != 1 || state.Accounts[0].Enabled || len(state.Accounts[0].Keys) > 0 {
		t.Fatalf("revocation snapshot invalid: %+v", state)
	}
	generation, err := store.ConnectNode(ctx, nodeID, "123")
	must(err)
	next, err := store.ConnectNode(ctx, nodeID, "123")
	must(err)
	result := synchronization.ApplyResult{Revision: state.Revision, Digest: "test", Results: []synchronization.ResourceResult{{UserID: bob.ID, Login: bob.Login, Status: "applied"}}}
	if store.ApplyResult(ctx, nodeID, generation, result) == nil {
		t.Fatal("old connection generation acknowledged state")
	}
	must(store.ApplyResult(ctx, nodeID, next, result))
	var outstanding int
	must(store.Pool.QueryRow(ctx, "SELECT count(*) FROM sync_targets WHERE node_id=$1 AND status<>'applied'", nodeID).Scan(&outstanding))
	if outstanding != 0 {
		t.Fatal("acknowledgement did not complete prior targets")
	}
	// A mutation rejected after changing state must roll back its revision and outbox.
	for _, r := range roles {
		if r.Name == "Administrator" {
			r.Permissions = []string{}
			if _, err = store.SaveRole(ctx, admin, r); err == nil {
				t.Fatal("removed last global administrator")
			}
		}
	}
	stillAdmin, err := store.Principal(ctx, admin.UserID, "", "api")
	must(err)
	if !stillAdmin.Allowed("*", "*") {
		t.Fatal("rejected role transaction leaked")
	}
	if current, err := store.IdentityUser(ctx, "ldap:test", "source-alice"); err != nil || current.ID != alice.ID {
		t.Fatal("stable directory identity changed")
	}
}
