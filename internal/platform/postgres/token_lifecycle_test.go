//go:build integration

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/platform/security"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestExpiredTokensAreHiddenRevokedAndAuditedOnce(t *testing.T) {
	ctx, s, admin, _ := isolatedStore(t)
	groups, err := s.Groups(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.CreateNamedJoinToken(ctx, admin, groups[0].ID, "  Build fleet  ", 0, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var joinID, name string
	if err = s.Pool.QueryRow(ctx, "SELECT id,name FROM join_tokens WHERE hash=$1", security.HashToken(secret)).Scan(&joinID, &name); err != nil || name != "Build fleet" {
		t.Fatalf("optional name was not preserved: %q, %v", name, err)
	}
	token, apiSecret, err := s.CreateToken(ctx, admin, application.Token{Name: "CI inventory", Audiences: []string{"api"}, Scopes: []string{"inventory.read"}, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for _, resource := range []struct{ table, id string }{{"join_tokens", joinID}, {"api_tokens", token.ID}} {
		if _, err = s.Pool.Exec(ctx, "UPDATE "+resource.table+" SET expires_at=now()-interval '1 second' WHERE id=$1", resource.id); err != nil {
			t.Fatal(err)
		}
	}
	// Expiry is enforced on authorization and list reads even before cleanup runs.
	if _, err = s.Enroll(ctx, secret, "expired", "serial", time.Now().Add(time.Hour), uuid.NewString()); err == nil {
		t.Fatal("expired join token still authorized enrollment")
	}
	if _, err = s.Bearer(ctx, apiSecret, "api"); err == nil {
		t.Fatal("expired API token still authorized access")
	}
	for _, collection := range []string{"join-tokens", "tokens"} {
		page, readErr := s.ReadPage(ctx, admin, collection, application.PageQuery{})
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, item := range page.Items {
			if strings.Contains(string(item), joinID) || strings.Contains(string(item), token.ID) {
				t.Fatal("expired token leaked into active list")
			}
		}
	}
	for i := 0; i < 2; i++ {
		if err = s.Detect(ctx, time.Minute, time.Minute, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM join_tokens WHERE id=$1", joinID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("expired join token not removed: %d, %v", count, err)
	}
	var revoked bool
	if err = s.Pool.QueryRow(ctx, "SELECT revoked_at IS NOT NULL FROM api_tokens WHERE id=$1", token.ID).Scan(&revoked); err != nil || !revoked {
		t.Fatalf("expired API token not revoked: %v", err)
	}
	for _, resource := range []struct{ action, id string }{{"join_token.expired", joinID}, {"api_token.expired", token.ID}} {
		if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action=$1 AND resource_id LIKE '%'||$2", resource.action, resource.id).Scan(&count); err != nil || count != 1 {
			t.Fatalf("expiry must be audited once: %s, count=%d, %v", resource.action, count, err)
		}
	}
}
