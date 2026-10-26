//go:build integration

package postgres

import (
	"Heimdall/internal/identity"
	"Heimdall/internal/platform/security"
	"testing"
)

func TestMandatoryTOTPReplacementIsAtomicAndVersioned(t *testing.T) {
	ctx, s, admin, _ := isolatedStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	u, _, err := s.CreateUser(ctx, admin, identity.User{Login: "rotate_totp", MFAPolicy: "totp"}, security.HashToken("rotate-invite"))
	must(err)
	_, err = s.AcceptInvite(ctx, "rotate-invite", "fixture-hash")
	must(err)
	recovery := func() []string {
		out := make([]string, 10)
		for i := range out {
			out[i] = security.HashToken(security.Random(32))
		}
		return out
	}
	oldCodes := recovery()
	must(s.EnableTOTP(ctx, u.ID, "encrypted-old", oldCodes))
	before, err := s.User(ctx, u.ID)
	must(err)
	if err = s.RotateTOTP(ctx, u.ID, before.AuthVersion-1, "encrypted-new", recovery()); err == nil {
		t.Fatal("stale replacement accepted")
	}
	unchanged, err := s.Auth(ctx, u.Login)
	must(err)
	if unchanged.TOTPSecret != "encrypted-old" {
		t.Fatal("failed replacement removed old factor")
	}
	newCodes := recovery()
	must(s.RotateTOTP(ctx, u.ID, before.AuthVersion, "encrypted-new", newCodes))
	after, err := s.Auth(ctx, u.Login)
	must(err)
	if after.TOTPSecret != "encrypted-new" || after.User.AuthVersion != before.AuthVersion+1 {
		t.Fatal("replacement failed to invalidate existing sessions")
	}
	principal, err := s.Principal(ctx, u.ID, "", "api")
	must(err)
	if principal.Restricted {
		t.Fatal("rotation weakened or violated mandatory enrollment")
	}
	var old int
	must(s.Pool.QueryRow(ctx, "SELECT count(*) FROM recovery_codes WHERE user_id=$1 AND hash=ANY($2::text[])", u.ID, oldCodes).Scan(&old))
	if old != 0 {
		t.Fatal("old recovery codes retained")
	}
	if err = s.RotateTOTP(ctx, u.ID, before.AuthVersion, "encrypted-racing", recovery()); err == nil {
		t.Fatal("concurrent replacement overwrote committed factor")
	}
}
