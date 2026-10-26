//go:build integration

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/identity"
	"Heimdall/internal/platform/security"
	"github.com/google/uuid"
	"testing"
)

func TestRequiredTOTPEnrollmentAfterPasskeyPreservesBothFactors(t *testing.T) {
	ctx, s, admin, _ := isolatedStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	u, _, err := s.CreateUser(ctx, admin, identity.User{Login: "two_factors", DisplayName: "Two independent factors"}, security.HashToken("factor-invite"))
	must(err)
	_, err = s.AcceptInvite(ctx, "factor-invite", "fixture-password-hash")
	must(err)
	_, err = s.SaveUserGroup(ctx, admin, application.UserGroup{ID: uuid.NewString(), Name: "TOTP required", MFAPolicy: "totp", Members: []string{u.ID}})
	must(err)
	recovery := []string{}
	for i := 0; i < 10; i++ {
		recovery = append(recovery, security.HashToken(security.Random(32)))
	}
	must(s.EnableWebAuthn(ctx, u.ID, "fixture-passkey", []byte(`{"id":"fixture-passkey"}`), recovery))
	p, err := s.Principal(ctx, u.ID, "", "api")
	must(err)
	if !p.Restricted {
		t.Fatal("passkey bypassed the required TOTP registration")
	}
	must(s.EnableTOTP(ctx, u.ID, "fixture-encrypted-totp", recovery))
	p, err = s.Principal(ctx, u.ID, "", "api")
	must(err)
	if p.Restricted {
		t.Fatal("completed TOTP registration still restricts access")
	}
	user, err := s.User(ctx, u.ID)
	must(err)
	if !user.TOTPEnabled || user.PasskeyCount != 1 {
		t.Fatal("independent enrollment did not retain both factors")
	}
	if err = s.EnableTOTP(ctx, u.ID, "replacement-secret", recovery); err == nil {
		t.Fatal("existing TOTP was overwritten")
	}
	var secret string
	var version int64
	must(s.Pool.QueryRow(ctx, "SELECT totp_secret,auth_version FROM users WHERE id=$1", u.ID).Scan(&secret, &version))
	if secret != "fixture-encrypted-totp" || version != user.AuthVersion {
		t.Fatal("rejected replacement changed credentials or invalidated sessions")
	}
	keys, err := s.WebAuthnCredentials(ctx, u.ID)
	must(err)
	if len(keys) != 1 {
		t.Fatal("TOTP replacement removed an existing passkey")
	}
}
