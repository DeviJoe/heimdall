//go:build integration

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/identity"
	"Heimdall/internal/platform/security"
	"fmt"
	"testing"
)

func TestFactorRemovalRespectsTheEffectiveMinimumAndRollsBack(t *testing.T) {
	ctx, s, admin, _ := isolatedStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, tc := range []struct {
		name, direct, group, personal, remove string
		passkeys                              int
		allowed                               bool
	}{
		{"optional TOTP", "none", "none", "none", "totp", 1, true},
		{"either with passkey remaining", "any", "none", "none", "totp", 1, true},
		{"mandatory TOTP", "totp", "none", "none", "totp", 1, false},
		{"optional passkey with TOTP remaining", "totp", "none", "none", "key", 1, true},
		{"last required passkey", "passkey", "none", "none", "key", 1, false},
		{"one of two passkeys", "passkey", "none", "none", "key", 2, true},
		{"direct and group intersect", "totp", "passkey", "none", "key", 1, false},
		{"both required TOTP", "both", "none", "any", "totp", 1, false},
		{"both required passkey", "both", "none", "none", "key", 1, false},
		{"personal requirement", "none", "none", "both", "totp", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, _, err := s.CreateUser(ctx, admin, identity.User{Login: fmt.Sprintf("factor_case_%d", i), DisplayName: tc.name, MFAPolicy: tc.direct}, security.HashToken(fmt.Sprintf("invite-%d", i)))
			must(err)
			_, err = s.AcceptInvite(ctx, fmt.Sprintf("invite-%d", i), "fixture-password-hash")
			must(err)
			if tc.group != "none" {
				_, err = s.SaveUserGroup(ctx, admin, application.UserGroup{Name: fmt.Sprintf("Factor minimum %d", i), MFAPolicy: tc.group, Members: []string{u.ID}})
				must(err)
			}
			recovery := make([]string, 10)
			for j := range recovery {
				recovery[j] = security.HashToken(security.Random(32))
			}
			must(s.EnableTOTP(ctx, u.ID, "fixture-encrypted-secret", recovery))
			key := fmt.Sprintf("fixture-key-%d", i)
			for j := 0; j < tc.passkeys; j++ {
				must(s.EnableWebAuthn(ctx, u.ID, fmt.Sprintf("%s-%d", key, j), []byte(`{"fixture":true}`), recovery))
			}
			p, err := s.Principal(ctx, u.ID, "", "api")
			must(err)
			_, err = s.SetPersonalFactorPolicy(ctx, p, tc.personal)
			must(err)
			p, err = s.Principal(ctx, u.ID, "", "api")
			must(err)
			state, err := s.FactorState(ctx, u.ID)
			must(err)
			if !state.Satisfied(true, tc.passkeys > 0) {
				t.Fatal("fixture does not meet minimum")
			}
			before, err := s.User(ctx, u.ID)
			must(err)
			var rev int64
			must(s.Pool.QueryRow(ctx, "SELECT revision FROM system_state WHERE id=true").Scan(&rev))
			remove := tc.remove
			if remove == "key" {
				remove = key + "-0"
			}
			_, err = s.RemoveFactor(ctx, p, u.ID, remove)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v, error=%v", tc.allowed, err)
			}
			after, e := s.User(ctx, u.ID)
			must(e)
			var afterRev int64
			var recoveryCount int
			must(s.Pool.QueryRow(ctx, "SELECT revision FROM system_state WHERE id=true").Scan(&afterRev))
			must(s.Pool.QueryRow(ctx, "SELECT count(*) FROM recovery_codes WHERE user_id=$1", u.ID).Scan(&recoveryCount))
			if !tc.allowed && (after.AuthVersion != before.AuthVersion || after.TOTPEnabled != before.TOTPEnabled || after.PasskeyCount != before.PasskeyCount || afterRev != rev || recoveryCount != 10) {
				t.Fatal("rejected removal did not roll back credentials, sessions, recovery codes and synchronization")
			}
			if tc.allowed && (after.AuthVersion != before.AuthVersion+1 || (remove == "totp" && after.TOTPEnabled) || (remove != "totp" && after.PasskeyCount != before.PasskeyCount-1)) {
				t.Fatal("optional factor was not removed")
			}
		})
	}
}

func TestPersonalPolicyNeverReplacesAdministratorOrGroupPolicies(t *testing.T) {
	ctx, s, admin, _ := isolatedStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	u, _, err := s.CreateUser(ctx, admin, identity.User{Login: "policy_floor", DisplayName: "Policy floor", MFAPolicy: "totp"}, security.HashToken("floor-invite"))
	must(err)
	_, err = s.AcceptInvite(ctx, "floor-invite", "fixture-password-hash")
	must(err)
	recovery := make([]string, 10)
	for i := range recovery {
		recovery[i] = security.HashToken(security.Random(32))
	}
	must(s.EnableTOTP(ctx, u.ID, "fixture-encrypted-secret", recovery))
	p, err := s.Principal(ctx, u.ID, "", "api")
	must(err)
	for _, policy := range []string{"none", "any", "totp"} {
		_, err = s.SetPersonalFactorPolicy(ctx, p, policy)
		must(err)
		state, err := s.FactorState(ctx, u.ID)
		must(err)
		if len(state.AdministratorRequired) != 1 || state.AdministratorRequired[0] != "totp" || state.Satisfied(false, true) {
			t.Fatal("personal policy weakened mandatory TOTP")
		}
	}
	_, err = s.SetPersonalFactorPolicy(ctx, p, "passkey")
	must(err)
	current, err := s.Principal(ctx, u.ID, "", "api")
	must(err)
	if !current.Restricted {
		t.Fatal("new personal requirement was not enforced")
	}
	must(s.EnableWebAuthn(ctx, u.ID, "fixture-floor-passkey", []byte(`{"fixture":true}`), recovery))
	current, err = s.Principal(ctx, u.ID, "", "api")
	must(err)
	if current.Restricted {
		t.Fatal("completed additional enrollment did not restore access")
	}
	_, err = s.SaveUserGroup(ctx, admin, application.UserGroup{Name: "Mandatory passkey", MFAPolicy: "passkey", Members: []string{u.ID}})
	must(err)
	_, err = s.SetPersonalFactorPolicy(ctx, current, "none")
	must(err)
	state, err := s.FactorState(ctx, u.ID)
	must(err)
	if state.Satisfied(false, true) || state.Satisfied(true, false) {
		t.Fatal("personal none weakened direct or group minimum")
	}
	current.TokenID = "api-token"
	if _, err = s.SetPersonalFactorPolicy(ctx, current, "both"); err != ErrForbidden {
		t.Fatal("API token changed interactive enrollment preferences")
	}
	current.TokenID = ""
	if _, err = s.SetPersonalFactorPolicy(ctx, current, "invalid"); err == nil {
		t.Fatal("invalid policy was accepted")
	}
	_, err = s.RemoveFactor(ctx, admin, u.ID, "totp")
	must(err)
	current, err = s.Principal(ctx, u.ID, "", "api")
	must(err)
	if !current.Restricted {
		t.Fatal("administrator reset did not require re-enrollment")
	}
	_, err = s.SetPersonalFactorPolicy(ctx, current, "none")
	must(err)
	current, err = s.Principal(ctx, u.ID, "", "api")
	must(err)
	if !current.Restricted {
		t.Fatal("restricted personal preferences bypassed administrator minimum")
	}
	_, err = s.RemoveFactor(ctx, current, u.ID, "fixture-floor-passkey")
	if err != ErrForbidden {
		t.Fatal("restricted self session managed credentials")
	}
}
