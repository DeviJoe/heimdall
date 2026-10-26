package native

import (
	"Heimdall/internal/identity"
	"Heimdall/internal/synchronization"
	"strings"
	"testing"
)

func TestSSHMethodsAreExplicitAndIndependent(t *testing.T) {
	for _, tc := range []struct {
		password, keys, enabled bool
		auth                    string
	}{
		{false, true, true, "publickey"}, {true, false, true, "password"}, {true, true, true, "password publickey"}, {true, true, false, ""},
	} {
		a := synchronization.Account{User: identity.User{Login: "engineer"}, Enabled: tc.enabled, AllowPassword: tc.password, AllowSSHKeys: tc.keys}
		policy := SSHPolicy([]synchronization.Account{a})
		pw, pk := "no", "no"
		if tc.password && tc.enabled {
			pw = "yes"
		}
		if tc.keys && tc.enabled {
			pk = "yes"
		}
		if tc.auth != "" && !strings.Contains(policy, "AuthenticationMethods "+tc.auth+"\n") {
			t.Fatal("explicit method missing")
		}
		if tc.auth == "" && strings.Contains(policy, "AuthenticationMethods") {
			t.Fatal("disabled Match has unnecessary AuthenticationMethods")
		}
		for _, want := range []string{"PasswordAuthentication " + pw, "PubkeyAuthentication " + pk, "KbdInteractiveAuthentication no", "AuthorizedKeysCommand none", "TrustedUserCAKeys none"} {
			if !strings.Contains(policy, want+"\n") {
				t.Fatalf("missing %q in %s", want, policy)
			}
		}
	}
}
func TestManagedMatchPrecedesExistingMatchesWithoutSwallowingGlobals(t *testing.T) {
	path := managedDirectory + "/sshd_config"
	config := "Port 22\nUsePAM yes\nMatch User root\n PasswordAuthentication no\n"
	got, err := sshConfigWithPolicy(config, path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(got, "Include "+path) < strings.Index(got, "UsePAM yes") || strings.Index(got, "Include "+path) > strings.Index(got, "Match User root") {
		t.Fatal("unsafe include placement")
	}
	again, err := sshConfigWithPolicy(got, path)
	if err != nil || again != got {
		t.Fatal("non-idempotent OpenSSH config")
	}
}
